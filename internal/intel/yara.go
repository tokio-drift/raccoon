// Package intel checks carved files against YARA rules and external reputation services.
package intel

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed rules/default.yar
var defaultRules []byte // embedded default YARA rules from rules/default.yar

// yaraScanTimeout is the maximum wall-clock time allowed for a single
// yara subprocess invocation. A hostile carved file that triggers a
// slow/backtracking rule would otherwise stall the pipeline.
const yaraScanTimeout = 10 * time.Second

// Match is one YARA rule hit returned by a RuleEngine scan.
type Match struct {
	// Rule is the matched YARA rule name.
	Rule string
	// File is the absolute path that was scanned (echoed from the scanner output).
	File string
}

// RuleEngine is the interface satisfied by any YARA back-end.
// Implementations must be safe for concurrent use.
type RuleEngine interface {
	// Scan scans the file at the given absolute path and returns all matching
	// rule names. A nil slice means no matches. The error is non-nil only for
	// infrastructure failures (process not found, timeout, I/O error); a clean
	// run with no matches returns (nil, nil).
	Scan(path string) ([]Match, error)
	// Available returns true when the back-end is ready for use (e.g., the
	// yara binary exists on PATH).
	Available() bool
}

// SubprocessEngine implements RuleEngine by shelling out to the yara(1) binary.
// It loads the compiled rules from rulesDir on every call so the rules can be
// updated without restarting the daemon. A nil or zero-value SubprocessEngine
// is not usable; always construct via NewSubprocessEngine.
type SubprocessEngine struct {
	// rulesDir is the directory containing YARA rule files. The engine passes
	// it to yara via -r (recursive) and -w (suppress warnings).
	rulesDir string
}

// ErrYARAUnavailable is returned when the yara binary is not on PATH.
var ErrYARAUnavailable = errors.New("intel: yara binary not found on PATH")

// ErrYARAScanTimeout is returned when a yara subprocess exceeds yaraScanTimeout.
var ErrYARAScanTimeout = errors.New("intel: yara scan timed out")

// NewSubprocessEngine returns a SubprocessEngine that scans files using the
// rules found in rulesDir. If rulesDir is empty the engine uses a temporary
// directory containing only the embedded default rules; that directory is
// cleaned up at process exit.
//
// An error is returned only when the temporary directory cannot be created.
func NewSubprocessEngine(rulesDir string) (*SubprocessEngine, error) {
	if rulesDir == "" {
		dir, err := writeDefaultRules()
		if err != nil {
			return nil, fmt.Errorf("intel: write default rules: %w", err)
		}
		return &SubprocessEngine{rulesDir: dir}, nil
	}
	return &SubprocessEngine{rulesDir: rulesDir}, nil
}

// writeDefaultRules writes the embedded default.yar to a temporary directory
// and returns its path. The caller is responsible for cleanup.
func writeDefaultRules() (string, error) {
	dir, err := os.MkdirTemp("", "raccoon-yara-*")
	if err != nil {
		return "", err
	}
	dst := filepath.Join(dir, "default.yar")
	if err := os.WriteFile(dst, defaultRules, 0600); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// Available returns true when the yara binary can be found on PATH.
func (e *SubprocessEngine) Available() bool {
	_, err := exec.LookPath("yara")
	return err == nil
}

// Scan runs `yara -r -w <rulesDir> <path>` with a 10 s timeout and parses
// the output into Match values. Each output line has the form:
//
//	ruleName /path/to/file
//
// An exit code of 0 means matches were found; exit code 1 may mean no matches
// (depending on the yara version); exit code > 1 indicates an error.
// The subprocess stderr is captured and included in the returned error.
func (e *SubprocessEngine) Scan(path string) ([]Match, error) {
	if !e.Available() {
		return nil, ErrYARAUnavailable
	}

	ctx, cancel := context.WithTimeout(context.Background(), yaraScanTimeout)
	defer cancel()

	// -r: recurse into directories (noop for single files but harmless)
	// -w: suppress warnings so output only contains match lines
	cmd := exec.CommandContext(ctx, "yara", "-r", "-w", e.rulesDir, path)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, ErrYARAScanTimeout
	}

	// yara exits 0 when at least one rule matched, and may exit 1 when no
	// rules matched (depends on the version). Any other exit code is an error.
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			code := exitErr.ExitCode()
			if code == 1 && stdout.Len() == 0 {
				// yara reports "no matches" as exit code 1 on some versions.
				return nil, nil
			}
			if code > 1 {
				return nil, fmt.Errorf("intel: yara exited %d: %s", code, strings.TrimSpace(stderr.String()))
			}
		} else {
			return nil, fmt.Errorf("intel: yara exec: %w", runErr)
		}
	}

	return parseYARAOutput(stdout.Bytes(), path), nil
}

// parseYARAOutput turns the yara stdout text into a slice of Match values.
// Each non-empty line is expected to be "ruleName <space> filePath".
// Lines that do not parse cleanly are logged at debug level and skipped.
func parseYARAOutput(out []byte, scannedPath string) []Match {
	var matches []Match
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			slog.Debug("intel: yara: unexpected output line", "line", line)
			continue
		}
		m := Match{
			Rule: strings.TrimSpace(parts[0]),
			File: strings.TrimSpace(parts[1]),
		}
		if m.Rule == "" {
			continue
		}
		// Use the caller's path when the binary echoes something different.
		if m.File == "" {
			m.File = scannedPath
		}
		matches = append(matches, m)
	}
	return matches
}

// NopEngine is a RuleEngine that always reports itself as unavailable and
// returns no matches. It is used when the yara binary is absent and the caller
// wants a sentinel rather than a nil pointer.
type NopEngine struct{}

// Available always returns false.
func (NopEngine) Available() bool { return false }

// Scan always returns (nil, ErrYARAUnavailable).
func (NopEngine) Scan(_ string) ([]Match, error) { return nil, ErrYARAUnavailable }

// DefaultEngine returns a *SubprocessEngine backed by the embedded default
// rules (writing them to a temporary directory), or a NopEngine when the
// yara binary is absent. The caller should log a warning in the NopEngine
// case and set verdicts to "not_checked".
func DefaultEngine() (RuleEngine, error) {
	if _, err := exec.LookPath("yara"); err != nil {
		slog.Warn("intel: yara binary not found; YARA scanning disabled; verdicts will be not_checked")
		return NopEngine{}, nil
	}
	eng, err := NewSubprocessEngine("")
	if err != nil {
		return nil, err
	}
	return eng, nil
}
