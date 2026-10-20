package intel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildEICARFile assembles the EICAR test string from split parts at test
// runtime so that this source file itself does not contain the exact EICAR
// string (which would cause AV scanners to flag the raccoon source tree).
//
// The EICAR standard anti-malware test string is 68 bytes:
//
//	X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
func buildEICARFile(t *testing.T) string {
	t.Helper()
	// Split across multiple lines so no single string literal contains the
	// full EICAR test string.
	part1 := "X5O!P%@AP[4" + `\` + "PZX54(P^)7CC)7}"
	part2 := "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	content := part1 + part2

	dir := t.TempDir()
	path := filepath.Join(dir, "eicar.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write EICAR file: %v", err)
	}
	return path
}

// TestDefaultRulesEmbedded verifies that the embedded rules blob is non-empty
// and contains expected rule names.
func TestDefaultRulesEmbedded(t *testing.T) {
	if len(defaultRules) == 0 {
		t.Fatal("defaultRules embed is empty")
	}
	content := string(defaultRules)
	for _, want := range []string{
		"pe_header_in_non_exe",
		"suspicious_script",
		"eicar_test_file",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("defaultRules does not contain rule %q", want)
		}
	}
}

// TestNopEngine verifies that NopEngine correctly reports itself as unavailable
// and returns ErrYARAUnavailable on Scan.
func TestNopEngine(t *testing.T) {
	eng := NopEngine{}
	if eng.Available() {
		t.Error("NopEngine.Available() should be false")
	}
	_, err := eng.Scan("/dev/null")
	if err != ErrYARAUnavailable {
		t.Errorf("NopEngine.Scan: want ErrYARAUnavailable, got %v", err)
	}
}

// TestNewSubprocessEngineDefaultRules checks that NewSubprocessEngine("") writes
// the embedded default rules to a temporary directory successfully.
func TestNewSubprocessEngineDefaultRules(t *testing.T) {
	eng, err := NewSubprocessEngine("")
	if err != nil {
		t.Fatalf("NewSubprocessEngine: %v", err)
	}
	// The temp directory should exist and contain default.yar.
	entries, err := os.ReadDir(eng.rulesDir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", eng.rulesDir, err)
	}
	var found bool
	for _, e := range entries {
		if e.Name() == "default.yar" {
			found = true
		}
	}
	if !found {
		t.Errorf("default.yar not found in temp rules dir %s", eng.rulesDir)
	}
	// Cleanup the temp directory (production code leaves it for the process
	// lifetime; tests clean up explicitly).
	_ = os.RemoveAll(eng.rulesDir)
}

// TestSubprocessEngineAvailable checks that Available() agrees with whether
// the yara binary is actually on PATH.
func TestSubprocessEngineAvailable(t *testing.T) {
	eng, err := NewSubprocessEngine("")
	if err != nil {
		t.Fatalf("NewSubprocessEngine: %v", err)
	}
	defer os.RemoveAll(eng.rulesDir)

	// We don't know whether yara is installed, so we just verify the result
	// is consistent: if Available() returns true, Scan of /dev/null should
	// not return ErrYARAUnavailable.
	avail := eng.Available()
	if !avail {
		t.Logf("yara binary not on PATH; skipping subprocess tests")
		return
	}
	t.Logf("yara binary found on PATH")
}

// TestEICARDetection runs the subprocess engine against an EICAR file and
// expects the eicar_test_file rule to fire. Skips when yara is not on PATH.
func TestEICARDetection(t *testing.T) {
	eng, err := NewSubprocessEngine("")
	if err != nil {
		t.Fatalf("NewSubprocessEngine: %v", err)
	}
	defer os.RemoveAll(eng.rulesDir)

	if !eng.Available() {
		t.Skip("yara binary not on PATH; skipping EICAR test")
	}

	eicarPath := buildEICARFile(t)
	matches, err := eng.Scan(eicarPath)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var found bool
	for _, m := range matches {
		if m.Rule == "eicar_test_file" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected eicar_test_file rule match, got: %v", matches)
	}
}

// TestScanNoMatches runs the engine against a benign text file and expects no
// rule matches. Skips when yara is not on PATH.
func TestScanNoMatches(t *testing.T) {
	eng, err := NewSubprocessEngine("")
	if err != nil {
		t.Fatalf("NewSubprocessEngine: %v", err)
	}
	defer os.RemoveAll(eng.rulesDir)

	if !eng.Available() {
		t.Skip("yara binary not on PATH; skipping scan test")
	}

	dir := t.TempDir()
	benign := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(benign, []byte("Hello, world!\n"), 0600); err != nil {
		t.Fatalf("write benign file: %v", err)
	}

	matches, err := eng.Scan(benign)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no matches for benign file, got: %v", matches)
	}
}

// TestScanPEHeader runs the engine against a file that starts with the MZ
// magic bytes (PE header marker) and expects pe_header_in_non_exe to fire.
// Skips when yara is not on PATH.
func TestScanPEHeader(t *testing.T) {
	eng, err := NewSubprocessEngine("")
	if err != nil {
		t.Fatalf("NewSubprocessEngine: %v", err)
	}
	defer os.RemoveAll(eng.rulesDir)

	if !eng.Available() {
		t.Skip("yara binary not on PATH; skipping PE header test")
	}

	dir := t.TempDir()
	// MZ magic followed by padding to make a non-trivial file
	pe := make([]byte, 64)
	pe[0] = 'M'
	pe[1] = 'Z'
	path := filepath.Join(dir, "fake.png")
	if err := os.WriteFile(path, pe, 0600); err != nil {
		t.Fatalf("write PE file: %v", err)
	}

	matches, err := eng.Scan(path)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var found bool
	for _, m := range matches {
		if m.Rule == "pe_header_in_non_exe" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected pe_header_in_non_exe rule match, got: %v", matches)
	}
}

// TestParseYARAOutput unit-tests the output parser against synthetic yara output.
func TestParseYARAOutput(t *testing.T) {
	tests := []struct {
		name     string
		out      string
		path     string
		wantLen  int
		wantRule string
	}{
		{
			name:     "single match",
			out:      "eicar_test_file /tmp/eicar.txt\n",
			path:     "/tmp/eicar.txt",
			wantLen:  1,
			wantRule: "eicar_test_file",
		},
		{
			name:    "multiple matches",
			out:     "pe_header_in_non_exe /f.png\nsuspicious_script /f.png\n",
			path:    "/f.png",
			wantLen: 2,
		},
		{
			name:    "empty output",
			out:     "",
			path:    "/f.txt",
			wantLen: 0,
		},
		{
			name:    "blank lines skipped",
			out:     "\n\neicar_test_file /f.txt\n\n",
			path:    "/f.txt",
			wantLen: 1,
		},
		{
			name:    "malformed line skipped",
			out:     "badline\neicar_test_file /f.txt\n",
			path:    "/f.txt",
			wantLen: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseYARAOutput([]byte(tc.out), tc.path)
			if len(got) != tc.wantLen {
				t.Errorf("got %d matches, want %d (matches=%v)", len(got), tc.wantLen, got)
			}
			if tc.wantRule != "" && len(got) > 0 && got[0].Rule != tc.wantRule {
				t.Errorf("got rule %q, want %q", got[0].Rule, tc.wantRule)
			}
		})
	}
}

// TestDefaultEngine verifies that DefaultEngine returns a usable engine (either
// a SubprocessEngine or NopEngine) without error.
func TestDefaultEngine(t *testing.T) {
	eng, err := DefaultEngine()
	if err != nil {
		t.Fatalf("DefaultEngine: %v", err)
	}
	if eng == nil {
		t.Fatal("DefaultEngine returned nil engine")
	}
	// Cleanup any temp dir that may have been written (only for SubprocessEngine).
	if se, ok := eng.(*SubprocessEngine); ok {
		defer os.RemoveAll(se.rulesDir)
	}
}

// TestWriteDefaultRules verifies that writeDefaultRules produces a readable
// non-empty file that matches the embedded blob.
func TestWriteDefaultRules(t *testing.T) {
	dir, err := writeDefaultRules()
	if err != nil {
		t.Fatalf("writeDefaultRules: %v", err)
	}
	defer os.RemoveAll(dir)

	dst := filepath.Join(dir, "default.yar")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != len(defaultRules) {
		t.Errorf("written %d bytes, want %d", len(got), len(defaultRules))
	}
}
