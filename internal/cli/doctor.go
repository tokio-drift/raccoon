package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/tokio-drift/raccoon/internal/casedir"
)

// doctorFreeSpaceWarn is the amount of free space below which the doctor
// warns about the case directory filling up.
const doctorFreeSpaceWarn uint64 = 1 << 30 // 1 GiB

// doctorStatus is the outcome of one doctor check.
type doctorStatus string

const (
	doctorOK   doctorStatus = "ok"
	doctorWarn doctorStatus = "warning"
	doctorFail doctorStatus = "failed"
	doctorInfo doctorStatus = "info"
)

// doctorCheck is one line of the doctor report.
type doctorCheck struct {
	Name   string
	Status doctorStatus
	Detail string
}

// line renders one check for the terminal.
func (c doctorCheck) line() string {
	switch c.Status {
	case doctorOK:
		return fmt.Sprintf("%s: ok (%s)", c.Name, c.Detail)
	case doctorWarn:
		return fmt.Sprintf("%s: warning (%s)", c.Name, c.Detail)
	case doctorFail:
		return fmt.Sprintf("%s: failed (%s)", c.Name, c.Detail)
	default:
		return fmt.Sprintf("%s: %s", c.Name, c.Detail)
	}
}

// failed reports whether the check makes RACCOON unusable.
func (c doctorCheck) failed() bool { return c.Status == doctorFail }

// Indirections so the checks can be exercised in tests.
var (
	doctorLookPath  = exec.LookPath
	doctorFreeDisk  = freeDiskBytes
	doctorMountInfo = mountOptionsForPath
	doctorListen    = listenLocalhost
)

func newDoctorCommand(stdout io.Writer) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the local RACCOON environment",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			base, err := filepath.Abs(out)
			if err != nil {
				return internal(fmt.Errorf("resolve case directory: %w", err))
			}
			checks := runDoctor(base)
			failed := 0
			for _, c := range checks {
				fmt.Fprintln(stdout, c.line())
				if c.failed() {
					failed++
				}
			}
			if failed > 0 {
				return internal(fmt.Errorf("%d environment check(s) failed", failed))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", defaultBaseDir(), "case directory base")
	return cmd
}

// runDoctor performs every environment check and returns the results.
func runDoctor(base string) []doctorCheck {
	checks := make([]doctorCheck, 0, 5)

	// YARA availability (warning only: scanning is optional).
	if path, err := doctorLookPath("yara"); err != nil {
		checks = append(checks, doctorCheck{
			Name:   "yara",
			Status: doctorWarn,
			Detail: "not found, YARA scanning will be disabled",
		})
	} else {
		checks = append(checks, doctorCheck{Name: "yara", Status: doctorOK, Detail: path})
	}

	// The case base must exist and be writable.
	if err := os.MkdirAll(base, 0o700); err != nil {
		checks = append(checks, doctorCheck{
			Name:   "case directory",
			Status: doctorFail,
			Detail: fmt.Sprintf("cannot create %s: %v", base, err),
		})
	} else if err := writableDir(base); err != nil {
		checks = append(checks, doctorCheck{
			Name:   "case directory",
			Status: doctorFail,
			Detail: fmt.Sprintf("%s is not writable: %v", base, err),
		})
	} else {
		checks = append(checks, doctorCheck{
			Name:   "case directory",
			Status: doctorOK,
			Detail: fmt.Sprintf("writable (%s)", base),
		})
	}

	// Free space in the case base.
	free, err := doctorFreeDisk(base)
	switch {
	case err != nil:
		checks = append(checks, doctorCheck{
			Name:   "free disk",
			Status: doctorInfo,
			Detail: fmt.Sprintf("could not be determined: %v", err),
		})
	case free < doctorFreeSpaceWarn:
		checks = append(checks, doctorCheck{
			Name:   "free disk",
			Status: doctorWarn,
			Detail: fmt.Sprintf("only %s free in %s", formatBytes(free), base),
		})
	default:
		checks = append(checks, doctorCheck{
			Name:   "free disk",
			Status: doctorOK,
			Detail: fmt.Sprintf("%s free in %s", formatBytes(free), base),
		})
	}

	// The mount holding the carved files should not allow execution.
	switch info, err := doctorMountInfo(carvedPath(base)); {
	case err != nil:
		checks = append(checks, doctorCheck{
			Name:   "carved files",
			Status: doctorInfo,
			Detail: fmt.Sprintf("mount options unknown: %v", err),
		})
	case info.NoExec:
		checks = append(checks, doctorCheck{
			Name:   "carved files",
			Status: doctorOK,
			Detail: fmt.Sprintf("mount %s is noexec", info.MountPoint),
		})
	default:
		checks = append(checks, doctorCheck{
			Name:   "carved files",
			Status: doctorWarn,
			Detail: fmt.Sprintf("mount %s is not noexec, carved files could be executed if opened by hand", info.MountPoint),
		})
	}

	// The dashboard must be reachable on the loopback interface.
	if addr, err := doctorListen(); err != nil {
		checks = append(checks, doctorCheck{
			Name:   "localhost",
			Status: doctorFail,
			Detail: fmt.Sprintf("cannot listen on 127.0.0.1: %v", err),
		})
	} else {
		checks = append(checks, doctorCheck{
			Name:   "localhost",
			Status: doctorOK,
			Detail: fmt.Sprintf("listening (%s)", addr),
		})
	}

	return checks
}

// writableDir verifies that a file can be created inside dir.
func writableDir(dir string) error {
	f, err := os.CreateTemp(dir, ".doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// carvedPath returns the directory the carved files live in: the carved
// directory of the most recent case, or the case base when there is none.
func carvedPath(base string) string {
	cases, err := casedir.List(base)
	if err != nil || len(cases) == 0 {
		return base
	}
	carved := cases[len(cases)-1].CarvedDir()
	if info, err := os.Stat(carved); err == nil && info.IsDir() {
		return carved
	}
	return base
}

// listenLocalhost binds an ephemeral loopback port and reports its address.
func listenLocalhost() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr, nil
}

// formatBytes renders a byte count with a binary unit suffix.
func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
