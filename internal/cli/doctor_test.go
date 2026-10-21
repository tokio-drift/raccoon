package cli

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// errTestListen is the error returned by the stubbed localhost listener.
var errTestListen = errors.New("cannot listen on 127.0.0.1")

// withDoctorStubs replaces the doctor environment probes for one test.
func withDoctorStubs(t *testing.T, lookPath func(string) (string, error), freeDisk func(string) (uint64, error), mounts func(string) (mountInfo, error), listen func() (string, error)) {
	t.Helper()
	prevLookPath, prevFreeDisk := doctorLookPath, doctorFreeDisk
	prevMountInfo, prevListen := doctorMountInfo, doctorListen
	if lookPath != nil {
		doctorLookPath = lookPath
	}
	if freeDisk != nil {
		doctorFreeDisk = freeDisk
	}
	if mounts != nil {
		doctorMountInfo = mounts
	}
	if listen != nil {
		doctorListen = listen
	}
	t.Cleanup(func() {
		doctorLookPath, doctorFreeDisk = prevLookPath, prevFreeDisk
		doctorMountInfo, doctorListen = prevMountInfo, prevListen
	})
}

// findCheck returns the check with the given name.
func findCheck(checks []doctorCheck, name string) (doctorCheck, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return doctorCheck{}, false
}

func TestRunDoctorChecks(t *testing.T) {
	withDoctorStubs(t,
		func(name string) (string, error) { return "/usr/bin/yara", nil },
		func(string) (uint64, error) { return 10 << 30, nil },
		func(string) (mountInfo, error) { return mountInfo{MountPoint: "/", NoExec: true}, nil },
		func() (string, error) { return "127.0.0.1:34567", nil },
	)

	checks := runDoctor(t.TempDir())
	for _, name := range []string{"yara", "case directory", "free disk", "carved files", "localhost"} {
		c, ok := findCheck(checks, name)
		if !ok {
			t.Fatalf("missing check %q in %v", name, checks)
		}
		if c.Status != doctorOK {
			t.Errorf("check %q = %s (%s), want ok", name, c.Status, c.Detail)
		}
	}
}

func TestRunDoctorWarns(t *testing.T) {
	withDoctorStubs(t,
		func(name string) (string, error) { return "", exec.ErrNotFound },
		func(string) (uint64, error) { return 1024, nil },
		func(string) (mountInfo, error) { return mountInfo{MountPoint: "/home"}, nil },
		func() (string, error) { return "127.0.0.1:34567", nil },
	)

	checks := runDoctor(t.TempDir())

	yara, _ := findCheck(checks, "yara")
	if yara.Status != doctorWarn {
		t.Errorf("yara = %s, want warning", yara.Status)
	}
	disk, _ := findCheck(checks, "free disk")
	if disk.Status != doctorWarn {
		t.Errorf("free disk = %s, want warning", disk.Status)
	}
	carved, _ := findCheck(checks, "carved files")
	if carved.Status != doctorWarn {
		t.Errorf("carved files = %s, want warning", carved.Status)
	}
	if !strings.Contains(carved.Detail, "noexec") {
		t.Errorf("carved files detail = %q, want a noexec mention", carved.Detail)
	}
	dir, _ := findCheck(checks, "case directory")
	if dir.Status != doctorOK {
		t.Errorf("case directory = %s, want ok", dir.Status)
	}
}

func TestRunDoctorFailsOnUnusableEnvironment(t *testing.T) {
	withDoctorStubs(t,
		nil,
		nil,
		nil,
		func() (string, error) { return "", errTestListen },
	)

	checks := runDoctor(t.TempDir())
	local, _ := findCheck(checks, "localhost")
	if local.Status != doctorFail {
		t.Fatalf("localhost = %s, want failed", local.Status)
	}
	if !local.failed() {
		t.Fatal("failed check is not reported as failed")
	}
}

func TestDoctorCommandOutput(t *testing.T) {
	withDoctorStubs(t,
		func(name string) (string, error) { return "/usr/bin/yara", nil },
		func(string) (uint64, error) { return 10 << 30, nil },
		func(string) (mountInfo, error) { return mountInfo{MountPoint: "/", NoExec: true}, nil },
		func() (string, error) { return "127.0.0.1:34567", nil },
	)

	var out strings.Builder
	code := runCLI([]string{"doctor", "--out", t.TempDir()}, &out, &out)
	if code != 0 {
		t.Fatalf("exit code %d, output %q", code, out.String())
	}
	for _, want := range []string{"yara: ok", "case directory: ok", "free disk: ok", "carved files: ok", "localhost: ok"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output %q does not contain %q", out.String(), want)
		}
	}
}

func TestDoctorCommandFailsWhenCheckFails(t *testing.T) {
	withDoctorStubs(t,
		nil,
		nil,
		nil,
		func() (string, error) { return "", errTestListen },
	)

	var out strings.Builder
	code := runCLI([]string{"doctor", "--out", t.TempDir()}, &out, &out)
	if code == 0 {
		t.Fatalf("exit code 0, want a failure, output %q", out.String())
	}
	if !strings.Contains(out.String(), "localhost: failed") {
		t.Errorf("output %q does not report the failed check", out.String())
	}
}

func TestFormatBytes(t *testing.T) {
	for _, tc := range []struct {
		in   uint64
		want string
	}{
		{in: 512, want: "512 B"},
		{in: 2 << 20, want: "2.0 MiB"},
		{in: 3 << 30, want: "3.0 GiB"},
	} {
		if got := formatBytes(tc.in); got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
