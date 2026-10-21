//go:build linux

package cli

import (
	"strings"
	"testing"
)

const mountTable = `sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 /home ext4 rw,relatime 0 0
/dev/sda2 /home/user/carved ext4 rw,noexec,relatime 0 0
tmpfs /tmp/world tmpfs rw,nosuid,nodev,noexec,relatime 0 0
`

func TestParseMounts(t *testing.T) {
	for _, tc := range []struct {
		path       string
		mountPoint string
		noExec     bool
	}{
		{path: "/home/user/carved", mountPoint: "/home/user/carved", noExec: true},
		{path: "/home/user/carved/file.bin", mountPoint: "/home/user/carved", noExec: true},
		{path: "/home/user/other", mountPoint: "/home", noExec: false},
		{path: "/proc/1", mountPoint: "/proc", noExec: true},
		{path: "/tmp/world/file", mountPoint: "/tmp/world", noExec: true},
	} {
		info, err := parseMounts(strings.NewReader(mountTable), tc.path)
		if err != nil {
			t.Fatalf("parseMounts(%q): %v", tc.path, err)
		}
		if info.MountPoint != tc.mountPoint {
			t.Errorf("parseMounts(%q) mount = %q, want %q", tc.path, info.MountPoint, tc.mountPoint)
		}
		if info.NoExec != tc.noExec {
			t.Errorf("parseMounts(%q) noexec = %v, want %v", tc.path, info.NoExec, tc.noExec)
		}
	}
}

func TestParseMountsWithoutMatch(t *testing.T) {
	if _, err := parseMounts(strings.NewReader(mountTable), "/nowhere"); err == nil {
		t.Fatal("expected an error for an unmounted path")
	}
}

func TestPathUnder(t *testing.T) {
	if !pathUnder("/home/user", "/home/user") {
		t.Error("path should be under itself")
	}
	if !pathUnder("/home/user/file", "/home") {
		t.Error("path should be under its parent")
	}
	if pathUnder("/home/user2/file", "/home/user") {
		t.Error("a sibling prefix must not match")
	}
}

func TestUnescapeMount(t *testing.T) {
	if got := unescapeMount(`/mnt/my\040disk`); got != "/mnt/my disk" {
		t.Errorf("unescapeMount = %q", got)
	}
}
