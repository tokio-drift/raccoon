//go:build linux

package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// procMounts is the kernel table of the mounted filesystems.
const procMounts = "/proc/mounts"

// mountOptionsForPath returns the mount options of the filesystem that holds
// path. The longest matching mount point wins.
func mountOptionsForPath(path string) (mountInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return mountInfo{}, err
	}
	f, err := os.Open(procMounts)
	if err != nil {
		return mountInfo{}, err
	}
	defer f.Close()
	return parseMounts(f, abs)
}

// parseMounts reads a kernel mount table and returns the options of the
// filesystem that holds path.
func parseMounts(r io.Reader, path string) (mountInfo, error) {
	var (
		best  mountInfo
		found bool
	)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		mountPoint := unescapeMount(fields[1])
		if !pathUnder(path, mountPoint) {
			continue
		}
		if found && len(mountPoint) <= len(best.MountPoint) {
			continue
		}
		options := fields[3]
		best = mountInfo{
			MountPoint: mountPoint,
			Options:    options,
			NoExec:     hasMountOption(options, "noexec"),
		}
		found = true
	}
	if err := sc.Err(); err != nil {
		return mountInfo{}, err
	}
	if !found {
		return mountInfo{}, fmt.Errorf("no mount found for %s", path)
	}
	return best, nil
}

// pathUnder reports whether path is dir itself or inside it.
func pathUnder(path, dir string) bool {
	if path == dir {
		return true
	}
	return strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// hasMountOption reports whether a comma separated mount option list contains
// the given option.
func hasMountOption(options, want string) bool {
	for _, opt := range strings.Split(options, ",") {
		if opt == want {
			return true
		}
	}
	return false
}

// unescapeMount decodes the octal escapes used in the kernel mount table.
func unescapeMount(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}
