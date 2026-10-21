//go:build !linux

package cli

import "fmt"

// mountOptionsForPath is not available on this platform.
func mountOptionsForPath(path string) (mountInfo, error) {
	return mountInfo{}, fmt.Errorf("mount options are not available on this platform")
}
