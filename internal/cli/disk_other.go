//go:build !unix

package cli

import "fmt"

// freeDiskBytes is not available on this platform.
func freeDiskBytes(path string) (uint64, error) {
	return 0, fmt.Errorf("free disk space cannot be determined on this platform")
}
