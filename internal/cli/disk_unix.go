//go:build unix

package cli

import "syscall"

// freeDiskBytes returns the space available to unprivileged users on the
// filesystem that holds path.
func freeDiskBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	avail := int64(st.Bavail)
	if avail < 0 {
		avail = 0
	}
	return uint64(avail) * uint64(st.Bsize), nil
}
