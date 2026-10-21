package cli

// mountInfo describes the filesystem mount that holds a path.
type mountInfo struct {
	// MountPoint is the mount point of the filesystem.
	MountPoint string
	// Options is the raw mount option list.
	Options string
	// NoExec reports whether the mount refuses execution of binaries.
	NoExec bool
}
