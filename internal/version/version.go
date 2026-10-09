package version

import "runtime/debug"

// Version may be set at build time with
// -ldflags "-X github.com/tokio-drift/raccoon/internal/version.Version=vX.Y.Z".
var Version = ""

// String returns the build version of the running binary. It prefers a version
// injected at link time, then the module version reported by the Go toolchain,
// and finally falls back to "devel".
func String() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "devel"
}
