// Package web embeds the compiled frontend assets served by RACCOON.
package web

import "embed"

// Dist holds the built web UI assets. The dist directory is committed to the
// repository so that a plain go build produces a self-contained binary.
//
//go:embed all:dist
var Dist embed.FS
