package cli

import (
	"os"
)

// Execute runs the raccoon command-line interface.
func Execute() {
	code := runCLI(os.Args[1:], os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}
