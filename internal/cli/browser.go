package cli

import (
	"fmt"
	"os/exec"
	"runtime"
)

// openBrowserFn opens a URL in the user's default browser. It is a variable so
// tests can replace it.
var openBrowserFn = openBrowser

// browserCommand returns the opener command for the given operating system.
// Linux and BSD use xdg-open, macOS uses open and Windows uses rundll32 with
// the URL protocol handler.
func browserCommand(goos, url string) (string, []string) {
	switch goos {
	case "darwin":
		return "open", []string{url}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		return "xdg-open", []string{url}
	}
}

// openBrowser starts the platform's URL opener without waiting for the
// browser window to close.
func openBrowser(url string) error {
	name, args := browserCommand(runtime.GOOS, url)
	path, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("no browser opener available (%s): %w", name, err)
	}
	cmd := exec.Command(path, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
