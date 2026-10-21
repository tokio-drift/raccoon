package cli

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
)

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func badInput(err error) error { return &exitError{code: 2, err: err} }
func internal(err error) error { return &exitError{code: 3, err: err} }

func newToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func defaultWorkers() int {
	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	return n
}

func defaultBaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "raccoon", "cases")
	}
	return filepath.Join(home, ".raccoon", "cases")
}

func dashboardURL(s interface{ Addr() net.Addr }) string {
	addr := s.Addr()
	if addr == nil {
		return ""
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return "http://127.0.0.1:" + port + "/?t="
}

func writeDashboard(w io.Writer, s interface {
	Addr() net.Addr
	Token() string
}) {
	url := dashboardURL(s)
	if url == "" {
		fmt.Fprintln(w, "Dashboard: unavailable")
		return
	}
	fmt.Fprintf(w, "Dashboard: %s%s\n", url, s.Token())
}
