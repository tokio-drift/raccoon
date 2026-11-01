package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBrowserCommand(t *testing.T) {
	for _, tc := range []struct {
		goos string
		want string
		args []string
	}{
		{goos: "linux", want: "xdg-open", args: []string{"http://127.0.0.1:8080/?t=abc"}},
		{goos: "freebsd", want: "xdg-open", args: []string{"http://127.0.0.1:8080/?t=abc"}},
		{goos: "darwin", want: "open", args: []string{"http://127.0.0.1:8080/?t=abc"}},
		{goos: "windows", want: "rundll32", args: []string{"url.dll,FileProtocolHandler", "http://127.0.0.1:8080/?t=abc"}},
	} {
		name, args := browserCommand(tc.goos, "http://127.0.0.1:8080/?t=abc")
		if name != tc.want {
			t.Errorf("%s: name %q, want %q", tc.goos, name, tc.want)
		}
		if strings.Join(args, " ") != strings.Join(tc.args, " ") {
			t.Errorf("%s: args %v, want %v", tc.goos, args, tc.args)
		}
	}
}

// syncBuffer is a bytes.Buffer that is safe to read while a goroutine writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// stubBrowser replaces the browser opener for the duration of a test.
func stubBrowser(t *testing.T) *[]string {
	t.Helper()
	var mu sync.Mutex
	var opened []string
	prev := openBrowserFn
	openBrowserFn = func(url string) error {
		mu.Lock()
		defer mu.Unlock()
		opened = append(opened, url)
		return nil
	}
	t.Cleanup(func() { openBrowserFn = prev })
	return &opened
}

func TestServeOpensBrowserUnlessDisabled(t *testing.T) {
	for _, noBrowser := range []bool{false, true} {
		opened := stubBrowser(t)
		base := t.TempDir()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var (
			stdout syncBuffer
			stderr syncBuffer
			done   = make(chan error, 1)
		)
		go func() {
			done <- serveCase(ctx, base, 0, noBrowser, &stdout, &stderr)
		}()

		waitFor(t, &stdout, "Dashboard: ")
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("serveCase: %v (stderr %s)", err, stderr.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatal("serveCase did not return")
		}

		if noBrowser && len(*opened) != 0 {
			t.Fatalf("browser opened with --no-browser: %v", *opened)
		}
		if !noBrowser {
			if len(*opened) != 1 {
				t.Fatalf("browser calls %d, want 1", len(*opened))
			}
			if !strings.HasPrefix((*opened)[0], "http://127.0.0.1:") || !strings.Contains((*opened)[0], "?t=") {
				t.Fatalf("opened url %q", (*opened)[0])
			}
		}
		if !strings.Contains(stdout.String(), "Stopped. Cases are kept in "+base) {
			t.Fatalf("missing shutdown notice:\n%s", stdout.String())
		}
	}
}

// waitFor waits until the buffer contains want.
func waitFor(t *testing.T, buf *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in:\n%s", want, buf.String())
}

func TestServeKeepsCaseOnDisk(t *testing.T) {
	stubBrowser(t)
	base := t.TempDir()
	caseDir := filepath.Join(base, "20260101-120000-abcdef")
	if err := os.MkdirAll(filepath.Join(caseDir, "carved"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() { done <- serveCase(ctx, base, 0, true, &stdout, &stderr) }()
	waitFor(t, &stdout, "Dashboard: ")
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveCase: %v", err)
	}
	if _, err := os.Stat(caseDir); err != nil {
		t.Fatalf("case directory was removed: %v", err)
	}
}

func TestServeCaseWithDeepLink(t *testing.T) {
	opened := stubBrowser(t)
	base := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() { done <- serveCaseWith(ctx, base, "20260101-120000-abcdef", 0, false, &stdout, &stderr) }()
	waitFor(t, &stdout, "Dashboard: ")
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveCaseWith: %v", err)
	}
	if len(*opened) != 1 {
		t.Fatalf("browser calls %d, want 1", len(*opened))
	}
	wantSuffix := "&goto=/case/20260101-120000-abcdef/storyboard"
	if !strings.Contains((*opened)[0], wantSuffix) {
		t.Fatalf("opened url %q, want containing %q", (*opened)[0], wantSuffix)
	}
}
