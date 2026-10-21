package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/version"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runCLI(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVersion(t *testing.T) {
	code, out, errOut := run(t, "version")
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if strings.TrimSpace(out) != version.String() {
		t.Fatalf("version output %q, want %q", out, version.String())
	}
}

func TestHelpListsDebug(t *testing.T) {
	code, out, errOut := run(t, "--help")
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "debug") {
		t.Fatalf("help does not list debug:\n%s", out)
	}
}

func TestInvalidCaptureExitCode(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pcap")
	if err := os.WriteFile(bad, []byte("not a capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, "analyze", bad, "--out", dir, "--offline", "--report", "json", "--max-disk", "1GB")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr %s", code, errOut)
	}
	if !strings.Contains(errOut, "invalid capture") {
		t.Fatalf("stderr %q does not explain the bad input", errOut)
	}
}

func TestLowMemoryIsUsageError(t *testing.T) {
	code, _, errOut := run(t, "analyze", fixture(t, "ftp_upload_png.pcap"), "--out", t.TempDir(), "--max-mem", "128MB", "--offline")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr %s", code, errOut)
	}
	if !strings.Contains(errOut, "at least 256") {
		t.Fatalf("stderr %q does not mention the minimum", errOut)
	}
}

func TestAnalyzeWritesJSONReport(t *testing.T) {
	dir := t.TempDir()
	code, out, errOut := run(t,
		"analyze", fixture(t, "ftp_upload_png.pcap"),
		"--out", dir,
		"--offline",
		"--report", "json",
		"--max-disk", "1GB",
	)
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if strings.Contains(out, "Dashboard:") {
		t.Fatalf("headless report started a server:\n%s", out)
	}
	cases, err := casedir.List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 {
		t.Fatalf("got %d cases, want 1", len(cases))
	}
	reportPath := filepath.Join(cases[0].ReportsDir(), "report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !bytes.Contains(data, []byte(`"schemaVersion": 1`)) {
		t.Fatalf("report missing schema version:\n%s", data)
	}
	if !strings.Contains(out, "Report: "+reportPath) {
		t.Fatalf("output does not name the report:\n%s", out)
	}

	code, out, errOut = run(t, "report", cases[0].Dir, "--format", "html")
	if code != 0 {
		t.Fatalf("report exit %d, stderr %s", code, errOut)
	}
	htmlPath := filepath.Join(cases[0].ReportsDir(), "report.html")
	if !strings.Contains(out, htmlPath) {
		t.Fatalf("report output %q does not name %s", out, htmlPath)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(html, []byte("RACCOON case report")) {
		t.Fatalf("html report has unexpected content")
	}
}

func TestDebugDumpStream(t *testing.T) {
	code, out, errOut := run(t, "debug", "dump-stream", "--pcap", fixture(t, "ftp_upload_png.pcap"), "--stream", "1", "--dir", "c2s")
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut)
	}
	if !strings.Contains(out, "89 50 4e 47 0d 0a 1a 0a") {
		t.Fatalf("PNG bytes missing from dump:\n%s", out)
	}
}

func TestServeRejectsBadPort(t *testing.T) {
	code, _, errOut := run(t, "serve", "--port", "-1", "--out", t.TempDir())
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr %s", code, errOut)
	}
}
