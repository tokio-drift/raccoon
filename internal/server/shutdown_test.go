package server

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

// TestShutdownFinishesStreamsAndKeepsCase covers the 10.8 graceful shutdown:
// open SSE connections are finished, the case database is flushed and closed,
// and the case directory is kept on disk.
func TestShutdownFinishesStreamsAndKeepsCase(t *testing.T) {
	f := startFixture(t, nil)

	cancel, resp, br := openSSE(t, f, "/api/case/"+testID+"/events/stream")
	defer cancel()
	defer resp.Body.Close()

	// The finished case replays progress, ready and done before the stream
	// stays open.
	for _, want := range []string{"progress", "ready", "done"} {
		if frame := readSSEFrame(t, br); frame.name != want {
			t.Fatalf("frame %q, want %q", frame.name, want)
		}
	}

	ctx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	done := make(chan error, 1)
	go func() { done <- f.srv.Shutdown(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown did not finish: an open stream blocked it")
	}

	// The stream must be finished, not left hanging.
	if _, err := br.ReadString('\n'); err != io.EOF {
		t.Fatalf("stream did not end with the shutdown: %v", err)
	}

	// The case directory is kept and its flushed data is readable.
	caseDir := filepath.Join(f.dataDir, testID)
	if _, err := os.Stat(caseDir); err != nil {
		t.Fatalf("case directory was removed: %v", err)
	}
	c, err := casedir.Open(caseDir)
	if err != nil {
		t.Fatalf("casedir.Open: %v", err)
	}
	db, err := store.Open(c.DB())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	events, _, _, err := db.Counts()
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if events != 7 {
		t.Fatalf("events after shutdown = %d, want 7", events)
	}
}

// TestShutdownWaitsForBackgroundAnalysis covers the 10.8 graceful shutdown:
// an analysis started by an upload is given time to finish, so its data is
// flushed to disk before the server closes.
func TestShutdownWaitsForBackgroundAnalysis(t *testing.T) {
	f := startFixture(t, nil)
	pcap := testutil.Pcap(t, "tcp_basic.pcap")
	data, err := os.ReadFile(pcap)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	resp, body := postUpload(t, f, "tcp_basic.pcap", data, "file")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status %d: %s", resp.StatusCode, body)
	}
	up := decodeInto[uploadResponse](t, body)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := f.srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if pending := f.srv.PendingAnalyses(); pending != 0 {
		t.Fatalf("%d analyses still running after the shutdown", pending)
	}

	// The analysis finished and its metadata is on disk.
	c, err := casedir.Open(filepath.Join(f.dataDir, up.CaseID))
	if err != nil {
		t.Fatalf("casedir.Open: %v", err)
	}
	db, err := store.Open(c.DB())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	meta, err := db.Meta()
	if err != nil {
		t.Fatalf("Meta: %v", err)
	}
	if meta["packets"] == "" || meta["packets"] == "0" {
		t.Fatalf("the analysis did not finish: packets=%q", meta["packets"])
	}
}
