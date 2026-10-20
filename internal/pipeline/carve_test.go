package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/resource"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

// runCarveFixture runs the pipeline over a fixture and returns the open store
// plus the run result.
func runCarveFixture(t *testing.T, name string) (*store.DB, *Result) {
	t.Helper()
	budget, err := resource.NewBudget(256*1024*1024, 0, 2)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	res, err := Run(context.Background(), Options{
		PCAPPath: testutil.Pcap(t, name),
		BaseDir:  t.TempDir(),
		Budget:   budget,
	})
	if err != nil {
		t.Fatalf("%s: Run: %v", name, err)
	}
	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("%s: open DB: %v", name, err)
	}
	t.Cleanup(func() { db.Close() })
	return db, res
}

// TestCarvedFileRows checks the CarvedFile rows emitted for each Phase 7
// fixture, including the on-disk carved bytes and the FILE_CARVED event link.
func TestCarvedFileRows(t *testing.T) {
	tests := []struct {
		fixture string
		sha256  string
		ext     string
		status  string
		name    string // expected DisplayName; "" means no assertion
	}{
		{
			fixture: "ftp_upload_png.pcap",
			sha256:  "6c0328165683e4450da3aea197fe7edb89fe3d858473df79d896f75a975be172",
			ext:     "png",
			status:  "complete",
			name:    "6c0328165683.png", // no FileSource name for ftp-data
		},
		{
			fixture: "ftp_download_pdf_port31337.pcap",
			sha256:  "3b7faaf1baec9cf4bd529d52e2ac20de2bba7972743209a722a90079764c363e",
			ext:     "pdf",
			status:  "complete",
			name:    "3b7faaf1baec.pdf",
		},
		{
			fixture: "http_get_jpeg_chunked.pcap",
			sha256:  "bae8839289a550db2da10bf79d22866f69dcf378291a9bd41e46c85f40d4f2b5",
			ext:     "jpg",
			status:  "complete",
			name:    "img.jpg", // HTTP Content-Disposition/URL filename
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.fixture, func(t *testing.T) {
			db, res := runCarveFixture(t, tt.fixture)

			files, err := db.Files(store.FileFilter{Confidence: store.ConfidenceAll})
			if err != nil {
				t.Fatalf("Files: %v", err)
			}
			if len(files) != 1 {
				t.Fatalf("carved %d files, want 1: %+v", len(files), files)
			}
			f := files[0]
			if f.SHA256 != tt.sha256 {
				t.Errorf("sha256 = %s, want %s", f.SHA256, tt.sha256)
			}
			if f.Ext != tt.ext {
				t.Errorf("ext = %q, want %q", f.Ext, tt.ext)
			}
			if f.Status != tt.status {
				t.Errorf("status = %q, want %q", f.Status, tt.status)
			}
			if f.Format == "" {
				t.Error("format is empty")
			}
			if f.MD5 == "" || f.MagicHex == "" {
				t.Errorf("md5/magicHex missing: %q %q", f.MD5, f.MagicHex)
			}
			if f.Size <= 0 || f.EndOff-f.StartOff != f.Size {
				t.Errorf("size = %d, extent = [%d,%d)", f.Size, f.StartOff, f.EndOff)
			}
			if f.StreamID == 0 {
				t.Error("stream id not set")
			}
			if tt.name != "" && f.DisplayName != tt.name {
				t.Errorf("display name = %q, want %q", f.DisplayName, tt.name)
			}
			if filepath.ToSlash(f.Path) != "carved/"+f.SHA256+"."+f.Ext {
				t.Errorf("path = %q, want carved/<sha>.%s", f.Path, f.Ext)
			}

			// The bytes on disk are what the row claims.
			diskPath := filepath.Join(res.Case.Dir, filepath.FromSlash(f.Path))
			data, err := os.ReadFile(diskPath)
			if err != nil {
				t.Fatalf("read carved file %s: %v", diskPath, err)
			}
			if int64(len(data)) != f.Size {
				t.Errorf("on-disk size = %d, want %d", len(data), f.Size)
			}
			if got := sha256Hex(data); got != f.SHA256 {
				t.Errorf("on-disk sha256 = %s, want %s", got, f.SHA256)
			}
			info, err := os.Stat(diskPath)
			if err != nil {
				t.Fatalf("stat carved file: %v", err)
			}
			if info.Mode().Perm() != 0o400 {
				t.Errorf("carved file mode = %v, want 0400", info.Mode().Perm())
			}

			if res.Files != 1 {
				t.Errorf("Result.Files = %d, want 1", res.Files)
			}

			// A FILE_CARVED event references the file row and carries every
			// required detail key.
			ev := findEvent(t, db, model.EvFileCarved)
			if ev.FileID != f.ID {
				t.Errorf("event file_id = %d, want %d", ev.FileID, f.ID)
			}
			for _, key := range []string{
				"sha256", "md5", "size", "format", "magicHex", "status", "dir", "startOff", "endOff",
			} {
				if _, ok := ev.Details[key]; !ok {
					t.Errorf("event details missing %q: %v", key, ev.Details)
				}
			}
			if ev.Details["sha256"] != f.SHA256 {
				t.Errorf("event sha256 = %v, want %s", ev.Details["sha256"], f.SHA256)
			}
		})
	}
}

// TestCarveFormatRegistryWire verifies the pipeline registers every format the
// plan expects.
func TestCarveFormatRegistryWire(t *testing.T) {
	reg := newFormatRegistry()
	names := map[string]bool{}
	for _, f := range reg.All() {
		names[f.Name()] = true
	}
	for _, want := range []string{"jpeg", "png", "pdf", "zip"} {
		if !names[want] {
			t.Errorf("format %q not registered", want)
		}
	}
}

// TestCarveNoCarvedContent verifies a capture with nothing carvable yields no
// files and no FILE_CARVED events, and Result.Files stays zero.
func TestCarveNoCarvedContent(t *testing.T) {
	db, res := runCarveFixture(t, "ftp_bruteforce.pcap")

	files, err := db.Files(store.FileFilter{Confidence: store.ConfidenceAll})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("carved %d files, want 0", len(files))
	}
	if res.Files != 0 {
		t.Errorf("Result.Files = %d, want 0", res.Files)
	}
	rows, err := db.Conn().Query(`SELECT count(*) FROM events WHERE type=?`, string(model.EvFileCarved))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var n int
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
	}
	if n != 0 {
		t.Errorf("FILE_CARVED events = %d, want 0", n)
	}
}

// TestCarveDiskBudgetStopsWrites verifies the carved-file disk budget is
// enforced: with a MaxDisk small enough that the first candidate would exceed
// it, nothing is written.
func TestCarveDiskBudgetStopsWrites(t *testing.T) {
	// MaxMemory, MaxDisk, Workers. MaxDisk = 1 byte forces every carve to be
	// dropped.
	budget, err := resource.NewBudget(256*1024*1024, 1, 2)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	res, err := Run(context.Background(), Options{
		PCAPPath: testutil.Pcap(t, "ftp_upload_png.pcap"),
		BaseDir:  t.TempDir(),
		Budget:   budget,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("open DB: %v", err)
	}
	defer db.Close()

	files, err := db.Files(store.FileFilter{Confidence: store.ConfidenceAll})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("carved %d files with a 1-byte budget, want 0", len(files))
	}
	ents, err := os.ReadDir(res.Case.CarvedDir())
	if err != nil {
		t.Fatalf("read carved dir: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("carved dir has %d entries, want 0", len(ents))
	}
}

// findEvent returns the single event of the given type, failing otherwise.
func findEvent(t *testing.T, db *store.DB, typ model.EventType) model.Event {
	t.Helper()
	events, _, err := db.Events(store.EventFilter{Types: []model.EventType{typ}, Limit: 10})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("%s events = %d, want 1", typ, len(events))
	}
	return events[0]
}

// sha256Hex returns the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
