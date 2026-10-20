package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

// expFile mirrors the files entry of testdata/expected/*.json.
type expFile struct {
	SHA256 string `json:"sha256"`
	Ext    string `json:"ext"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// expCarveDoc mirrors the fields of testdata/expected/*.json the carve tests
// need.
type expCarveDoc struct {
	Files []expFile `json:"files"`
}

// carveFixtures are the fixtures whose golden files carry an expected carved
// file list.
var carveFixtures = []string{
	"carve_nonstandard_port.pcap",
	"ftp_upload_png.pcap",
	"ftp_download_pdf_port31337.pcap",
	"http_get_jpeg_chunked.pcap",
}

// goldenName maps a fixture file name to its testdata/expected/*.json name,
// e.g. tcp_basic.pcap -> tcp_basic.json.
func goldenName(fixture string) string {
	return strings.TrimSuffix(fixture, filepath.Ext(fixture)) + ".json"
}

// httpCarvedName is the DisplayName the HTTP analyzer's FileSource gives the
// carved JPEG (from the request URL/Content-Disposition).
const httpCarvedName = "img.jpg"

// TestCarveFixtureGoldens carves each fixture and checks every file against the
// expected SHA-256/ext/status in testdata/expected/<name>.json. The on-disk
// bytes are re-hashed so a row that disagrees with its file is caught.
func TestCarveFixtureGoldens(t *testing.T) {
	for _, name := range carveFixtures {
		name := name
		t.Run(name, func(t *testing.T) {
			var want expCarveDoc
			testutil.LoadExpected(t, goldenName(name), &want)
			if len(want.Files) == 0 {
				t.Fatalf("%s: golden lists no expected files", name)
			}

			db, res := runCarveFixture(t, name)
			got, err := db.Files(store.FileFilter{Confidence: store.ConfidenceAll})
			if err != nil {
				t.Fatalf("Files: %v", err)
			}
			if len(got) != len(want.Files) {
				t.Fatalf("carved %d files, want %d: %+v", len(got), len(want.Files), got)
			}
			if res.Files != int64(len(want.Files)) {
				t.Errorf("Result.Files = %d, want %d", res.Files, len(want.Files))
			}

			bySHA := map[string]model.CarvedFile{}
			for _, f := range got {
				bySHA[f.SHA256] = f
			}
			for _, exp := range want.Files {
				f, ok := bySHA[exp.SHA256]
				if !ok {
					t.Errorf("no carved file with sha256 %s (got %+v)", exp.SHA256, got)
					continue
				}
				if f.Ext != exp.Ext {
					t.Errorf("%s: ext = %q, want %q", exp.SHA256[:12], f.Ext, exp.Ext)
				}
				if exp.Status != "" && f.Status != exp.Status {
					t.Errorf("%s: status = %q, want %q", exp.SHA256[:12], f.Status, exp.Status)
				}
				// 7.8: a carved file is named from the analyzer's FileSource
				// when one exists (HTTP), otherwise from the sha12 + ext
				// convention. The golden's files[].name records the
				// generator's intent, which currently only the HTTP case
				// implements.
				wantName := f.SHA256[:12] + "." + f.Ext
				if name == "http_get_jpeg_chunked.pcap" {
					wantName = httpCarvedName
				}
				if f.DisplayName != wantName {
					t.Errorf("%s: display name = %q, want %q", exp.SHA256[:12], f.DisplayName, wantName)
				}

				// The carved bytes on disk hash to the expected SHA-256.
				diskPath := filepath.Join(res.Case.Dir, filepath.FromSlash(f.Path))
				data, err := os.ReadFile(diskPath)
				if err != nil {
					t.Fatalf("read %s: %v", diskPath, err)
				}
				if got := sha256Hex(data); got != exp.SHA256 {
					t.Errorf("on-disk sha256 = %s, want %s", got, exp.SHA256)
				}
			}
		})
	}
}

// TestCarveHTTPDechunkedJPEG is the explicit provenance check for
// http_get_jpeg_chunked.pcap: the stream on the wire is gzip-compressed and
// chunked, so a carver that saw raw stream bytes could not produce a valid
// JPEG. The carved file must be byte-identical to the uncompressed source JPEG
// recorded in the golden's expected stream/file hashes.
func TestCarveHTTPDechunkedJPEG(t *testing.T) {
	var want expCarveDoc
	testutil.LoadExpected(t, goldenName("http_get_jpeg_chunked.pcap"), &want)
	if len(want.Files) != 1 {
		t.Fatalf("golden files = %d, want 1", len(want.Files))
	}
	wantJPEG := want.Files[0]

	db, res := runCarveFixture(t, "http_get_jpeg_chunked.pcap")
	got, err := db.Files(store.FileFilter{Confidence: store.ConfidenceAll})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("carved %d files, want 1", len(got))
	}
	f := got[0]

	// A GIF/PNG-style magic would mean the carver saw compressed bytes; a real
	// JPEG starts with FFD8FF.
	data, err := os.ReadFile(filepath.Join(res.Case.Dir, filepath.FromSlash(f.Path)))
	if err != nil {
		t.Fatalf("read carved file: %v", err)
	}
	if len(data) < 3 || data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
		t.Fatalf("carved bytes are not a JPEG (magic %x); dechunk/gunzip did not run", data[:3])
	}
	if f.MagicHex != "ffd8ff" {
		t.Errorf("magicHex = %q, want ffd8ff", f.MagicHex)
	}
	if got := sha256Hex(data); got != wantJPEG.SHA256 {
		t.Errorf("carved JPEG sha256 = %s, want %s", got, wantJPEG.SHA256)
	}
}

// TestCarveRandomDataOpaque verifies a high-entropy, non-carvable stream yields
// zero carved files and exactly one OPAQUE_REGION event covering the payload.
func TestCarveRandomDataOpaque(t *testing.T) {
	db, res := runCarveFixture(t, "random_data.pcap")

	files, err := db.Files(store.FileFilter{Confidence: store.ConfidenceAll})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("carved %d files from random data, want 0", len(files))
	}
	if res.Files != 0 {
		t.Errorf("Result.Files = %d, want 0", res.Files)
	}

	ev := findEvent(t, db, model.EvOpaqueRegion)
	if ev.Severity != model.SevWarning {
		t.Errorf("severity = %q, want %q", ev.Severity, model.SevWarning)
	}
	if ev.StreamID == 0 {
		t.Error("stream id not set")
	}
	if h, _ := ev.Details["meanH"].(float64); h < 7.2 {
		t.Errorf("meanH = %v, want >= 7.2", ev.Details["meanH"])
	}
	// Details survive a JSON round-trip through SQLite, so numbers come back
	// as float64.
	start, _ := ev.Details["startOff"].(float64)
	end, _ := ev.Details["endOff"].(float64)
	if end-start < 4*1024 {
		t.Errorf("opaque extent = [%v,%v), want >= 4 KB", start, end)
	}
	if ev.Details["dir"] != "c2s" {
		t.Errorf("dir = %v, want c2s", ev.Details["dir"])
	}
}
