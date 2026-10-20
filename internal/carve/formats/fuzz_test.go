package formats

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tokio-drift/raccoon/internal/carve"
)

// fuzzExtent drives f.Extent over arbitrary bytes and checks the invariants
// every Format must uphold: it never panics, never returns an out-of-range end,
// never reports success together with an error, and reports a status only from
// the documented set. The reader is a bytes.Reader, so an out-of-bounds read
// surfaces as io.EOF/io.ErrUnexpectedEOF rather than a slice panic — a real
// read past the stream end would otherwise crash a hostile-format walk.
func fuzzExtent(t *testing.T, f carve.Format, data []byte, start int64) {
	t.Helper()
	if len(data) == 0 {
		return
	}
	// Pick a start inside the buffer so the magic-header check can succeed.
	if start < 0 || start >= int64(len(data)) {
		start = int64(len(data) / 2)
	}
	r := bytes.NewReader(data)

	end, status, err := f.Extent(r, start, int64(len(data)))
	if err != nil {
		if end != 0 {
			t.Fatalf("Extent err=%v with non-zero end=%d", err, end)
		}
		return
	}
	switch status {
	case carve.StatusComplete, carve.StatusTruncated, carve.StatusCorrupt:
	default:
		t.Fatalf("Extent returned unknown status %q", status)
	}
	if end <= start || end > start+f.MaxSize() {
		t.Fatalf("Extent end=%d out of (start=%d, start+MaxSize=%d]", end, start, start+f.MaxSize())
	}
	if end > int64(len(data)) {
		t.Fatalf("Extent end=%d past stream length %d", end, len(data))
	}
}

// seedFormat fuzz seeds from the real generated fixtures so the fuzzer mutates
// structured input.
func seedFormat(f *testing.F) {
	for _, fix := range []string{
		"ftp_upload_png.pcap", "ftp_download_pdf_port31337.pcap",
		"http_get_jpeg_chunked.pcap", "carve_nonstandard_port.pcap",
	} {
		if data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", fix)); err == nil {
			f.Add(data, int64(0))
		}
	}
	f.Add([]byte{}, int64(0))
	f.Add([]byte("\x00"), int64(0))
}

// FuzzJPEGExtent checks JPEG.Extent on arbitrary bytes.
func FuzzJPEGExtent(f *testing.F) {
	seedFormat(f)
	f.Add([]byte{0xFF, 0xD8, 0xFF}, int64(0))
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xD9}, int64(0))
	f.Fuzz(func(t *testing.T, data []byte, start int64) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		fuzzExtent(t, JPEG{}, data, start)
	})
}

// FuzzPNGExtent checks PNG.Extent on arbitrary bytes.
func FuzzPNGExtent(f *testing.F) {
	seedFormat(f)
	f.Add([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, int64(0))
	f.Fuzz(func(t *testing.T, data []byte, start int64) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		fuzzExtent(t, PNG{}, data, start)
	})
}

// FuzzPDFExtent checks PDF.Extent on arbitrary bytes.
func FuzzPDFExtent(f *testing.F) {
	seedFormat(f)
	f.Add([]byte("%PDF-1.4\n%%EOF\n"), int64(0))
	f.Fuzz(func(t *testing.T, data []byte, start int64) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		fuzzExtent(t, PDF{}, data, start)
	})
}

// FuzzZIPExtent checks ZIP.Extent on arbitrary bytes.
func FuzzZIPExtent(f *testing.F) {
	seedFormat(f)
	f.Add([]byte{'P', 'K', 0x03, 0x04}, int64(0))
	f.Add([]byte{'P', 'K', 0x03, 0x04, 0, 0, 0, 0}, int64(0))
	f.Fuzz(func(t *testing.T, data []byte, start int64) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		fuzzExtent(t, ZIP{}, data, start)
	})
}
