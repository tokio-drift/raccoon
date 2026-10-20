package formats

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tokio-drift/raccoon/internal/carve"
)

// makePDF builds a minimal but structurally complete PDF: header, body,
// startxref and %%EOF, followed by optional trailing bytes.
func makePDF(trailing []byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	b.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	b.WriteString("trailer\n<< /Root 1 0 R >>\n")
	b.WriteString("startxref\n9\n")
	b.WriteString("%%EOF")
	b.Write(trailing)
	return b.Bytes()
}

func TestPDFExtentComplete(t *testing.T) {
	data := makePDF(nil)
	end, status, err := (PDF{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	// end is one past the last byte of %%EOF.
	want := int64(bytes.LastIndex(data, pdfEOF) + len(pdfEOF))
	if end != want {
		t.Fatalf("end = %d, want %d (one past %%EOF)", end, want)
	}
}

// TestPDFExtentNoStartxref: %%EOF exists but no startxref within 1 KB
// before it, so the carve ends at the marker as truncated.
func TestPDFExtentNoStartxref(t *testing.T) {
	data := []byte("%PDF-1.4\nsome body\n%%EOF")
	end, status, err := (PDF{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusTruncated {
		t.Fatalf("status = %q, want %q", status, carve.StatusTruncated)
	}
	if end != int64(len(data)) {
		t.Fatalf("end = %d, want %d (one past %%EOF)", end, len(data))
	}
}

// TestPDFExtentStartxrefTooFar: a startxref exists but sits more than 1 KB
// before %%EOF, which does not count as complete.
func TestPDFExtentStartxrefTooFar(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\nstartxref\n0\n")
	b.Write(bytes.Repeat([]byte("x"), 2*pdfXrefWindow))
	b.WriteString("%%EOF")
	data := b.Bytes()

	end, status, err := (PDF{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusTruncated {
		t.Fatalf("status = %q, want %q", status, carve.StatusTruncated)
	}
	if end != int64(len(data)) {
		t.Fatalf("end = %d, want %d", end, len(data))
	}
}

func TestPDFExtentNoEOFMarker(t *testing.T) {
	data := []byte("%PDF-1.4\nbody without any end marker")
	end, status, err := (PDF{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusTruncated {
		t.Fatalf("status = %q, want %q", status, carve.StatusTruncated)
	}
	if end != int64(len(data)) {
		t.Fatalf("end = %d, want %d (stream end)", end, len(data))
	}
}

// TestPDFExtentStopsAtLastEOF: trailing bytes after %%EOF (the start of the
// next carve candidate) are excluded from the carve.
func TestPDFExtentStopsAtLastEOF(t *testing.T) {
	pdf := makePDF(nil)
	data := append(append([]byte{}, pdf...), bytes.Repeat([]byte("trailing-next-file"), 10)...)
	end, status, err := (PDF{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	if end != int64(len(pdf)) {
		t.Fatalf("end = %d, want %d (one past %%EOF, before trailing bytes)", end, len(pdf))
	}
}

// TestPDFExtentLastEOFWins: an incremental update means several %%EOF
// markers; the last one before the bound wins.
func TestPDFExtentLastEOFWins(t *testing.T) {
	data := makePDF([]byte("\n% more data\nstartxref\n42\n%%EOF"))
	end, status, err := (PDF{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	if end != int64(len(data)) {
		t.Fatalf("end = %d, want %d (one past the LAST %%EOF)", end, len(data))
	}
}

// TestPDFExtentEOOFSplitsScanChunk places %%EOF so it straddles the first
// backward-scan chunk boundary (limit-scanChunk), exercising the 4-byte
// overlap of the back-scan.
func TestPDFExtentEOOFSplitsScanChunk(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\nstartxref\n0\n") // %%EOF starts right after this
	b.WriteString("%%EOF")
	// Total length: marker at S, limit = S + 5 + trailing. The first chunk
	// starts at limit-scanChunk = S+2 for trailing = scanChunk-3, so the
	// marker straddles that boundary.
	b.Write(bytes.Repeat([]byte{'Z'}, scanChunk-3))
	data := b.Bytes()

	markerAt := bytes.Index(data, pdfEOF)
	if markerAt < 0 {
		t.Fatal("marker lost while building fixture")
	}
	if wantFrom := int64(len(data)) - scanChunk; int64(markerAt) >= wantFrom {
		t.Fatalf("fixture does not straddle the boundary: marker at %d, chunk starts at %d", markerAt, wantFrom)
	}

	end, status, err := (PDF{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	if end != int64(markerAt+len(pdfEOF)) {
		t.Fatalf("end = %d, want %d", end, markerAt+len(pdfEOF))
	}
}

func TestPDFExtentInvalidHeader(t *testing.T) {
	data := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if _, _, err := (PDF{}).Extent(bytes.NewReader(data), 0, int64(len(data))); !errors.Is(err, carve.ErrInvalidHeader) {
		t.Fatalf("err = %v, want ErrInvalidHeader", err)
	}
}

func TestPDFExtentBounds(t *testing.T) {
	data := makePDF(nil)
	if _, _, err := (PDF{}).Extent(bytes.NewReader(data), -1, int64(len(data))); !errors.Is(err, carve.ErrBounds) {
		t.Fatalf("negative start: err = %v, want ErrBounds", err)
	}
	if _, _, err := (PDF{}).Extent(bytes.NewReader(data), 4, 2); !errors.Is(err, carve.ErrBounds) {
		t.Fatalf("start beyond streamLen: err = %v, want ErrBounds", err)
	}
	// A stream shorter than the header is truncated, not a crash.
	end, status, err := (PDF{}).Extent(bytes.NewReader(data[:3]), 0, 3)
	if err != nil {
		t.Fatalf("3-byte stream: %v", err)
	}
	if status != carve.StatusTruncated || end != 3 {
		t.Fatalf("3-byte stream: end=%d status=%q, want end=3 status=%q", end, status, carve.StatusTruncated)
	}
}
