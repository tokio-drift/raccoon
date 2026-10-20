package formats

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/tokio-drift/raccoon/internal/carve"
)

// makeZIP builds a real one-entry ZIP archive with an optional EOCD comment.
func makeZIP(t *testing.T, comment string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.Create("hello.txt")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := fw.Write([]byte("hello raccoon\n")); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if comment != "" {
		if err := w.SetComment(comment); err != nil {
			t.Fatalf("zip comment: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestZIPExtentRealZip(t *testing.T) {
	data := makeZIP(t, "")
	end, status, err := (ZIP{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	if end != int64(len(data)) {
		t.Fatalf("end = %d, want %d (full archive)", end, len(data))
	}
}

// TestZIPExtentEOCDComment: the comment length field decides where the
// archive ends.
func TestZIPExtentEOCDComment(t *testing.T) {
	const comment = "written by the raccoon test suite"
	data := makeZIP(t, comment)
	end, status, err := (ZIP{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	if end != int64(len(data)) {
		t.Fatalf("end = %d, want %d (archive + EOCD comment)", end, len(data))
	}
	if !bytes.HasSuffix(data, []byte(comment)) {
		t.Fatal("fixture does not end with the EOCD comment")
	}
}

func TestZIPExtentTruncatedBeforeEOCD(t *testing.T) {
	data := makeZIP(t, "")
	cut := data[:len(data)-zipEOCDLen] // remove the EOCD record entirely
	end, status, err := (ZIP{}).Extent(bytes.NewReader(cut), 0, int64(len(cut)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusTruncated {
		t.Fatalf("status = %q, want %q", status, carve.StatusTruncated)
	}
	if end != int64(len(cut)) {
		t.Fatalf("end = %d, want %d (stream end)", end, len(cut))
	}
}

// TestZIPExtentCorruptCDOffset breaks the central-directory offset so the
// consistency check (start + cdOff + cdSize == eocdOff) must fail.
func TestZIPExtentCorruptCDOffset(t *testing.T) {
	data := makeZIP(t, "")
	eocd := bytes.LastIndex(data, zipEOCD)
	if eocd < 0 {
		t.Fatal("fixture has no EOCD")
	}
	corrupt := append([]byte{}, data...)
	off := binary.LittleEndian.Uint32(corrupt[eocd+16 : eocd+20])
	binary.LittleEndian.PutUint32(corrupt[eocd+16:eocd+20], off+10)

	end, status, err := (ZIP{}).Extent(bytes.NewReader(corrupt), 0, int64(len(corrupt)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusCorrupt {
		t.Fatalf("status = %q, want %q", status, carve.StatusCorrupt)
	}
	if end != int64(eocd) {
		t.Fatalf("end = %d, want %d (EOCD offset)", end, eocd)
	}
}

// TestZIPExtentCommentLenPastEnd: a hostile comment length pointing beyond
// the bound must be clamped and reported truncated.
func TestZIPExtentCommentLenPastEnd(t *testing.T) {
	data := makeZIP(t, "")
	eocd := bytes.LastIndex(data, zipEOCD)
	if eocd < 0 {
		t.Fatal("fixture has no EOCD")
	}
	hostile := append([]byte{}, data...)
	binary.LittleEndian.PutUint16(hostile[eocd+20:eocd+22], 0xFFFF)

	end, status, err := (ZIP{}).Extent(bytes.NewReader(hostile), 0, int64(len(hostile)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusTruncated {
		t.Fatalf("status = %q, want %q", status, carve.StatusTruncated)
	}
	if end != int64(len(hostile)) {
		t.Fatalf("end = %d, want %d (clamped to the bound)", end, len(hostile))
	}
}

// TestZIPExtentEmbeddedCarve proves the central-directory offset is treated
// as archive-relative when the ZIP sits at a nonzero stream offset.
func TestZIPExtentEmbeddedCarve(t *testing.T) {
	zipBytes := makeZIP(t, "")
	prefix := []byte("PK\x03\x04-stub-before-the-real-archive-")
	data := append(append([]byte{}, prefix...), zipBytes...)
	start := int64(len(prefix))

	end, status, err := (ZIP{}).Extent(bytes.NewReader(data), start, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	if end != int64(len(data)) {
		t.Fatalf("end = %d, want %d", end, len(data))
	}
}

func TestZIPExtentInvalidHeader(t *testing.T) {
	data := makePNG(t)
	if _, _, err := (ZIP{}).Extent(bytes.NewReader(data), 0, int64(len(data))); !errors.Is(err, carve.ErrInvalidHeader) {
		t.Fatalf("err = %v, want ErrInvalidHeader", err)
	}
}

func TestZIPExtentBounds(t *testing.T) {
	data := makeZIP(t, "")
	if _, _, err := (ZIP{}).Extent(bytes.NewReader(data), -1, int64(len(data))); !errors.Is(err, carve.ErrBounds) {
		t.Fatalf("negative start: err = %v, want ErrBounds", err)
	}
	if _, _, err := (ZIP{}).Extent(bytes.NewReader(data), 4, 2); !errors.Is(err, carve.ErrBounds) {
		t.Fatalf("start beyond streamLen: err = %v, want ErrBounds", err)
	}
	// A stream cut inside the local header is truncated, not a crash.
	end, status, err := (ZIP{}).Extent(bytes.NewReader(data[:3]), 0, 3)
	if err != nil {
		t.Fatalf("3-byte stream: %v", err)
	}
	if status != carve.StatusTruncated || end != 3 {
		t.Fatalf("3-byte stream: end=%d status=%q, want end=3 status=%q", end, status, carve.StatusTruncated)
	}
}
