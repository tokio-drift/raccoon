package formats

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"testing"

	"github.com/tokio-drift/raccoon/internal/carve"
)

// makeJPEG encodes a small real JPEG with the standard library.
func makeJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 24, 24))
	for y := 0; y < 24; y++ {
		for x := 0; x < 24; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 10), uint8(y * 10), 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return buf.Bytes()
}

// withEXIFThumbnail splices an APP1 Exif segment directly after the SOI
// marker of base. The segment embeds thumb (a complete JPEG with its own EOI)
// plus fill bytes, so any carver that scans segment contents instead of
// walking length fields would stop at the thumbnail's EOI.
func withEXIFThumbnail(base, thumb []byte) []byte {
	payload := append([]byte("Exif\x00\x00"), thumb...)
	payload = append(payload, bytes.Repeat([]byte{0x2A}, 16)...) // padding after the thumbnail

	seg := make([]byte, 0, 4+len(payload))
	seg = append(seg, 0xFF, 0xE1) // APP1
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(2+len(payload))) // includes the length field itself
	seg = append(seg, lb[0], lb[1])
	seg = append(seg, payload...)

	out := make([]byte, 0, 2+len(seg)+len(base)-2)
	out = append(out, base[:2]...) // SOI
	out = append(out, seg...)
	out = append(out, base[2:]...) // remainder of the real JPEG
	return out
}

func TestJPEGExtentRealJPEG(t *testing.T) {
	data := makeJPEG(t)
	end, status, err := JPEG{}.Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	if end != int64(len(data)) {
		t.Fatalf("end = %d, want %d (full file)", end, len(data))
	}
	// The EOI is the final two bytes of the file.
	if !bytes.Equal(data[len(data)-2:], []byte{0xFF, 0xD9}) {
		t.Fatalf("fixture does not end with EOI: % x", data[len(data)-2:])
	}
}

// TestJPEGExtentEmbeddedThumbnailEOI is the regression the plan calls out: an
// Exif thumbnail is a complete JPEG with its own EOI embedded inside APP1.
// The carver must skip the segment by its length field and must not end at
// the thumbnail's EOI.
func TestJPEGExtentEmbeddedThumbnailEOI(t *testing.T) {
	base := makeJPEG(t)
	thumb := makeJPEG(t)
	data := withEXIFThumbnail(base, thumb)

	thumbEOI := bytes.LastIndex(thumb, []byte{0xFF, 0xD9})
	if thumbEOI < 0 {
		t.Fatal("thumbnail has no EOI")
	}

	end, status, err := JPEG{}.Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	if end != int64(len(data)) {
		t.Fatalf("end = %d, want %d (carved too %s)", end, len(data),
			map[bool]string{true: "early", false: "late"}[end < int64(len(data))])
	}
	if end <= int64(2+len("Exif\x00\x00")+thumbEOI) {
		t.Fatalf("end = %d stops at or inside the embedded thumbnail EOI", end)
	}
	// Sanity: the embedded EOI really is followed by more file bytes.
	if !bytes.Contains(data, []byte{0xFF, 0xD9, 0x2A, 0x2A}) {
		t.Fatal("thumbnail EOI is not embedded inside APP1 as intended")
	}
}

func TestJPEGExtentTruncated(t *testing.T) {
	data := makeJPEG(t)
	if len(data) < 8 {
		t.Fatalf("jpeg too small: %d bytes", len(data))
	}
	cut := data[:len(data)-4] // chop the EOI and the bytes before it
	end, status, err := JPEG{}.Extent(bytes.NewReader(cut), 0, int64(len(cut)))
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

// TestJPEGExtentEmbeddedCarve proves Extent works at a nonzero start offset,
// as it will for a JPEG found inside a reassembled stream.
func TestJPEGExtentEmbeddedCarve(t *testing.T) {
	jpegBytes := makeJPEG(t)
	prefix := []byte("GET /a.jpg HTTP/1.1\r\n\r\n")
	data := append(append([]byte{}, prefix...), jpegBytes...)
	start := int64(len(prefix))

	end, status, err := JPEG{}.Extent(bytes.NewReader(data), start, int64(len(data)))
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

func TestJPEGExtentInvalidHeader(t *testing.T) {
	data := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	_, _, err := JPEG{}.Extent(bytes.NewReader(data), 0, int64(len(data)))
	if !errors.Is(err, carve.ErrInvalidHeader) {
		t.Fatalf("err = %v, want ErrInvalidHeader", err)
	}
}

func TestJPEGExtentCorruptMarkerLength(t *testing.T) {
	// SOI, then APP0 whose length field says 1 (legal minimum is 2).
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x01, 0x00, 0x00}
	end, status, err := JPEG{}.Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusCorrupt {
		t.Fatalf("status = %q, want %q", status, carve.StatusCorrupt)
	}
	if end != 2 {
		t.Fatalf("end = %d, want 2 (offset of the broken marker)", end)
	}
}

func TestJPEGExtentBounds(t *testing.T) {
	data := makeJPEG(t)
	if _, _, err := (JPEG{}).Extent(bytes.NewReader(data), -1, int64(len(data))); !errors.Is(err, carve.ErrBounds) {
		t.Fatalf("negative start: err = %v, want ErrBounds", err)
	}
	if _, _, err := (JPEG{}).Extent(bytes.NewReader(data), 4, 2); !errors.Is(err, carve.ErrBounds) {
		t.Fatalf("start beyond streamLen: err = %v, want ErrBounds", err)
	}
	// A stream ending right after SOI+one marker prefix is truncated, not a
	// crash: FF D8 FF <cut>.
	end, status, err := (JPEG{}).Extent(bytes.NewReader(data[:3]), 0, 3)
	if err != nil {
		t.Fatalf("3-byte stream: %v", err)
	}
	if status != carve.StatusTruncated || end != 3 {
		t.Fatalf("3-byte stream: end=%d status=%q, want end=3 status=%q", end, status, carve.StatusTruncated)
	}
}

// TestJPEGExtentRandomDataTerminates guards the walker against pathological
// marker streams: it must always terminate with a status and never panic.
func TestJPEGExtentRandomDataTerminates(t *testing.T) {
	data := makeJPEG(t)
	for i := 0; i < len(data)-2; i++ {
		cut := data[:i]
		if len(cut) < 3 {
			continue
		}
		end, status, err := JPEG{}.Extent(bytes.NewReader(cut), 0, int64(len(cut)))
		if err != nil {
			t.Fatalf("cut at %d: unexpected error %v", i, err)
		}
		if end < 0 || end > int64(len(cut)) {
			t.Fatalf("cut at %d: end %d out of bounds [0,%d]", i, end, len(cut))
		}
		switch status {
		case carve.StatusComplete, carve.StatusTruncated, carve.StatusCorrupt:
		default:
			t.Fatalf("cut at %d: unknown status %q", i, status)
		}
		if i >= len(data)-4 && status == carve.StatusComplete {
			// Cutting away the EOI (last 2 bytes) must never yield complete.
			if !bytes.HasSuffix(cut, []byte{0xFF, 0xD9}) {
				t.Fatalf("cut at %d: status complete without trailing EOI", i)
			}
		}
	}
}
