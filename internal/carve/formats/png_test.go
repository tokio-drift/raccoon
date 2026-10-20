package formats

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/tokio-drift/raccoon/internal/carve"
)

// makePNG encodes a small real PNG with the standard library.
func makePNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 24, 24))
	for y := 0; y < 24; y++ {
		for x := 0; x < 24; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 10), uint8(y * 10), 200, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func TestPNGExtentRealPNG(t *testing.T) {
	data := makePNG(t)
	end, status, err := (PNG{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	if end != int64(len(data)) {
		t.Fatalf("end = %d, want %d (full file)", end, len(data))
	}
	// The file must actually end with the IEND chunk (len 0, "IEND", CRC).
	if !bytes.HasSuffix(data, []byte{0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82}) {
		t.Fatalf("fixture does not end with the IEND chunk: % x", data[len(data)-12:])
	}
}

// TestPNGExtentEndsAfterIEND proves trailing bytes after IEND belong to the
// next file and are not part of the carve.
func TestPNGExtentEndsAfterIEND(t *testing.T) {
	pngBytes := makePNG(t)
	data := append(append([]byte{}, pngBytes...), bytes.Repeat([]byte("junk"), 32)...)
	end, status, err := (PNG{}).Extent(bytes.NewReader(data), 0, int64(len(data)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusComplete {
		t.Fatalf("status = %q, want %q", status, carve.StatusComplete)
	}
	if end != int64(len(pngBytes)) {
		t.Fatalf("end = %d, want %d (must stop after IEND)", end, len(pngBytes))
	}
}

// TestPNGExtentCorruptCRC flips a byte of the IHDR data, which the CRC32
// over type+data must catch.
func TestPNGExtentCorruptCRC(t *testing.T) {
	data := makePNG(t)
	// Layout: 8 sig + [4 len + 4 type + 13 data + 4 CRC] for IHDR.
	corrupt := append([]byte{}, data...)
	corrupt[16] ^= 0xFF // first IHDR data byte (width)
	end, status, err := (PNG{}).Extent(bytes.NewReader(corrupt), 0, int64(len(corrupt)))
	if err != nil {
		t.Fatalf("Extent: %v", err)
	}
	if status != carve.StatusCorrupt {
		t.Fatalf("status = %q, want %q", status, carve.StatusCorrupt)
	}
	if end != 8 {
		t.Fatalf("end = %d, want 8 (offset of the chunk with the bad CRC)", end)
	}
}

func TestPNGExtentTruncated(t *testing.T) {
	data := makePNG(t)
	cut := data[:len(data)-4] // cut into the IEND chunk
	end, status, err := (PNG{}).Extent(bytes.NewReader(cut), 0, int64(len(cut)))
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

// TestPNGExtentEmbeddedCarve proves Extent works at a nonzero start offset.
func TestPNGExtentEmbeddedCarve(t *testing.T) {
	pngBytes := makePNG(t)
	prefix := []byte("GET /a.png HTTP/1.1\r\n\r\n")
	data := append(append([]byte{}, prefix...), pngBytes...)
	start := int64(len(prefix))

	end, status, err := (PNG{}).Extent(bytes.NewReader(data), start, int64(len(data)))
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

func TestPNGExtentInvalidHeader(t *testing.T) {
	data := []byte("%PDF-1.4\n%%EOF")
	if _, _, err := (PNG{}).Extent(bytes.NewReader(data), 0, int64(len(data))); !errors.Is(err, carve.ErrInvalidHeader) {
		t.Fatalf("err = %v, want ErrInvalidHeader", err)
	}
}

func TestPNGExtentBounds(t *testing.T) {
	data := makePNG(t)
	if _, _, err := (PNG{}).Extent(bytes.NewReader(data), -1, int64(len(data))); !errors.Is(err, carve.ErrBounds) {
		t.Fatalf("negative start: err = %v, want ErrBounds", err)
	}
	if _, _, err := (PNG{}).Extent(bytes.NewReader(data), 4, 2); !errors.Is(err, carve.ErrBounds) {
		t.Fatalf("start beyond streamLen: err = %v, want ErrBounds", err)
	}
	// A stream cut inside the signature is truncated, not a crash.
	end, status, err := (PNG{}).Extent(bytes.NewReader(data[:5]), 0, 5)
	if err != nil {
		t.Fatalf("5-byte stream: %v", err)
	}
	if status != carve.StatusTruncated || end != 5 {
		t.Fatalf("5-byte stream: end=%d status=%q, want end=5 status=%q", end, status, carve.StatusTruncated)
	}
}

// TestPNGExtentPrefixCutTerminates sweeps every prefix of a real PNG: the
// walker must always terminate with a valid status, an in-bounds end and no
// panic.
func TestPNGExtentPrefixCutTerminates(t *testing.T) {
	data := makePNG(t)
	for i := 0; i < len(data); i++ {
		cut := data[:i]
		end, status, err := (PNG{}).Extent(bytes.NewReader(cut), 0, int64(len(cut)))
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
		if status == carve.StatusComplete {
			// Completeness means the full IEND chunk is present.
			if i < len(data) {
				t.Fatalf("cut at %d: status complete on a truncated PNG", i)
			}
		}
	}
}
