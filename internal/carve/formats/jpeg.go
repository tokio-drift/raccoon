package formats

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tokio-drift/raccoon/internal/carve"
	"github.com/tokio-drift/raccoon/internal/limits"
)

// JPEG carves JFIF/Exif JPEG images. It validates the FF D8 FF header, walks
// marker segments by their length fields up to the start-of-scan marker, and
// then scans the entropy-coded data for the FF D9 end-of-image marker,
// skipping stuffed bytes (FF 00), restart markers (FF D0-D7) and FF FF fill.
// Because the scan only ends on an unescaped FF D9, the EOI of a thumbnail
// embedded in an APP segment cannot end the carve early.
type JPEG struct{}

var _ carve.Format = JPEG{}

// Name implements carve.Format.
func (JPEG) Name() string { return "jpeg" }

// Ext implements carve.Format.
func (JPEG) Ext() string { return "jpg" }

// Headers implements carve.Format.
func (JPEG) Headers() [][]byte { return [][]byte{{0xFF, 0xD8, 0xFF}} }

// MaxSize implements carve.Format.
func (JPEG) MaxSize() int64 { return limits.MaxCarveSize }

// Extent implements carve.Format. end is the absolute offset one past the
// EOI marker when StatusComplete, the clamped stream end when
// StatusTruncated, and the offset of the first invalid byte when
// StatusCorrupt.
func (JPEG) Extent(r io.ReaderAt, start, streamLen int64) (end int64, status string, err error) {
	if start < 0 || streamLen < start {
		return 0, "", fmt.Errorf("jpeg: extent(start=%d, streamLen=%d): %w", start, streamLen, carve.ErrBounds)
	}
	limit := streamLen
	if max := (JPEG{}).MaxSize(); start+max < limit {
		limit = start + max
	}

	// Validate the FF D8 FF header, tolerating a stream cut short inside it.
	avail := limit - start
	if avail < 3 {
		return limit, carve.StatusTruncated, nil
	}
	hdr, err := readAt(r, start, 3)
	if err != nil {
		if isEOF(err) {
			return limit, carve.StatusTruncated, nil
		}
		return 0, "", err
	}
	if hdr[0] != 0xFF || hdr[1] != 0xD8 || hdr[2] != 0xFF {
		return 0, "", fmt.Errorf("jpeg: header % x: %w", hdr, carve.ErrInvalidHeader)
	}

	// The third header byte is the first marker prefix; walk markers from
	// there until the SOS marker hands over to entropy-coded data.
	pos := start + 2
	for {
		if pos+2 > limit {
			return limit, carve.StatusTruncated, nil
		}
		mk, err := readAt(r, pos, 2)
		if err != nil {
			if isEOF(err) {
				return limit, carve.StatusTruncated, nil
			}
			return 0, "", err
		}
		if mk[0] != 0xFF {
			// A marker prefix must precede every marker id.
			return pos, carve.StatusCorrupt, nil
		}
		id := mk[1]
		switch {
		case id == 0xD9: // EOI before any scan: empty but well-formed image
			return pos + 2, carve.StatusComplete, nil
		case id == 0x01 || id == 0xD8 || (id >= 0xD0 && id <= 0xD7):
			// TEM, SOI and restart markers carry no length field.
			pos += 2
		default:
			// Every other marker starts with a big-endian length that
			// includes the two length bytes themselves.
			if pos+4 > limit {
				return limit, carve.StatusTruncated, nil
			}
			lb, err := readAt(r, pos+2, 2)
			if err != nil {
				if isEOF(err) {
					return limit, carve.StatusTruncated, nil
				}
				return 0, "", err
			}
			n := int64(binary.BigEndian.Uint16(lb))
			if n < 2 {
				return pos, carve.StatusCorrupt, nil
			}
			pos += 2 + n
			if pos > limit {
				return limit, carve.StatusTruncated, nil
			}
			if id == 0xDA { // SOS: the segment ends, entropy-coded data follows
				return jpegScanEntropy(r, pos, limit)
			}
		}
	}
}

// jpegScanEntropy scans entropy-coded data starting at pos for the FF D9
// end-of-image marker and returns the offset one past it.
func jpegScanEntropy(r io.ReaderAt, pos, limit int64) (int64, string, error) {
	buf := make([]byte, scanChunk)
	prevFF := false
	for pos < limit {
		n := int64(scanChunk)
		if limit-pos < n {
			n = limit - pos
		}
		got, err := r.ReadAt(buf[:n], pos)
		if got == 0 {
			return limit, carve.StatusTruncated, nil
		}
		for i := 0; i < got; i++ {
			c := buf[i]
			if prevFF {
				prevFF = false
				if c == 0xD9 {
					// pos+i is the D9; the image ends just past it.
					return pos + int64(i) + 1, carve.StatusComplete, nil
				}
				// FF 00 stuffed, FF D0-D7 restart, FF FF fill or any other
				// marker (e.g. a further scan in a progressive JPEG): not
				// the end, keep scanning. Entropy data escapes every FF as
				// FF 00, so an unescaped FF D9 is always the real EOI.
				continue
			}
			if c == 0xFF {
				prevFF = true
			}
		}
		pos += int64(got)
		if got < int(n) && err != nil {
			return limit, carve.StatusTruncated, nil
		}
	}
	return limit, carve.StatusTruncated, nil
}
