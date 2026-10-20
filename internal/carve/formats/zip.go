package formats

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tokio-drift/raccoon/internal/carve"
	"github.com/tokio-drift/raccoon/internal/limits"
)

var (
	zipLocalHeader = []byte{'P', 'K', 0x03, 0x04}
	zipEOCD        = []byte{'P', 'K', 0x05, 0x06}
)

// zipEOCDLen is the fixed size of the End-of-Central-Directory record
// without its comment: 4 sig + 16 fields + 2 comment length.
const zipEOCDLen = 22

// ZIP carves ZIP archives. It validates the PK\x03\x04 local-file-header
// signature, scans forward within the bound for the End-of-Central-Directory
// record (PK\x05\x06), reads its comment length to find the archive end,
// and verifies that the central directory's recorded offset and size are
// consistent with the EOCD position — only a consistent archive is
// StatusComplete.
type ZIP struct{}

var _ carve.Format = ZIP{}

// Name implements carve.Format.
func (ZIP) Name() string { return "zip" }

// Ext implements carve.Format.
func (ZIP) Ext() string { return "zip" }

// Headers implements carve.Format.
func (ZIP) Headers() [][]byte { return [][]byte{zipLocalHeader} }

// MaxSize implements carve.Format.
func (ZIP) MaxSize() int64 { return limits.MaxCarveSize }

// Extent implements carve.Format. end is the absolute offset one past the
// EOCD comment when StatusComplete, the clamped stream end when
// StatusTruncated, and the EOCD offset when the central-directory
// consistency check fails with StatusCorrupt.
func (ZIP) Extent(r io.ReaderAt, start, streamLen int64) (end int64, status string, err error) {
	if start < 0 || streamLen < start {
		return 0, "", fmt.Errorf("zip: extent(start=%d, streamLen=%d): %w", start, streamLen, carve.ErrBounds)
	}
	limit := streamLen
	if max := (ZIP{}).MaxSize(); start+max < limit {
		limit = start + max
	}

	if limit-start < int64(len(zipLocalHeader)) {
		return limit, carve.StatusTruncated, nil
	}
	hdr, err := readAt(r, start, int64(len(zipLocalHeader)))
	if err != nil {
		if isEOF(err) {
			return limit, carve.StatusTruncated, nil
		}
		return 0, "", err
	}
	if !bytes.Equal(hdr, zipLocalHeader) {
		return 0, "", fmt.Errorf("zip: header % x: %w", hdr, carve.ErrInvalidHeader)
	}

	// Scan forward for the EOCD signature, overlapping chunks by 3 bytes so
	// a signature split across a chunk boundary is still found.
	eocdOff := int64(-1)
	from := start + int64(len(zipLocalHeader))
	for from < limit {
		n := int64(scanChunk)
		if limit-from < n {
			n = limit - from
		}
		buf, err := readAt(r, from, n)
		if err != nil {
			if isEOF(err) {
				break
			}
			return 0, "", err
		}
		if idx := bytes.Index(buf, zipEOCD); idx >= 0 {
			eocdOff = from + int64(idx)
			break
		}
		if n <= int64(len(zipEOCD)-1) {
			break // the whole remaining range has been scanned
		}
		from += n - int64(len(zipEOCD)-1)
	}
	if eocdOff < 0 {
		// No end record before the bound: the archive is cut off.
		return limit, carve.StatusTruncated, nil
	}
	if eocdOff+zipEOCDLen > limit {
		return limit, carve.StatusTruncated, nil
	}
	rec, err := readAt(r, eocdOff, zipEOCDLen)
	if err != nil {
		if isEOF(err) {
			return limit, carve.StatusTruncated, nil
		}
		return 0, "", err
	}
	// The ZIP format is little-endian: cdSize, cdOff and the comment length
	// are all stored least-significant byte first.
	cdSize := int64(binary.LittleEndian.Uint32(rec[12:16]))
	cdOff := int64(binary.LittleEndian.Uint32(rec[16:20]))
	commentLen := int64(binary.LittleEndian.Uint16(rec[20:22]))

	// The central directory must end exactly where the EOCD begins;
	// offsets in the record are relative to the archive (stream) start.
	if start+cdOff+cdSize != eocdOff {
		return eocdOff, carve.StatusCorrupt, nil
	}
	end = eocdOff + zipEOCDLen + commentLen
	if end > limit {
		return limit, carve.StatusTruncated, nil
	}
	return end, carve.StatusComplete, nil
}
