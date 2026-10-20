package formats

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/tokio-drift/raccoon/internal/carve"
	"github.com/tokio-drift/raccoon/internal/limits"
)

// pngSig is the 8-byte PNG signature.
var pngSig = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}

// pngChunkOverhead is the fixed part of a chunk: 4 length + 4 type + 4 CRC.
const pngChunkOverhead = 12

// PNG carves PNG images. It validates the 8-byte signature, then walks
// (length, type, data, CRC32) chunks to the end of the IEND chunk, verifying
// each chunk's CRC32 over type+data as specified; a bad CRC or a chunk
// running past the bound is reported, and the file ends right after IEND
// (trailing bytes belong to the next file).
type PNG struct{}

var _ carve.Format = PNG{}

// Name implements carve.Format.
func (PNG) Name() string { return "png" }

// Ext implements carve.Format.
func (PNG) Ext() string { return "png" }

// Headers implements carve.Format.
func (PNG) Headers() [][]byte { return [][]byte{pngSig} }

// MaxSize implements carve.Format.
func (PNG) MaxSize() int64 { return limits.MaxCarveSize }

// Extent implements carve.Format. end is the absolute offset one past the
// IEND chunk when StatusComplete, the clamped stream end when
// StatusTruncated, and the offset of the chunk with the bad CRC when
// StatusCorrupt.
func (PNG) Extent(r io.ReaderAt, start, streamLen int64) (end int64, status string, err error) {
	if start < 0 || streamLen < start {
		return 0, "", fmt.Errorf("png: extent(start=%d, streamLen=%d): %w", start, streamLen, carve.ErrBounds)
	}
	limit := streamLen
	if max := (PNG{}).MaxSize(); start+max < limit {
		limit = start + max
	}

	// Validate the signature, tolerating a stream cut short inside it.
	if limit-start < int64(len(pngSig)) {
		return limit, carve.StatusTruncated, nil
	}
	sig, err := readAt(r, start, int64(len(pngSig)))
	if err != nil {
		if isEOF(err) {
			return limit, carve.StatusTruncated, nil
		}
		return 0, "", err
	}
	if !bytes.Equal(sig, pngSig) {
		return 0, "", fmt.Errorf("png: header % x: %w", sig, carve.ErrInvalidHeader)
	}

	// Walk chunks: (length, type, data, CRC32).
	pos := start + int64(len(pngSig))
	for {
		if pos+pngChunkOverhead > limit {
			return limit, carve.StatusTruncated, nil
		}
		ht, err := readAt(r, pos, 8) // length + type
		if err != nil {
			if isEOF(err) {
				return limit, carve.StatusTruncated, nil
			}
			return 0, "", err
		}
		n := int64(binary.BigEndian.Uint32(ht[:4]))
		typ := ht[4:8]
		if n > limit-pos-pngChunkOverhead {
			// The chunk claims data past the bound.
			return limit, carve.StatusTruncated, nil
		}

		// CRC32 covers type + data (not the length field); data is read in
		// scanChunk pieces so a large IDAT never exceeds the read cap.
		sum := crc32.Checksum(typ, crc32.IEEETable)
		dataEnd := pos + 8 + n
		for off := pos + 8; off < dataEnd; {
			chunk := int64(scanChunk)
			if dataEnd-off < chunk {
				chunk = dataEnd - off
			}
			part, err := readAt(r, off, chunk)
			if err != nil {
				if isEOF(err) {
					return limit, carve.StatusTruncated, nil
				}
				return 0, "", err
			}
			sum = crc32.Update(sum, crc32.IEEETable, part)
			off += chunk
		}
		want, err := readAt(r, dataEnd, 4)
		if err != nil {
			if isEOF(err) {
				return limit, carve.StatusTruncated, nil
			}
			return 0, "", err
		}
		if binary.BigEndian.Uint32(want) != sum {
			return pos, carve.StatusCorrupt, nil
		}
		if bytes.Equal(typ, []byte("IEND")) {
			return dataEnd + 4, carve.StatusComplete, nil
		}
		pos = dataEnd + 4
	}
}
