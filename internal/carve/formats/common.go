// Package formats implements carve.Format for the file types the carver can
// extract: magic-header validation, then a structure walk that finds the
// file's end inside a reassembled stream.
package formats

import (
	"errors"
	"fmt"
	"io"

	"github.com/tokio-drift/raccoon/internal/carve"
)

// maxReadBytes caps a single readAt request so a hostile length field cannot
// drive an unbounded allocation.
const maxReadBytes = 1 << 20

// scanChunk is the read size used for chunked walks and searches (JPEG
// entropy scan, PDF back-scan, ZIP EOCD scan, PNG CRC computation).
const scanChunk = 64 * 1024

// readAt reads exactly n bytes at off. It rejects nil readers, negative
// offsets and oversized requests with carve.ErrBounds, and surfaces short
// reads as io.EOF / io.ErrUnexpectedEOF from the underlying ReaderAt.
func readAt(r io.ReaderAt, off, n int64) ([]byte, error) {
	if r == nil || off < 0 || n < 0 || n > maxReadBytes {
		return nil, fmt.Errorf("formats: read(off=%d, n=%d): %w", off, n, carve.ErrBounds)
	}
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	got, err := r.ReadAt(buf, off)
	if int64(got) == n {
		return buf, nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return nil, fmt.Errorf("formats: read %d bytes at %d: %w", n, off, err)
}

// isEOF reports whether err is a short-read error.
func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
