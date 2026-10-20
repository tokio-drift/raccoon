package formats

import (
	"bytes"
	"fmt"
	"io"

	"github.com/tokio-drift/raccoon/internal/carve"
	"github.com/tokio-drift/raccoon/internal/limits"
)

var (
	pdfHeader    = []byte("%PDF-")
	pdfEOF       = []byte("%%EOF")
	pdfStartxref = []byte("startxref")
)

// pdfXrefWindow is how close before %%EOF the startxref token must sit for
// the file to count as complete (1 KB).
const pdfXrefWindow = 1024

// PDF carves PDF documents. It validates the %PDF- header, then searches
// backwards from the bound (the next carve-candidate header or the stream
// end, whichever the caller passes as streamLen) for the last %%EOF marker.
// A document is StatusComplete only when a startxref token lies within 1 KB
// before that marker; otherwise the carve ends at the marker (or at the
// bound when no marker exists at all) with StatusTruncated.
type PDF struct{}

var _ carve.Format = PDF{}

// Name implements carve.Format.
func (PDF) Name() string { return "pdf" }

// Ext implements carve.Format.
func (PDF) Ext() string { return "pdf" }

// Headers implements carve.Format.
func (PDF) Headers() [][]byte { return [][]byte{pdfHeader} }

// MaxSize implements carve.Format.
func (PDF) MaxSize() int64 { return limits.MaxCarveSize }

// BoundedExtent implements carve.BoundedFormat: the scanner clamps the stream
// length handed to Extent to the next carve-candidate header so a following
// document cannot be swallowed by this one's %%EOF search.
func (PDF) BoundedExtent() bool { return true }

// Extent implements carve.Format. end is the absolute offset one past
// %%EOF when the marker is found, and the clamped stream end when it is
// not; StatusComplete additionally requires startxref within 1 KB before
// the marker.
func (PDF) Extent(r io.ReaderAt, start, streamLen int64) (end int64, status string, err error) {
	if start < 0 || streamLen < start {
		return 0, "", fmt.Errorf("pdf: extent(start=%d, streamLen=%d): %w", start, streamLen, carve.ErrBounds)
	}
	limit := streamLen
	if max := (PDF{}).MaxSize(); start+max < limit {
		limit = start + max
	}

	if limit-start < int64(len(pdfHeader)) {
		return limit, carve.StatusTruncated, nil
	}
	hdr, err := readAt(r, start, int64(len(pdfHeader)))
	if err != nil {
		if isEOF(err) {
			return limit, carve.StatusTruncated, nil
		}
		return 0, "", err
	}
	if !bytes.Equal(hdr, pdfHeader) {
		return 0, "", fmt.Errorf("pdf: header % x: %w", hdr, carve.ErrInvalidHeader)
	}

	// Search backwards from the bound for the last %%EOF, overlapping each
	// chunk by 4 bytes so a marker split across chunks is still found.
	eofOff := int64(-1)
	pos := limit
	for pos-start >= int64(len(pdfEOF)) {
		n := int64(scanChunk)
		if pos-start < n {
			n = pos - start
		}
		from := pos - n
		buf, err := readAt(r, from, n)
		if err != nil {
			if isEOF(err) {
				break
			}
			return 0, "", err
		}
		if idx := bytes.LastIndex(buf, pdfEOF); idx >= 0 {
			eofOff = from + int64(idx)
			break
		}
		if n <= int64(len(pdfEOF)-1) {
			break // the whole remaining range has been scanned
		}
		pos = from + int64(len(pdfEOF)-1) // 4-byte overlap with the next chunk
	}

	if eofOff < 0 {
		// No end marker anywhere before the bound.
		return limit, carve.StatusTruncated, nil
	}
	end = eofOff + int64(len(pdfEOF))

	// startxref must appear within 1 KB before %%EOF for a complete file.
	from := eofOff - pdfXrefWindow
	if from < start {
		from = start
	}
	win, err := readAt(r, from, eofOff-from)
	if err != nil {
		if isEOF(err) {
			return end, carve.StatusTruncated, nil
		}
		return 0, "", err
	}
	if bytes.LastIndex(win, pdfStartxref) < 0 {
		return end, carve.StatusTruncated, nil
	}
	return end, carve.StatusComplete, nil
}
