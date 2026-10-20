// Package entropy flags high-entropy regions in streams.
//
// It divides the byte ranges it is given into fixed-size blocks, measures the
// Shannon entropy of each block, skips blocks that are mostly printable text,
// and reports runs of adjacent high-entropy blocks as opaque regions. The
// pipeline turns those into OPAQUE_REGION events.
package entropy

import (
	"fmt"
	"io"
	"math"

	"github.com/tokio-drift/raccoon/internal/limits"
)

// scanChunk is the read size used to walk a range; blocks are sliced out of
// each chunk so a large range costs one syscall per 64 KiB rather than one per
// block.
const scanChunk = 64 * 1024

// minOpaqueLen is the smallest opaque region worth reporting (4 KB).
const minOpaqueLen = 4 * 1024

// printableRatio is the fraction of printable bytes at or above which a block
// is treated as text and skipped even if its entropy is high (base64, minified
// JS and similar).
const printableRatio = 0.90

// Range is a half-open byte range [Start, End) of a stream direction to scan.
type Range struct {
	Start, End int64
}

// OpaqueRegion is a merged run of adjacent high-entropy blocks. Start and End
// are absolute stream offsets (End is exclusive); MeanH is the mean entropy in
// bits per byte over the blocks of the run.
type OpaqueRegion struct {
	Start, End int64
	MeanH      float64
}

// Scan measures Shannon entropy over regions and returns the opaque regions it
// found, in ascending Start order. Regions outside the reader's bounds are
// clamped to the bytes actually available. It reports only regions of at least
// 4 KB and skips blocks that are mostly printable ASCII text.
//
// Scan never allocates more than one scanChunk-sized buffer and tolerates a
// short reader (the trailing bytes simply form a shorter final block).
func Scan(r io.ReaderAt, regions []Range) ([]OpaqueRegion, error) {
	if r == nil || len(regions) == 0 {
		return nil, nil
	}
	blockSize := int64(limits.EntropyBlockSize)
	if blockSize <= 0 {
		blockSize = 1024
	}

	var out []OpaqueRegion

	// pending accumulates the current run of adjacent opaque blocks.
	var (
		runStart int64
		runEnd   int64
		runSum   float64
		runLen   int64
	)
	flushRun := func() {
		if runLen >= minOpaqueLen {
			out = append(out, OpaqueRegion{
				Start: runStart,
				End:   runEnd,
				MeanH: runSum / float64(runLen),
			})
		}
		runStart, runEnd, runSum, runLen = 0, 0, 0, 0
	}

	buf := make([]byte, scanChunk)
	for _, reg := range regions {
		// Runs never span disjoint input ranges: the bytes between them are
		// outside the caller's work list (carved or otherwise excluded), so a
		// region must end where its range ends.
		flushRun()
		start, end := reg.Start, reg.End
		if start < 0 {
			start = 0
		}
		if end <= start {
			continue
		}
		for off := start; off < end; {
			want := end - off
			if want > int64(len(buf)) {
				want = int64(len(buf))
			}
			n, err := r.ReadAt(buf[:want], off)
			if n <= 0 {
				if err != nil {
					// A read failure before any bytes are available ends this
					// range; a clean EOF at the range boundary is normal.
					if err != io.EOF {
						flushRun()
						return out, fmt.Errorf("entropy: read at %d: %w", off, err)
					}
					break
				}
				break
			}

			// Split the chunk into blocks, aligned to the block grid.
			for b := int64(0); b < int64(n); {
				blockLen := blockSize - ((off + b) % blockSize)
				if blockLen > int64(n)-b {
					blockLen = int64(n) - b
				}
				block := buf[b : b+blockLen]
				offset := off + b

				h, opaque := blockEntropy(block)
				if opaque {
					if runLen == 0 {
						runStart = offset
					}
					runEnd = offset + blockLen
					runSum += h * float64(blockLen)
					runLen += blockLen
				} else {
					flushRun()
				}
				b += blockLen
			}

			off += int64(n)
			if err != nil || n < int(want) {
				break
			}
		}
	}
	flushRun()
	return out, nil
}

// blockEntropy returns the Shannon entropy of b in bits per byte and whether
// the block counts as opaque: at or above the threshold and not mostly
// printable text.
func blockEntropy(b []byte) (h float64, opaque bool) {
	if len(b) == 0 {
		return 0, false
	}
	var counts [256]int
	printable := 0
	for _, c := range b {
		counts[c]++
		if isPrintable(c) {
			printable++
		}
	}
	h = shannon(counts[:], len(b))
	if float64(printable)/float64(len(b)) >= printableRatio {
		return h, false
	}
	return h, h >= limits.EntropyThreshold
}

// shannon computes the Shannon entropy (bits per byte) of counts totalling n.
func shannon(counts []int, n int) float64 {
	if n == 0 {
		return 0
	}
	var h float64
	inv := 1.0 / float64(n)
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) * inv
		h -= p * math.Log2(p)
	}
	return h
}

// isPrintable reports whether c is printable ASCII: the space-through-tilde
// run plus tab, newline and carriage return.
func isPrintable(c byte) bool {
	if c >= 0x20 && c <= 0x7e {
		return true
	}
	switch c {
	case '\t', '\n', '\r':
		return true
	}
	return false
}
