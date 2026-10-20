package entropy

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/tokio-drift/raccoon/internal/limits"
)

// ramp returns n bytes cycling 0..255. Any 256 consecutive bytes contain each
// value exactly once, so every aligned 1 KB block has entropy exactly 8.
func ramp(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// text returns n copies of a single printable byte (entropy 0).
func text(n int) []byte {
	return bytes.Repeat([]byte{'A'}, n)
}

func TestScanDetectsOpaqueRegion(t *testing.T) {
	const size = 8 * 1024
	data := ramp(size)
	regions, err := Scan(bytes.NewReader(data), []Range{{Start: 0, End: size}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 1 {
		t.Fatalf("regions = %+v, want 1", regions)
	}
	r := regions[0]
	if r.Start != 0 || r.End != size {
		t.Errorf("extent = [%d,%d), want [0,%d)", r.Start, r.End, size)
	}
	if math.Abs(r.MeanH-8.0) > 1e-9 {
		t.Errorf("mean entropy = %v, want 8", r.MeanH)
	}
}

func TestScanSkipsPrintableText(t *testing.T) {
	// Base64-like data: high entropy but ~100% printable ASCII, so it must be
	// treated as text and skipped.
	b64 := []byte("QWxsIHlvdXIgYmFzZTY0IGFyZSBiZWxvbmcgdG8gdXMhIEFhQmJDY0RkRWVGZkdnSGhJaUo=")
	data := bytes.Repeat(b64, 200)
	regions, err := Scan(bytes.NewReader(data), []Range{{Start: 0, End: int64(len(data))}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 0 {
		t.Fatalf("regions = %+v, want none (printable text)", regions)
	}
}

func TestScanSkipsLowEntropy(t *testing.T) {
	data := text(16 * 1024)
	regions, err := Scan(bytes.NewReader(data), []Range{{Start: 0, End: int64(len(data))}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 0 {
		t.Fatalf("regions = %+v, want none (low entropy)", regions)
	}
}

func TestScanBelowMinLength(t *testing.T) {
	// 2 KB of opaque data is under the 4 KB reporting floor.
	data := ramp(2 * 1024)
	regions, err := Scan(bytes.NewReader(data), []Range{{Start: 0, End: int64(len(data))}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 0 {
		t.Fatalf("regions = %+v, want none (< 4 KB)", regions)
	}

	// Exactly 4 KB is reported.
	data = ramp(4 * 1024)
	regions, err = Scan(bytes.NewReader(data), []Range{{Start: 0, End: int64(len(data))}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 1 {
		t.Fatalf("regions = %+v, want 1", regions)
	}
}

func TestScanSplitsOnInterruption(t *testing.T) {
	// 4 KB opaque, 4 KB text, 4 KB opaque -> two regions.
	data := append(append(ramp(4*1024), text(4*1024)...), ramp(4*1024)...)
	regions, err := Scan(bytes.NewReader(data), []Range{{Start: 0, End: int64(len(data))}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 2 {
		t.Fatalf("regions = %+v, want 2", regions)
	}
	if regions[0].Start != 0 || regions[0].End != 4*1024 {
		t.Errorf("region 0 extent = [%d,%d), want [0,%d)", regions[0].Start, regions[0].End, 4*1024)
	}
	if regions[1].Start != 8*1024 || regions[1].End != 12*1024 {
		t.Errorf("region 1 extent = [%d,%d), want [%d,%d)", regions[1].Start, regions[1].End, 8*1024, 12*1024)
	}
}

func TestScanMergesAcrossChunks(t *testing.T) {
	// Larger than scanChunk (64 KiB) so merging must span chunk boundaries.
	const size = 3*scanChunk + 1234
	data := ramp(size)
	regions, err := Scan(bytes.NewReader(data), []Range{{Start: 0, End: size}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 1 {
		t.Fatalf("regions = %+v, want 1 merged run", regions)
	}
	if regions[0].Start != 0 || regions[0].End != size {
		t.Errorf("extent = [%d,%d), want [0,%d)", regions[0].Start, regions[0].End, size)
	}
}

func TestScanRespectsRegionsAndOffsets(t *testing.T) {
	// Two disjoint opaque regions separated by text, supplied as two ranges so
	// they must not be merged even though they are adjacent in the reader.
	const block = 4 * 1024
	data := append(append(ramp(block), text(block)...), ramp(block)...)
	regions, err := Scan(bytes.NewReader(data), []Range{
		{Start: 0, End: block},
		{Start: 2 * block, End: 3 * block},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 2 {
		t.Fatalf("regions = %+v, want 2", regions)
	}
	if regions[0].Start != 0 || regions[0].End != block {
		t.Errorf("region 0 = [%d,%d)", regions[0].Start, regions[0].End)
	}
	if regions[1].Start != 2*block || regions[1].End != 3*block {
		t.Errorf("region 1 = [%d,%d)", regions[1].Start, regions[1].End)
	}
}

func TestScanUnalignedStart(t *testing.T) {
	// Start mid-block; offsets must stay absolute and alignment computed from
	// the stream offset, not the read cursor. The ramp is long enough that its
	// trailing partial block holds >= 256 distinct byte values, so the whole
	// scanned run stays opaque to its end.
	data := append(text(100), ramp(8*1024+300)...)
	regions, err := Scan(bytes.NewReader(data), []Range{{Start: 100, End: int64(len(data))}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 1 {
		t.Fatalf("regions = %+v, want 1", regions)
	}
	if regions[0].Start != 100 {
		t.Errorf("start = %d, want 100", regions[0].Start)
	}
	if regions[0].End != int64(len(data)) {
		t.Errorf("end = %d, want %d", regions[0].End, len(data))
	}
}

// TestScanShortTrailingBlockNotOpaque pins the threshold behaviour of a short
// trailing block: 100 distinct byte values give H = log2(100) ~ 6.64, below the
// 7.2 threshold, so the run stops before it.
func TestScanShortTrailingBlockNotOpaque(t *testing.T) {
	data := ramp(8*1024 + 100)
	regions, err := Scan(bytes.NewReader(data), []Range{{Start: 0, End: int64(len(data))}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 1 {
		t.Fatalf("regions = %+v, want 1 ending at the short tail", regions)
	}
	if regions[0].End != 8*1024 {
		t.Errorf("end = %d, want 8192 (short tail below threshold)", regions[0].End)
	}
}

func TestScanPartialTrailingBlock(t *testing.T) {
	// 5 KB = 5 full blocks; the last block is full. Try 4 KB + 300 bytes which
	// should still merge (trailing partial block is opaque).
	size := 4*1024 + 300
	data := ramp(size)
	regions, err := Scan(bytes.NewReader(data), []Range{{Start: 0, End: int64(size)}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 1 {
		t.Fatalf("regions = %+v, want 1", regions)
	}
	if regions[0].End != int64(size) {
		t.Errorf("end = %d, want %d", regions[0].End, size)
	}
}

func TestScanShortReaderStopsCleanly(t *testing.T) {
	// A range longer than the reader: only the available bytes are scanned.
	data := ramp(8 * 1024)
	regions, err := Scan(bytes.NewReader(data), []Range{{Start: 0, End: 1 << 20}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(regions) != 1 {
		t.Fatalf("regions = %+v, want 1", regions)
	}
	if regions[0].End != int64(len(data)) {
		t.Errorf("end = %d, want %d", regions[0].End, len(data))
	}
}

func TestScanNilAndEmptyInputs(t *testing.T) {
	if got, err := Scan(nil, []Range{{Start: 0, End: 100}}); err != nil || got != nil {
		t.Fatalf("nil reader: got %v, err %v", got, err)
	}
	if got, err := Scan(bytes.NewReader(ramp(1024)), nil); err != nil || got != nil {
		t.Fatalf("no regions: got %v, err %v", got, err)
	}
	if got, err := Scan(bytes.NewReader(ramp(1024)), []Range{{Start: 5, End: 5}}); err != nil || got != nil {
		t.Fatalf("empty range: got %v, err %v", got, err)
	}
	if got, err := Scan(bytes.NewReader(ramp(1024)), []Range{{Start: 10, End: -1}}); err != nil || got != nil {
		t.Fatalf("inverted range: got %v, err %v", got, err)
	}
}

// errReader fails every read after the first n bytes.
type errReader struct {
	data []byte
	n    int
}

func (e *errReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(e.n) {
		return 0, errors.New("boom")
	}
	n := copy(p, e.data[off:])
	return n, errors.New("boom")
}

func TestScanReadError(t *testing.T) {
	data := ramp(2 * scanChunk)
	r := &errReader{data: data, n: 0}
	if _, err := Scan(r, []Range{{Start: 0, End: int64(len(data))}}); err == nil {
		t.Fatal("expected an error from a failing reader")
	}
}

func TestShannonExtremes(t *testing.T) {
	// Uniform 0..255 -> 8 bits/byte.
	var uniform [256]int
	for i := range uniform {
		uniform[i] = 1
	}
	if h := shannon(uniform[:], 256); math.Abs(h-8) > 1e-9 {
		t.Errorf("uniform entropy = %v, want 8", h)
	}
	// All one value -> 0 bits/byte.
	var single [256]int
	single[42] = 1024
	if h := shannon(single[:], 1024); h != 0 {
		t.Errorf("single-value entropy = %v, want 0", h)
	}
	// Two equiprobable values -> 1 bit/byte.
	var two [256]int
	two[0], two[1] = 512, 512
	if h := shannon(two[:], 1024); math.Abs(h-1) > 1e-9 {
		t.Errorf("two-value entropy = %v, want 1", h)
	}
}

func TestBlockEntropyPrintableRule(t *testing.T) {
	// A block that is 95% printable but high entropy must be skipped.
	blk := make([]byte, limits.EntropyBlockSize)
	for i := range blk {
		if i%20 == 0 {
			blk[i] = 0x00 // 5% non-printable
		} else {
			blk[i] = byte('!' + i%94)
		}
	}
	if _, opaque := blockEntropy(blk); opaque {
		t.Error("mostly printable block marked opaque")
	}
	// A block of cycling 0..255 is only ~37% printable and has entropy 8, so it
	// is opaque.
	for i := range blk {
		blk[i] = byte(i)
	}
	if h, opaque := blockEntropy(blk); !opaque {
		t.Errorf("mostly non-printable block not opaque (h=%v)", h)
	}
}

func TestIsPrintable(t *testing.T) {
	for _, c := range []byte{' ', '~', '\t', '\n', '\r'} {
		if !isPrintable(c) {
			t.Errorf("isPrintable(%q) = false, want true", c)
		}
	}
	for _, c := range []byte{0x00, 0x1f, 0x7f, 0x80, 0xff} {
		if isPrintable(c) {
			t.Errorf("isPrintable(%#x) = true, want false", c)
		}
	}
}

// discardReader verifies Scan never reads past the range end.
func TestScanNeverReadsPastEnd(t *testing.T) {
	data := ramp(64 * 1024)
	r := &limitReader{data: data, limit: 8 * 1024}
	if _, err := Scan(r, []Range{{Start: 0, End: 8 * 1024}}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
}

type limitReader struct {
	data  []byte
	limit int
}

func (l *limitReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(l.limit) {
		return 0, io.EOF
	}
	if off+int64(len(p)) > int64(l.limit) {
		return 0, errors.New("read past limit")
	}
	return copy(p, l.data[off:]), nil
}
