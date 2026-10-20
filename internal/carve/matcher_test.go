package carve

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
)

type matchHit struct {
	idx int
	off int64
}

// allOccurrences returns every overlapping occurrence of p in buf, found with
// bytes.Index starting one byte past each hit.
func allOccurrences(buf, p []byte) []int64 {
	var offs []int64
	if len(p) == 0 {
		return nil
	}
	for from := 0; from+len(p) <= len(buf); {
		j := bytes.Index(buf[from:], p)
		if j < 0 {
			break
		}
		offs = append(offs, int64(from+j))
		from = from + j + 1
	}
	return offs
}

func sortHits(hits []matchHit) {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].off != hits[j].off {
			return hits[i].off < hits[j].off
		}
		return hits[i].idx < hits[j].idx
	})
}

// TestMatcherMatchesBytesIndex is a property test: on random data the matcher
// must report exactly the same (pattern, offset) set as a bytes.Index
// reference scan, including overlapping hits.
func TestMatcherMatchesBytesIndex(t *testing.T) {
	patterns := [][]byte{
		[]byte("ab"),
		[]byte("bab"),
		[]byte("aa"),
		[]byte("\xff\xd8\xff"),
		[]byte("PK\x03\x04"),
		[]byte("longer-pattern"),
		nil, // empty patterns never match
		{},
	}
	m := NewMatcher(patterns)

	rng := rand.New(rand.NewSource(42))
	alphabet := []byte("ab\xff\x00PK\x03\x04\x01")

	for iter := 0; iter < 300; iter++ {
		buf := make([]byte, rng.Intn(513))
		for i := range buf {
			buf[i] = alphabet[rng.Intn(len(alphabet))]
		}

		var got []matchHit
		m.Scan(buf, 0, func(idx int, off int64) { got = append(got, matchHit{idx, off}) })
		sortHits(got)

		var want []matchHit
		for idx, p := range patterns {
			for _, off := range allOccurrences(buf, p) {
				want = append(want, matchHit{idx, off})
			}
		}
		sortHits(want)

		if len(got) != len(want) {
			t.Fatalf("iter %d: got %d matches, want %d\ngot  %v\nwant %v", iter, len(got), len(want), got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter %d: match %d = %+v, want %+v", iter, i, got[i], want[i])
			}
		}
	}
}

// TestMatcherBaseOffset verifies that reported offsets are base + position.
func TestMatcherBaseOffset(t *testing.T) {
	buf := []byte("xxPDFxxPDF")
	m := NewMatcher([][]byte{[]byte("PDF")})
	var offs []int64
	m.Scan(buf, 1000, func(_ int, off int64) { offs = append(offs, off) })
	want := []int64{1002, 1007}
	if len(offs) != len(want) {
		t.Fatalf("got offsets %v, want %v", offs, want)
	}
	for i := range want {
		if offs[i] != want[i] {
			t.Fatalf("offset %d = %d, want %d", i, offs[i], want[i])
		}
	}
}

// TestMatcherOverlappingOccurrences checks that overlapping hits of the same
// pattern are all reported.
func TestMatcherOverlappingOccurrences(t *testing.T) {
	m := NewMatcher([][]byte{[]byte("aaa")})
	var offs []int64
	m.Scan([]byte("aaaaa"), 0, func(_ int, off int64) { offs = append(offs, off) })
	want := []int64{0, 1, 2}
	if len(offs) != len(want) {
		t.Fatalf("got %v, want %v", offs, want)
	}
	for i := range want {
		if offs[i] != want[i] {
			t.Fatalf("offset %d = %d, want %d", i, offs[i], want[i])
		}
	}
}

// TestMatcherSuffixPatterns verifies patterns that are suffixes of other
// patterns (reported through fail links) are both found. In "theshe", "the"
// ends at 0 with "he" inside it at 1, "she" ends at 3 with "he" inside it at
// 4.
func TestMatcherSuffixPatterns(t *testing.T) {
	m := NewMatcher([][]byte{[]byte("he"), []byte("the"), []byte("she")})
	var hits []matchHit
	m.Scan([]byte("theshe"), 0, func(idx int, off int64) { hits = append(hits, matchHit{idx, off}) })
	sortHits(hits)
	want := []matchHit{{1, 0}, {0, 1}, {2, 3}, {0, 4}}
	if len(hits) != len(want) {
		t.Fatalf("got %v, want %v", hits, want)
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Fatalf("hit %d = %+v, want %+v", i, hits[i], want[i])
		}
	}
}

// TestMatcherNilFn guards against a nil callback.
func TestMatcherNilFn(t *testing.T) {
	m := NewMatcher([][]byte{[]byte("a")})
	m.Scan([]byte("aaa"), 0, nil)
}

// BenchmarkMatcherScan measures a single pass over a 1 MiB buffer with the
// four header patterns of the carver.
func BenchmarkMatcherScan(b *testing.B) {
	patterns := [][]byte{
		{0xFF, 0xD8, 0xFF},
		{'%', 'P', 'D', 'F'},
		{'P', 'K', 0x03, 0x04},
		{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
	}
	rng := rand.New(rand.NewSource(7))
	buf := make([]byte, 1<<20)
	for i := range buf {
		buf[i] = byte(rng.Intn(256))
	}
	m := NewMatcher(patterns)

	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Scan(buf, 0, func(int, int64) {})
	}
}
