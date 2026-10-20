package carve

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
)

// testFormat is a configurable Format for scanner tests. extent, when set,
// decides the returned end and status; otherwise it echoes the record end.
type testFormat struct {
	name    string
	ext     string
	headers [][]byte
	maxSize int64
	extent  func(start, streamLen int64) (int64, string, error)
}

func (f testFormat) Name() string      { return f.name }
func (f testFormat) Ext() string       { return f.ext }
func (f testFormat) Headers() [][]byte { return f.headers }
func (f testFormat) MaxSize() int64    { return f.maxSize }

func (f testFormat) Extent(_ io.ReaderAt, start, streamLen int64) (int64, string, error) {
	if f.extent != nil {
		return f.extent(start, streamLen)
	}
	return streamLen, StatusComplete, nil
}

// boundedTestFormat is a BoundedFormat whose Extent records the bound it was
// handed, so tests can assert the scanner clamped it to the next header.
type boundedTestFormat struct {
	testFormat
	bounds *[]int64
}

func (f boundedTestFormat) BoundedExtent() bool { return true }

func (f boundedTestFormat) Extent(r io.ReaderAt, start, streamLen int64) (int64, string, error) {
	if f.bounds != nil {
		*f.bounds = append(*f.bounds, streamLen)
	}
	return start + 4, StatusComplete, nil
}

// newTestScanner builds a Scanner over dir with the given formats.
func newTestScanner(t *testing.T, dir string, formats ...Format) *Scanner {
	t.Helper()
	reg := NewRegistry()
	for _, f := range formats {
		if err := reg.Register(f); err != nil {
			t.Fatalf("register %s: %v", f.Name(), err)
		}
	}
	s, err := NewScanner(Config{Registry: reg, CarvedDir: dir})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s
}

func marker(seq byte, n int) []byte { return bytes.Repeat([]byte{seq}, n) }

// fixedExtent returns an Extent func that ends exactly n bytes after start.
func fixedExtent(n int) func(start, streamLen int64) (int64, string, error) {
	return func(start, streamLen int64) (int64, string, error) {
		end := start + int64(n)
		if end > streamLen {
			end = streamLen
		}
		return end, StatusComplete, nil
	}
}

func TestScannerCarvesSingleFile(t *testing.T) {
	dir := t.TempDir()
	body := append([]byte("MAGI"), marker('a', 100)...)
	stream := append([]byte("prefix--"), body...)
	stream = append(stream, []byte("suffix")...)

	f := testFormat{name: "magic", ext: "mag", headers: [][]byte{{'M', 'A', 'G', 'I'}}, extent: fixedExtent(len(body))}
	s := newTestScanner(t, dir, f)

	var got []Carved
	if err := s.ScanStream(bytes.NewReader(stream), int64(len(stream)), model.S2C, "report.mag", func(c Carved) {
		got = append(got, c)
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("carved %d files, want 1", len(got))
	}
	c := got[0]
	if c.Format.Name() != "magic" || c.Ext != "mag" {
		t.Fatalf("unexpected format/ext: %q %q", c.Format.Name(), c.Ext)
	}
	if c.Dir != model.S2C {
		t.Fatalf("dir = %d, want S2C", c.Dir)
	}
	if c.Start != 8 {
		t.Fatalf("start = %d, want 8", c.Start)
	}
	if c.End != int64(8+len(body)) {
		t.Fatalf("end = %d, want %d", c.End, 8+len(body))
	}
	if c.Size != int64(len(body)) {
		t.Fatalf("size = %d, want %d", c.Size, len(body))
	}
	if c.DisplayName != "report.mag" {
		t.Fatalf("display name = %q, want report.mag", c.DisplayName)
	}
	if c.MagicHex != hex.EncodeToString([]byte("MAGI")) {
		t.Fatalf("magicHex = %q", c.MagicHex)
	}

	wantSHA := sha256.Sum256(body)
	if c.SHA256 != hex.EncodeToString(wantSHA[:]) {
		t.Fatalf("sha256 = %q, want %q", c.SHA256, hex.EncodeToString(wantSHA[:]))
	}
	if c.Status != StatusComplete {
		t.Fatalf("status = %q", c.Status)
	}

	// The carved file exists with the extracted bytes and read-only mode.
	onDisk, err := os.ReadFile(c.Path)
	if err != nil {
		t.Fatalf("read carved: %v", err)
	}
	if !bytes.Equal(onDisk, body) {
		t.Fatalf("carved bytes differ from body")
	}
	info, err := os.Stat(c.Path)
	if err != nil {
		t.Fatalf("stat carved: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("mode = %v, want 0400", info.Mode().Perm())
	}
	if filepath.Base(c.Path) != c.SHA256+"."+c.Ext {
		t.Fatalf("path = %q, want <sha>.%s", c.Path, c.Ext)
	}
	// No temp files are left behind.
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("carved dir has %d entries, want 1", len(ents))
	}
}

func TestScannerMultipleFilesAndCursorSkip(t *testing.T) {
	dir := t.TempDir()
	// First file deliberately contains an embedded MAGI at offset 10 that must
	// be skipped because it lies inside the already carved range. Both files
	// are 60 bytes so fixedExtent identifies their extents.
	const fileLen = 60
	first := make([]byte, fileLen)
	copy(first, "MAGI")
	copy(first[10:], "MAGI") // nested header inside the first file
	second := append([]byte("MAGI"), marker('y', fileLen-4)...)
	stream := append(append([]byte{}, first...), second...)

	f := testFormat{name: "magic", ext: "mag", headers: [][]byte{{'M', 'A', 'G', 'I'}}, extent: fixedExtent(fileLen)}
	s := newTestScanner(t, dir, f)

	var got []Carved
	if err := s.ScanStream(bytes.NewReader(stream), int64(len(stream)), model.C2S, "", func(c Carved) {
		got = append(got, c)
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("carved %d files, want 2 (nested header must be skipped)", len(got))
	}
	if got[0].Start != 0 || got[0].End != fileLen {
		t.Fatalf("first extent = [%d,%d), want [0,%d)", got[0].Start, got[0].End, fileLen)
	}
	if got[1].Start != fileLen {
		t.Fatalf("second start = %d, want %d", got[1].Start, fileLen)
	}
}

func TestScannerDropsCorruptAndCounts(t *testing.T) {
	dir := t.TempDir()
	stream := append([]byte("MAGI"), marker('z', 20)...)
	f := testFormat{
		name:    "magic",
		ext:     "mag",
		headers: [][]byte{{'M', 'A', 'G', 'I'}},
		extent: func(start, _ int64) (int64, string, error) {
			return start, StatusCorrupt, nil
		},
	}
	s := newTestScanner(t, dir, f)

	var got []Carved
	if err := s.ScanStream(bytes.NewReader(stream), int64(len(stream)), model.C2S, "", func(c Carved) {
		got = append(got, c)
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("carved %d files, want 0", len(got))
	}
	if st := s.Stats(); st.Corrupt != 1 {
		t.Fatalf("corrupt = %d, want 1", st.Corrupt)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Fatalf("carved dir has %d entries, want 0", len(ents))
	}
}

func TestScannerReusesExistingSHA(t *testing.T) {
	dir := t.TempDir()
	body := append([]byte("MAGI"), marker('q', 16)...)
	wantSHA := sha256.Sum256(body)
	existing := filepath.Join(dir, hex.EncodeToString(wantSHA[:])+".mag")
	if err := os.WriteFile(existing, body, 0o400); err != nil {
		t.Fatalf("seed existing: %v", err)
	}

	f := testFormat{name: "magic", ext: "mag", headers: [][]byte{{'M', 'A', 'G', 'I'}}}
	s := newTestScanner(t, dir, f)

	var got []Carved
	if err := s.ScanStream(bytes.NewReader(body), int64(len(body)), model.C2S, "", func(c Carved) {
		got = append(got, c)
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 || !got[0].Reused {
		t.Fatalf("want 1 reused carve, got %+v", got)
	}
	if st := s.Stats(); st.Reused != 1 || st.Bytes != 0 {
		t.Fatalf("stats = %+v, want Reused=1 Bytes=0", st)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("carved dir has %d entries, want 1", len(ents))
	}
}

func TestScannerDiskBudgetDropsCandidate(t *testing.T) {
	dir := t.TempDir()
	body := append([]byte("MAGI"), marker('d', 64)...)
	f := testFormat{name: "magic", ext: "mag", headers: [][]byte{{'M', 'A', 'G', 'I'}}}

	reg := NewRegistry()
	if err := reg.Register(f); err != nil {
		t.Fatal(err)
	}
	disk := &fakeDisk{wouldExceed: true}
	s, err := NewScanner(Config{Registry: reg, CarvedDir: dir, Disk: disk})
	if err != nil {
		t.Fatal(err)
	}

	var got []Carved
	if err := s.ScanStream(bytes.NewReader(body), int64(len(body)), model.C2S, "", func(c Carved) {
		got = append(got, c)
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("carved %d files, want 0", len(got))
	}
	if st := s.Stats(); st.DiskSkipped != 1 {
		t.Fatalf("diskSkipped = %d, want 1", st.DiskSkipped)
	}
	if disk.added != 0 {
		t.Fatalf("disk.AddCarved called with %d, want 0", disk.added)
	}
}

func TestScannerDiskCounterAddsWrittenBytes(t *testing.T) {
	dir := t.TempDir()
	body := append([]byte("MAGI"), marker('d', 64)...)
	f := testFormat{name: "magic", ext: "mag", headers: [][]byte{{'M', 'A', 'G', 'I'}}}

	reg := NewRegistry()
	if err := reg.Register(f); err != nil {
		t.Fatal(err)
	}
	disk := &fakeDisk{}
	s, err := NewScanner(Config{Registry: reg, CarvedDir: dir, Disk: disk})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ScanStream(bytes.NewReader(body), int64(len(body)), model.C2S, "", nil); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if disk.added != int64(len(body)) {
		t.Fatalf("disk.AddCarved = %d, want %d", disk.added, len(body))
	}
}

func TestScannerMaxSizeCap(t *testing.T) {
	dir := t.TempDir()
	// Extent claims the whole 500-byte record; MaxSize caps it to 100.
	stream := append([]byte("MAGI"), marker('m', 500)...)
	f := testFormat{name: "magic", ext: "mag", headers: [][]byte{{'M', 'A', 'G', 'I'}}}

	reg := NewRegistry()
	if err := reg.Register(f); err != nil {
		t.Fatal(err)
	}
	s, err := NewScanner(Config{Registry: reg, CarvedDir: dir, MaxSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	var got []Carved
	if err := s.ScanStream(bytes.NewReader(stream), int64(len(stream)), model.C2S, "", func(c Carved) {
		got = append(got, c)
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("carved %d, want 1", len(got))
	}
	if got[0].Size != 100 || got[0].End != 100 {
		t.Fatalf("size/end = %d/%d, want 100/100", got[0].Size, got[0].End)
	}
}

func TestScannerBoundedFormatClampsToNextHeader(t *testing.T) {
	dir := t.TempDir()
	// Two "documents"; a bounded format must be handed a stream length that
	// stops at the second header.
	first := append([]byte("MAGI"), marker('a', 10)...)
	second := append([]byte("MAGI"), marker('b', 10)...)
	stream := append(append([]byte{}, first...), second...)

	var bounds []int64
	bf := boundedTestFormat{
		testFormat: testFormat{name: "doc", ext: "doc", headers: [][]byte{{'M', 'A', 'G', 'I'}}},
		bounds:     &bounds,
	}
	s := newTestScanner(t, dir, bf)

	if err := s.ScanStream(bytes.NewReader(stream), int64(len(stream)), model.C2S, "", nil); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(bounds) == 0 {
		t.Fatal("bounded Extent was never called")
	}
	if bounds[0] != int64(len(first)) {
		t.Fatalf("first bound = %d, want %d (next header offset)", bounds[0], len(first))
	}
}

func TestScannerFindsHeaderAcrossWindowBoundary(t *testing.T) {
	dir := t.TempDir()
	const bodyLen = 8
	// Place the header so it straddles the 1 MB window boundary: the file
	// starts 2 bytes before the boundary and its 4-byte header spans it.
	filler := marker('-', scanWindow-2)
	body := append([]byte("MAGI"), marker('w', bodyLen)...)
	stream := append(filler, body...)

	f := testFormat{name: "magic", ext: "mag", headers: [][]byte{{'M', 'A', 'G', 'I'}}, extent: fixedExtent(len(body))}
	s := newTestScanner(t, dir, f)

	var got []Carved
	if err := s.ScanStream(bytes.NewReader(stream), int64(len(stream)), model.C2S, "", func(c Carved) {
		got = append(got, c)
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("carved %d files, want 1", len(got))
	}
	if got[0].Start != int64(scanWindow-2) {
		t.Fatalf("start = %d, want %d", got[0].Start, scanWindow-2)
	}
	if got[0].End != got[0].Start+int64(len(body)) {
		t.Fatalf("end = %d, want %d", got[0].End, got[0].Start+int64(len(body)))
	}
}

func TestScannerReadErrorCounted(t *testing.T) {
	dir := t.TempDir()
	stream := append([]byte("MAGI"), marker('e', 8)...)
	f := testFormat{
		name:    "magic",
		ext:     "mag",
		headers: [][]byte{{'M', 'A', 'G', 'I'}},
		extent: func(start, _ int64) (int64, string, error) {
			return 0, "", errors.New("boom")
		},
	}
	s := newTestScanner(t, dir, f)
	if err := s.ScanStream(bytes.NewReader(stream), int64(len(stream)), model.C2S, "", nil); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if st := s.Stats(); st.ReadErrors != 1 {
		t.Fatalf("readErrors = %d, want 1", st.ReadErrors)
	}
}

func TestNewScannerValidation(t *testing.T) {
	if _, err := NewScanner(Config{CarvedDir: t.TempDir()}); !errors.Is(err, ErrNoRegistry) {
		t.Fatalf("missing registry err = %v, want ErrNoRegistry", err)
	}
	if _, err := NewScanner(Config{Registry: NewRegistry()}); !errors.Is(err, ErrNoCarvedDir) {
		t.Fatalf("missing dir err = %v, want ErrNoCarvedDir", err)
	}
}

func TestScannerEmptyAndNilTargets(t *testing.T) {
	dir := t.TempDir()
	s := newTestScanner(t, dir, testFormat{name: "magic", ext: "mag", headers: [][]byte{{'M', 'A', 'G', 'I'}}})
	if err := s.ScanStream(nil, 10, model.C2S, "", nil); err != nil {
		t.Fatalf("nil reader: %v", err)
	}
	if err := s.ScanStream(bytes.NewReader(nil), 0, model.C2S, "", nil); err != nil {
		t.Fatalf("zero length: %v", err)
	}
	// A registry with no formats is a no-op.
	empty, err := NewScanner(Config{Registry: NewRegistry(), CarvedDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := empty.ScanStream(bytes.NewReader([]byte("MAGI...")), 7, model.C2S, "", nil); err != nil {
		t.Fatalf("empty registry: %v", err)
	}
}

func TestMagicHexFromBytes(t *testing.T) {
	f := testFormat{name: "magic", ext: "mag", headers: [][]byte{{'M', 'A', 'G', 'I'}}}
	if got := MagicHexFromBytes(f, []byte("MAGIxx")); got != hex.EncodeToString([]byte("MAGI")) {
		t.Fatalf("magicHex = %q", got)
	}
	if got := MagicHexFromBytes(f, []byte("nope")); got != "" {
		t.Fatalf("magicHex = %q, want empty", got)
	}
}

// fakeDisk is a DiskCounter stub for scanner tests.
type fakeDisk struct {
	wouldExceed bool
	added       int64
}

func (d *fakeDisk) WouldExceed(int64) bool { return d.wouldExceed }
func (d *fakeDisk) AddCarved(n int64)      { d.added += n }

// TestScannerStressManyCandidates is a light property test: a stream with many
// interleaved headers carves each disjoint file exactly once.
func TestScannerStressManyCandidates(t *testing.T) {
	dir := t.TempDir()
	var stream []byte
	const n = 200
	for i := 0; i < n; i++ {
		stream = append(stream, 'A', 'A', 'A') // 3-byte filler
		stream = append(stream, []byte("MAGI")...)
		stream = append(stream, marker(byte(i), 5)...)
	}
	f := testFormat{name: "magic", ext: "mag", headers: [][]byte{{'M', 'A', 'G', 'I'}}, extent: fixedExtent(9)}
	s := newTestScanner(t, dir, f)

	var got []Carved
	if err := s.ScanStream(bytes.NewReader(stream), int64(len(stream)), model.C2S, "", func(c Carved) {
		got = append(got, c)
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != n {
		t.Fatalf("carved %d files, want %d", len(got), n)
	}
	for i, c := range got {
		if c.Size != 9 {
			t.Fatalf("file %d size = %d, want 9", i, c.Size)
		}
	}
}
