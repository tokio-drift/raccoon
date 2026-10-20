package carve

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/tokio-drift/raccoon/internal/model"
)

// scanWindow is the size of the sliding window the scanner reads and searches
// in a single pass. Consecutive windows overlap by maxHeaderLen-1 bytes so a
// header split across a window boundary is still found with its true offset.
const scanWindow = 1 << 20

var (
	// ErrNoCarvedDir is returned when a Scanner is built without an output
	// directory for carved files.
	ErrNoCarvedDir = errors.New("carve: scanner needs a carved directory")
	// ErrNoRegistry is returned when a Scanner is built without a format
	// registry.
	ErrNoRegistry = errors.New("carve: scanner needs a registry")
	// ErrDiskFull is reported for a candidate that was not written because the
	// disk budget would be exceeded.
	ErrDiskFull = errors.New("carve: disk budget exceeded")
)

// DiskCounter is the subset of resource.DiskCounter the scanner needs to keep
// carved output within the configured disk budget. A nil DiskCounter means
// unlimited disk usage.
type DiskCounter interface {
	// WouldExceed reports whether adding n bytes would reach the disk limit.
	WouldExceed(n int64) bool
	// AddCarved records n newly written carved bytes.
	AddCarved(n int64)
}

// Target describes one byte range to scan: a direction of a reassembled stream
// or a decoded file body an analyzer handed over as a proto.FileSource. Name,
// when non-empty, is carried into the carved record as a display name.
type Target struct {
	Reader io.ReaderAt
	Len    int64
	Dir    model.Direction
	Name   string
}

// Carved is one file candidate the scanner found and (unless identically named
// content already existed) wrote to disk. The pipeline turns these into
// FILE_CARVED events and CarvedFile rows.
type Carved struct {
	Format      Format
	Dir         model.Direction
	Start, End  int64  // [Start, End) inside the scanned target
	Status      string // StatusComplete or StatusTruncated
	SHA256, MD5 string
	Size        int64
	MagicHex    string
	Ext         string
	Path        string // absolute path of the carved file on disk
	RelPath     string // path relative to the case directory (carved/<sha>.<ext>)
	DisplayName string // from Target.Name when non-empty
	Reused      bool   // identical content already existed on disk
}

// Stats counts what a Scanner has done. It is safe to read after a scan
// completes.
type Stats struct {
	Files       int64 // candidates whose bytes were written or reused
	Bytes       int64 // bytes of newly written carved files
	Corrupt     int64 // candidates dropped because Extent reported corrupt
	ReadErrors  int64 // candidates dropped because Extent returned an I/O error
	DiskSkipped int64 // candidates dropped because of the disk budget
	Reused      int64 // candidates whose content already existed
}

// Config configures a Scanner.
type Config struct {
	// Registry holds the formats to search for. Required.
	Registry *Registry
	// CarvedDir is the directory carved files are written to (case CarvedDir).
	// Required.
	CarvedDir string
	// MaxSize, when > 0, caps a single carved file across every format,
	// overriding a larger per-format MaxSize.
	MaxSize int64
	// Disk, when non-nil, is consulted before writing and updated after.
	Disk DiskCounter
	// Logger receives per-candidate debug lines. Defaults to slog.Default.
	Logger *slog.Logger
}

// Scanner finds and extracts embedded files from stream bytes. It is safe for
// concurrent use once constructed: construction snapshots the registry and the
// per-candidate state is local to each scan.
type Scanner struct {
	reg    *Registry
	dir    string
	maxSz  int64
	disk   DiskCounter
	log    *slog.Logger
	window int

	matcher *Matcher
	// patterns maps matcher pattern index to the format that owns it.
	patterns []Format

	files       atomic.Int64
	bytes       atomic.Int64
	corrupt     atomic.Int64
	readErrors  atomic.Int64
	diskSkipped atomic.Int64
	reused      atomic.Int64
}

// NewScanner builds a Scanner over cfg.Registry.
func NewScanner(cfg Config) (*Scanner, error) {
	if cfg.Registry == nil {
		return nil, ErrNoRegistry
	}
	if cfg.CarvedDir == "" {
		return nil, ErrNoCarvedDir
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Scanner{
		reg:   cfg.Registry,
		dir:   cfg.CarvedDir,
		maxSz: cfg.MaxSize,
		disk:  cfg.Disk,
		log:   logger,
	}
	var pats [][]byte
	for _, f := range cfg.Registry.All() {
		for _, h := range f.Headers() {
			if len(h) == 0 {
				continue
			}
			s.patterns = append(s.patterns, f)
			pats = append(pats, append([]byte(nil), h...))
		}
	}
	s.matcher = NewMatcher(pats)
	overlap := cfg.Registry.MaxHeaderLen() - 1
	if overlap < 1 {
		overlap = 1
	}
	s.window = scanWindow
	if s.window <= overlap {
		s.window = overlap + 1
	}
	return s, nil
}

// MaxHeaderLen returns the overlap the scanner uses between windows, derived
// from the registry.
func (s *Scanner) MaxHeaderLen() int { return s.reg.MaxHeaderLen() }

// Stats returns the cumulative counters.
func (s *Scanner) Stats() Stats {
	return Stats{
		Files:       s.files.Load(),
		Bytes:       s.bytes.Load(),
		Corrupt:     s.corrupt.Load(),
		ReadErrors:  s.readErrors.Load(),
		DiskSkipped: s.diskSkipped.Load(),
		Reused:      s.reused.Load(),
	}
}

// ScanStream scans one direction of a reassembled stream (or a decoded file
// body) and calls visit for every candidate it managed to write or reuse.
// Candidates whose structure is broken (StatusCorrupt) are dropped and counted
// in the debug log. visit is called with files in ascending start offset order.
func (s *Scanner) ScanStream(r io.ReaderAt, streamLen int64, dir model.Direction, name string, visit func(Carved)) error {
	if r == nil || streamLen <= 0 || len(s.patterns) == 0 {
		return nil
	}
	t := Target{Reader: r, Len: streamLen, Dir: dir, Name: name}
	return s.Scan(t, visit)
}

// Scan scans one Target. See ScanStream.
func (s *Scanner) Scan(t Target, visit func(Carved)) error {
	if t.Reader == nil || t.Len <= 0 || len(s.patterns) == 0 {
		return nil
	}
	if visit == nil {
		visit = func(Carved) {}
	}
	overlap := s.MaxHeaderLen() - 1
	if overlap < 1 {
		overlap = 1
	}
	streamLen := t.Len

	cursor := int64(0) // start of the first byte not yet covered by a carve
	for off := int64(0); off < streamLen; {
		n := int64(s.window)
		if streamLen-off < n {
			n = streamLen - off
		}
		buf := make([]byte, n)
		got, err := t.Reader.ReadAt(buf, off)
		if got == 0 && err != nil {
			break
		}
		buf = buf[:got]
		last := off+int64(got) >= streamLen
		handled := int64(-1) // last offset already evaluated in this window

		s.matcher.Scan(buf, off, func(pi int, h int64) {
			// Hits inside an already carved range are skipped.
			if h < cursor {
				return
			}
			// A hit starting in the overlap zone is re-reported by the next
			// window with a full header context, so defer it there. On the
			// final window there is no next window.
			if !last && h >= off+int64(got)-int64(overlap) {
				return
			}
			// Several registered headers may match at the same offset (shared
			// prefixes); evaluate the position only once.
			if h == handled {
				return
			}
			handled = h
			f := s.patterns[pi]
			if canonical, ok := s.reg.MatchHeader(buf[h-off:]); ok {
				f = canonical
			}
			end, status, err := s.extent(t.Reader, f, h, streamLen)
			switch {
			case err != nil:
				s.readErrors.Add(1)
				s.log.Debug("carve: extent error",
					"format", f.Name(), "dir", dirString(t.Dir), "off", h, "err", err)
				return
			case status == StatusCorrupt:
				s.corrupt.Add(1)
				s.log.Debug("carve: corrupt candidate dropped",
					"format", f.Name(), "dir", dirString(t.Dir), "off", h, "end", end)
				return
			}
			if end <= h {
				return
			}
			size := end - h
			if s.maxSz > 0 && size > s.maxSz {
				size = s.maxSz
				end = h + size
			}
			if s.disk != nil && s.disk.WouldExceed(size) {
				s.diskSkipped.Add(1)
				s.log.Debug("carve: disk budget exceeded, candidate dropped",
					"format", f.Name(), "dir", dirString(t.Dir), "off", h, "size", size)
				cursor = end
				return
			}
			c := s.write(t.Reader, f, t, h, end, status)
			if c == nil {
				return
			}
			cursor = end
			s.files.Add(1)
			if c.Reused {
				s.reused.Add(1)
			} else {
				s.bytes.Add(c.Size)
			}
			visit(*c)
		})

		if last {
			break
		}
		adv := int64(got) - int64(overlap)
		if adv <= 0 {
			break
		}
		off += adv
	}
	return nil
}

// extent calls f.Extent, clamping the stream length for bounded formats (PDF)
// to the offset of the next carve-candidate header so a following file cannot
// be swallowed.
func (s *Scanner) extent(r io.ReaderAt, f Format, start, streamLen int64) (int64, string, error) {
	bound := streamLen
	if bf, ok := f.(BoundedFormat); ok && bf.BoundedExtent() {
		bound = s.nextHeader(r, start+1, streamLen)
	}
	return f.Extent(r, start, bound)
}

// nextHeader returns the offset of the first header match at or after from, or
// streamLen when there is none.
func (s *Scanner) nextHeader(r io.ReaderAt, from, streamLen int64) int64 {
	overlap := s.MaxHeaderLen() - 1
	if overlap < 1 {
		overlap = 1
	}
	for off := from; off < streamLen; {
		n := int64(s.window)
		if streamLen-off < n {
			n = streamLen - off
		}
		buf := make([]byte, n)
		got, err := r.ReadAt(buf, off)
		if got == 0 && err != nil {
			break
		}
		buf = buf[:got]
		found := int64(-1)
		s.matcher.Scan(buf, off, func(_ int, h int64) {
			if found < 0 && h >= from {
				found = h
			}
		})
		if found >= 0 {
			return found
		}
		if off+int64(got) >= streamLen {
			break
		}
		adv := int64(got) - int64(overlap)
		if adv <= 0 {
			break
		}
		off += adv
	}
	return streamLen
}

// write streams [start,end) through MD5 and SHA-256 into a temp file in the
// carved directory, then chmod 0400 and renames it to <sha256>.<ext>. If a
// file with the same SHA-256 already exists its content is reused. It returns
// nil when the candidate cannot be written.
func (s *Scanner) write(r io.ReaderAt, f Format, t Target, start, end int64, status string) *Carved {
	ext := f.Ext()
	size := end - start

	tmp, err := os.CreateTemp(s.dir, ".carve-*")
	if err != nil {
		s.log.Debug("carve: create temp", "dir", s.dir, "err", err)
		return nil
	}
	tmpName := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpName)
		}
	}()

	md5h := md5.New()
	sha := sha256.New()
	src := io.NewSectionReader(r, start, size)
	if _, err := io.Copy(io.MultiWriter(tmp, md5h, sha), src); err != nil {
		tmp.Close()
		s.log.Debug("carve: copy bytes", "format", f.Name(), "err", err)
		return nil
	}
	if err := tmp.Close(); err != nil {
		s.log.Debug("carve: close temp", "err", err)
		return nil
	}

	shaHex := hex.EncodeToString(sha.Sum(nil))
	md5Hex := hex.EncodeToString(md5h.Sum(nil))
	final := filepath.Join(s.dir, shaHex+"."+ext)

	c := &Carved{
		Format:      f,
		Dir:         t.Dir,
		Start:       start,
		End:         end,
		Status:      status,
		SHA256:      shaHex,
		MD5:         md5Hex,
		Size:        size,
		MagicHex:    magicHex(f, r, start),
		Ext:         ext,
		Path:        final,
		RelPath:     filepath.ToSlash(filepath.Join(filepath.Base(s.dir), shaHex+"."+ext)),
		DisplayName: t.Name,
	}

	if _, err := os.Stat(final); err == nil {
		c.Reused = true
		return c
	}

	if err := os.Chmod(tmpName, 0o400); err != nil {
		s.log.Debug("carve: chmod temp", "err", err)
		return nil
	}
	if err := os.Rename(tmpName, final); err != nil {
		// Another scan may have written the identical file first; reuse it.
		if _, statErr := os.Stat(final); statErr == nil {
			c.Reused = true
			return c
		}
		s.log.Debug("carve: rename", "err", err)
		return nil
	}
	removeTmp = false
	if s.disk != nil {
		s.disk.AddCarved(size)
	}
	return c
}

// magicHex returns the hex of the format header that prefixes the bytes at off.
func magicHex(f Format, r io.ReaderAt, off int64) string {
	var longest []byte
	for _, h := range f.Headers() {
		if len(h) > len(longest) {
			longest = h
		}
	}
	if len(longest) == 0 {
		return ""
	}
	buf := make([]byte, len(longest))
	if _, err := r.ReadAt(buf, off); err != nil {
		return ""
	}
	for _, h := range f.Headers() {
		if len(buf) >= len(h) && string(buf[:len(h)]) == string(h) {
			return hex.EncodeToString(h)
		}
	}
	return hex.EncodeToString(longest)
}

// MagicHexFromBytes returns the hex of the first format header that prefixes
// b, for callers that already hold the file's first bytes (e.g. the pipeline
// when building CarvedFile rows).
func MagicHexFromBytes(f Format, b []byte) string {
	for _, h := range f.Headers() {
		if len(b) >= len(h) && string(b[:len(h)]) == string(h) {
			return hex.EncodeToString(h)
		}
	}
	return ""
}

func dirString(dir model.Direction) string {
	if dir == model.S2C {
		return "s2c"
	}
	return "c2s"
}
