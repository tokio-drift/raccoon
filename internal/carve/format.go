package carve

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Extent statuses. They map to model.CarvedFile.Status: a carved file is
// written for StatusComplete and StatusTruncated; StatusCorrupt results are
// dropped by the scanner.
const (
	// StatusComplete means the format's end marker was found and the structure
	// is fully validated up to it.
	StatusComplete = "complete"
	// StatusTruncated means the stream ended (or MaxSize was reached) before
	// the format's end marker; the bytes found so far are still carved.
	StatusTruncated = "truncated"
	// StatusCorrupt means the bytes matched a header but the structure is
	// broken (invalid length fields, missing markers).
	StatusCorrupt = "corrupt"
)

// Sentinel errors returned by this package.
var (
	// ErrBounds is returned when a read request is outside the stream or would
	// allocate more than the per-read cap.
	ErrBounds = errors.New("carve: read out of bounds")
	// ErrInvalidHeader is returned when the bytes at a start offset are not
	// the format's magic header.
	ErrInvalidHeader = errors.New("carve: invalid header")
	// ErrDuplicateFormat is returned when a registry already holds a format
	// with the same name.
	ErrDuplicateFormat = errors.New("carve: format already registered")
	// ErrInvalidFormat is returned when registering a nil format or one
	// without headers.
	ErrInvalidFormat = errors.New("carve: format needs a name and at least one header")
)

// maxReadBytes caps a single readFull request so a hostile length field can
// never drive an unbounded allocation.
const maxReadBytes = 1 << 20

// Format describes one carvable file format. Formats are stateless and shared:
// Extent may be called concurrently for different streams.
type Format interface {
	// Name returns the format name (e.g. "jpeg"), unique within a registry.
	Name() string
	// Ext returns the file extension without a leading dot (e.g. "jpg").
	Ext() string
	// Headers returns the magic byte patterns that start the format. Every
	// pattern must be non-empty; the longest one drives scanner overlap.
	Headers() [][]byte
	// MaxSize returns the largest file of this format that will be carved.
	MaxSize() int64
	// Extent locates the end of the file that starts at offset start inside a
	// stream of streamLen bytes. end is the absolute offset one past the file's
	// last byte and is always in (start, start+MaxSize] clamped to streamLen on
	// truncation. On success err is nil and status is StatusComplete,
	// StatusTruncated or StatusCorrupt. A structurally broken file returns
	// StatusCorrupt (the scanner drops it). Unreadable input returns a wrapped
	// io error (errors.Is with io.EOF / io.ErrUnexpectedEOF) and no end.
	Extent(r io.ReaderAt, start, streamLen int64) (end int64, status string, err error)
}

// BoundedFormat is implemented by formats whose Extent must not scan past the
// next carve-candidate header. PDF is the only such format: it searches
// backwards for the last %%EOF, so without a bound it would swallow every
// following document. The scanner clamps streamLen to the offset of the next
// header match (or the stream end) before calling Extent on a bounded format.
type BoundedFormat interface {
	Format
	// BoundedExtent reports whether the scanner must clamp the stream length
	// handed to Extent to the next carve-candidate header.
	BoundedExtent() bool
}

// readFull reads exactly n bytes at off from r. It returns ErrBounds for a
// negative offset, a negative length or a length above the per-read cap, and a
// wrapped io.EOF / io.ErrUnexpectedEOF when the stream is shorter than
// off+n (readers report short reads with a non-nil error).
func readFull(r io.ReaderAt, off, n int64) ([]byte, error) {
	if r == nil || off < 0 || n < 0 || n > maxReadBytes {
		return nil, fmt.Errorf("carve: readFull(off=%d, n=%d): %w", off, n, ErrBounds)
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
	return nil, fmt.Errorf("carve: read %d bytes at %d: %w", n, off, err)
}

// Registry holds the file formats the carver recognizes. Registration order is
// match priority for equally long headers; longer headers always win first.
type Registry struct {
	mu      sync.RWMutex
	formats []Format
}

// NewRegistry returns an empty format registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds f to the registry. It fails with ErrDuplicateFormat when a
// format with the same name is already registered and with ErrInvalidFormat
// for a nil format or one without headers.
func (r *Registry) Register(f Format) error {
	if f == nil || len(f.Headers()) == 0 || f.Name() == "" {
		return fmt.Errorf("carve: register: %w", ErrInvalidFormat)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, have := range r.formats {
		if have.Name() == f.Name() {
			return fmt.Errorf("carve: register %q: %w", f.Name(), ErrDuplicateFormat)
		}
	}
	r.formats = append(r.formats, f)
	return nil
}

// All returns the registered formats in registration order.
func (r *Registry) All() []Format {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Format(nil), r.formats...)
}

// MatchHeader returns the format whose header is the longest prefix of b.
// Ties go to the format registered first.
func (r *Registry) MatchHeader(b []byte) (Format, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var best Format
	bestLen := 0
	for _, f := range r.formats {
		for _, h := range f.Headers() {
			if len(h) > bestLen && len(b) >= len(h) && bytes.HasPrefix(b, h) {
				best, bestLen = f, len(h)
			}
		}
	}
	return best, best != nil
}

// MaxHeaderLen returns the length of the longest registered header, or 0 when
// the registry is empty. The scanner uses it as window overlap.
func (r *Registry) MaxHeaderLen() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	max := 0
	for _, f := range r.formats {
		for _, h := range f.Headers() {
			if len(h) > max {
				max = len(h)
			}
		}
	}
	return max
}

// Default is the package-level registry. Formats are registered explicitly by
// the caller (the pipeline wires them once), keeping this package free of
// init-time registration and import cycles with the formats subpackage.
var Default = NewRegistry()

// Register adds a format to Default.
func Register(f Format) error { return Default.Register(f) }

// Formats returns the formats registered in Default.
func Formats() []Format { return Default.All() }

// MatchHeader returns the Default format for a header prefix of b.
func MatchHeader(b []byte) (Format, bool) { return Default.MatchHeader(b) }

// MaxHeaderLen returns the longest header length registered in Default.
func MaxHeaderLen() int { return Default.MaxHeaderLen() }
