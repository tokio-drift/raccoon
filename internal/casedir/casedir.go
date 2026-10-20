// Package casedir manages the on-disk layout of a case directory.
package casedir

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/version"
)

var (
	// ErrNotACase indicates a path that is not a case directory (no case.json).
	ErrNotACase = errors.New("casedir: not a case directory")
	// ErrInvalidID indicates a case id that cannot form a safe path.
	ErrInvalidID = errors.New("casedir: invalid case id")
)

// Fixed file and directory names inside a case directory.
const (
	CaseJSON   = "case.json"
	DBFile     = "raccoon.db"
	PktIndex   = "pktindex.bin"
	StreamsDir = "streams"
	CarvedDir  = "carved"
	ReportsDir = "reports"
)

// idRe constrains case ids to <base>/YYYYMMDD-HHMMSS-<6 hex> so that ids can
// never contain path separators or escape the base directory.
var idRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$`)

// Options configures Create.
type Options struct {
	// ID overrides the generated case id; it must satisfy NewID's format.
	ID string
	// PCAP is the source capture path written to case.json.
	PCAP string
	// Created overrides the creation timestamp (defaults to now).
	Created time.Time
	// Version overrides the recorded tool version (defaults to version.String).
	Version string
	// Extra is preserved verbatim under case.json "options".
	Extra map[string]any
}

// Meta is the case.json envelope.
type Meta struct {
	Version string         `json:"version"`
	PCAP    string         `json:"pcap"`
	Created time.Time      `json:"created"`
	Options map[string]any `json:"options,omitempty"`
}

// Case points at one case directory.
type Case struct {
	Dir  string // absolute base + id
	ID   string
	Meta Meta
}

// ValidID reports whether id has the canonical case id form
// YYYYMMDD-HHMMSS-<6 hex>. Callers that build paths from untrusted ids (the
// HTTP API) must check this before joining.
func ValidID(id string) bool { return idRe.MatchString(id) }

// NewID returns a case id of the form YYYYMMDD-HHMMSS-<6 hex>.
func NewID() (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:]), nil
}

// Create makes the case directory tree under base with restrictive modes and
// writes case.json.
func Create(base string, opts Options) (*Case, error) {
	base = filepath.Clean(base)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	id := opts.ID
	if id == "" {
		var err error
		id, err = NewID()
		if err != nil {
			return nil, err
		}
	}
	if !idRe.MatchString(id) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidID, id)
	}

	dir := filepath.Join(base, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	for _, sub := range []string{StreamsDir, CarvedDir, ReportsDir} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}

	c := &Case{Dir: dir, ID: id}
	c.Meta.Version = opts.Version
	if c.Meta.Version == "" {
		c.Meta.Version = version.String()
	}
	c.Meta.PCAP = opts.PCAP
	if opts.Created.IsZero() {
		opts.Created = time.Now()
	}
	c.Meta.Created = opts.Created.UTC()
	c.Meta.Options = opts.Extra
	return c, c.saveMeta()
}

// Open validates that path is a case directory and returns it.
func Open(path string) (*Case, error) {
	path = filepath.Clean(path)
	data, err := os.ReadFile(filepath.Join(path, CaseJSON))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotACase, err)
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: bad %s: %v", ErrNotACase, CaseJSON, err)
	}
	return &Case{Dir: path, ID: filepath.Base(path), Meta: m}, nil
}

// List returns the case directories under base, newest first.
func List(base string) ([]*Case, error) {
	ents, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	var out []*Case
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if c, err := Open(filepath.Join(base, e.Name())); err == nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// Remove deletes the case id under base. Ids are validated so the path can
// never escape base.
func Remove(base, id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	return os.RemoveAll(filepath.Join(filepath.Clean(base), id))
}

func (c *Case) saveMeta() error {
	data, err := json.MarshalIndent(c.Meta, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(c.Path(CaseJSON), data, 0o600)
}

// Path joins elem under the case directory.
func (c *Case) Path(elem ...string) string {
	return filepath.Join(append([]string{c.Dir}, elem...)...)
}

// DB returns the SQLite database path.
func (c *Case) DB() string { return c.Path(DBFile) }

// PktIndex returns the packet index path.
func (c *Case) PktIndex() string { return c.Path(PktIndex) }

// StreamsDir returns the streams directory.
func (c *Case) StreamsDir() string { return c.Path(StreamsDir) }

// StreamPath returns the spool file path for a stream id and direction.
func (c *Case) StreamPath(id int64, dir model.Direction) string {
	return filepath.Join(c.Path(StreamsDir), streamFileName(id, dir))
}

// StreamIndex returns the segment index path for a stream id.
func (c *Case) StreamIndex(id int64) string {
	return filepath.Join(c.Path(StreamsDir), streamIndexName(id))
}

// CarvedDir returns the carved-files directory.
func (c *Case) CarvedDir() string { return c.Path(CarvedDir) }

// CarvedPath returns the path for a carved file named by its SHA-256.
func (c *Case) CarvedPath(sha, ext string) string {
	return filepath.Join(c.Path(CarvedDir), sha+"."+ext)
}

// ReportsDir returns the reports directory.
func (c *Case) ReportsDir() string { return c.Path(ReportsDir) }

func streamFileName(id int64, dir model.Direction) string {
	side := "c2s"
	if dir == model.S2C {
		side = "s2c"
	}
	return "stream_" + strconv.FormatInt(id, 10) + "_" + side + ".bin"
}

func streamIndexName(id int64) string {
	return "stream_" + strconv.FormatInt(id, 10) + ".idx"
}
