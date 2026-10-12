package reassembly

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/tokio-drift/raccoon/internal/model"
)

// Segment is one contiguous run of bytes delivered for a stream direction.
type Segment struct {
	Dir       model.Direction
	StreamOff int64
	Length    uint32
	TS        int64
	PacketNo  uint64
}

// Gap is a hole in a stream direction where Length bytes were never captured.
type Gap struct {
	Offset int64
	Length int64
}

// StreamData provides random access to reassembled stream bytes, segments and
// gaps. It is implemented by Spool.
type StreamData interface {
	ReaderAt(dir model.Direction) io.ReaderAt
	Len(dir model.Direction) int64
	Segments(dir model.Direction) []Segment
	Gaps(dir model.Direction) []Gap
}

// indexRecordSize is the on-disk size of one segment index record.
const indexRecordSize = 29

// SegmentIndex appends fixed-size segment records to an .idx stream and retains
// the same information in memory for the API.
type SegmentIndex struct {
	w    io.Writer
	buf  [indexRecordSize]byte
	segs []Segment
	gaps [2][]Gap
}

// NewSegmentIndex returns an index writing records to w.
func NewSegmentIndex(w io.Writer) *SegmentIndex { return &SegmentIndex{w: w} }

// Add records one segment.
func (x *SegmentIndex) Add(seg Segment) error {
	x.segs = append(x.segs, seg)
	if x.w == nil {
		return nil
	}
	x.buf[0] = byte(seg.Dir)
	binary.LittleEndian.PutUint64(x.buf[1:9], uint64(seg.StreamOff))
	binary.LittleEndian.PutUint32(x.buf[9:13], seg.Length)
	binary.LittleEndian.PutUint64(x.buf[13:21], uint64(seg.TS))
	binary.LittleEndian.PutUint64(x.buf[21:29], seg.PacketNo)
	_, err := x.w.Write(x.buf[:])
	return err
}

// AddGap records one gap in memory.
func (x *SegmentIndex) AddGap(dir model.Direction, g Gap) { x.gaps[dir] = append(x.gaps[dir], g) }

// Segments returns all segments for a direction.
func (x *SegmentIndex) Segments(dir model.Direction) []Segment {
	var out []Segment
	for _, s := range x.segs {
		if s.Dir == dir {
			out = append(out, s)
		}
	}
	return out
}

// Gaps returns all gaps for a direction.
func (x *SegmentIndex) Gaps(dir model.Direction) []Gap {
	return x.gaps[dir]
}

const spillThreshold = 1 << 20

// dirSpool buffers one stream direction in memory, spilling to a file once it
// exceeds spillThreshold.
type dirSpool struct {
	path   string
	mem    []byte
	file   *os.File
	bw     *bufio.Writer
	size   int64
	memory bool
}

func newDirSpool(path string) *dirSpool {
	return &dirSpool{path: path, memory: true}
}

func (d *dirSpool) Write(p []byte) (int, error) {
	if d.memory && d.size+int64(len(p)) > spillThreshold {
		if err := d.spill(); err != nil {
			return 0, err
		}
	}
	var n int
	var err error
	if d.memory {
		d.mem = append(d.mem, p...)
		n = len(p)
	} else {
		n, err = d.bw.Write(p)
	}
	d.size += int64(n)
	return n, err
}

func (d *dirSpool) spill() error {
	f, err := os.OpenFile(d.path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	d.file = f
	d.bw = bufio.NewWriterSize(f, 64*1024)
	if _, err := d.bw.Write(d.mem); err != nil {
		return err
	}
	d.mem = nil
	d.memory = false
	return nil
}

func (d *dirSpool) finalize() error {
	if d.bw != nil {
		return d.bw.Flush()
	}
	return nil
}

func (d *dirSpool) readerAt() io.ReaderAt {
	if d.memory {
		return bytes.NewReader(d.mem)
	}
	return d.file
}

func (d *dirSpool) close() error {
	if d.file != nil {
		return d.file.Close()
	}
	return nil
}

// Spool owns the per-stream byte files and the segment index.
type Spool struct {
	id      int64
	dirs    [2]*dirSpool
	index   *SegmentIndex
	idxFile *os.File
}

// NewSpool creates the spool files for stream id under dir. Files are created
// with mode 0600.
func NewSpool(dir string, id int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{id: id}
	s.dirs[0] = newDirSpool(filepath.Join(dir, streamFileName(id, model.C2S)))
	s.dirs[1] = newDirSpool(filepath.Join(dir, streamFileName(id, model.S2C)))

	idxPath := filepath.Join(dir, streamIndexName(id))
	f, err := os.OpenFile(idxPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	s.idxFile = f
	s.index = NewSegmentIndex(bufio.NewWriterSize(f, 64*1024))
	return s, nil
}

// ID returns the stream id.
func (s *Spool) ID() int64 { return s.id }

// Index returns the segment index.
func (s *Spool) Index() *SegmentIndex { return s.index }

// Writer returns the buffered byte writer for a direction.
func (s *Spool) Writer(dir model.Direction) io.Writer { return s.dirs[dir] }

// ReaderAt returns a reader over the delivered bytes for a direction. It is
// valid after Finalize.
func (s *Spool) ReaderAt(dir model.Direction) io.ReaderAt { return s.dirs[dir].readerAt() }

// Len returns the number of delivered bytes for a direction.
func (s *Spool) Len(dir model.Direction) int64 { return s.dirs[dir].size }

// Segments returns the segments for a direction.
func (s *Spool) Segments(dir model.Direction) []Segment { return s.index.Segments(dir) }

// Gaps returns the gaps for a direction.
func (s *Spool) Gaps(dir model.Direction) []Gap { return s.index.Gaps(dir) }

// Finalize flushes all buffered writers so that StreamData readers observe all
// bytes.
func (s *Spool) Finalize() error {
	for _, d := range s.dirs {
		if err := d.finalize(); err != nil {
			return err
		}
	}
	if bw, ok := s.index.w.(*bufio.Writer); ok {
		if err := bw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes and closes the spool files. StreamData must not be used after
// Close.
func (s *Spool) Close() error {
	err := s.Finalize()
	for _, d := range s.dirs {
		if cerr := d.close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	if s.idxFile != nil {
		if cerr := s.idxFile.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

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
