package proto

import (
	"bytes"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/reassembly"
)

// Analyzer parses one identified protocol and emits semantic events.
type Analyzer interface {
	// Name returns the protocol name, matching the stream's Proto column.
	Name() string
	// Match reports whether first looks like this protocol's first bytes in dir.
	Match(first []byte, dir model.Direction, ports PortPair) bool
	// Analyze inspects the stream and calls emit for every discovered event.
	Analyze(ctx *StreamContext, emit func(model.Event)) error
}

// StreamMeta is the stream metadata available to analyzers.
type StreamMeta struct {
	ID          int64
	Proto       string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	StartTS     int64
	EndTS       int64
	FirstPacket uint64
	LastPacket  uint64
}

// StreamSource is the subset of reassembly.Stream analyzers need.
type StreamSource interface {
	ReaderAt(dir model.Direction) io.ReaderAt
	Len(dir model.Direction) int64
	Segments(dir model.Direction) []reassembly.Segment
}

// Datagram is one captured UDP payload. UDP flows are not reassembled, so
// analyzers receive their payloads as datagrams instead of a byte stream.
type Datagram struct {
	TS       int64
	PacketNo uint64
	Dir      model.Direction
	Payload  []byte
}

// FileSource is a decoded file body an analyzer hands to the carver.
type FileSource struct {
	Name   string
	Reader io.ReaderAt
	Len    int64
	Dir    model.Direction
	Origin string
}

// StreamContext gives an analyzer access to a stream and its metadata, and
// collects the events and file sources it produces.
type StreamContext struct {
	StreamMeta
	src       StreamSource
	segments  [2][]reassembly.Segment
	datagrams []Datagram
	events    []model.Event
	files     []FileSource
}

// NewStreamContext builds a context for one reassembled TCP stream. src may be
// nil for tests that only emit events.
func NewStreamContext(meta StreamMeta, src StreamSource) *StreamContext {
	c := &StreamContext{StreamMeta: meta, src: src}
	if src != nil {
		for _, dir := range [2]model.Direction{model.C2S, model.S2C} {
			segs := append([]reassembly.Segment(nil), src.Segments(dir)...)
			sort.Slice(segs, func(i, j int) bool { return segs[i].StreamOff < segs[j].StreamOff })
			c.segments[dir] = segs
		}
	}
	return c
}

// NewDatagramContext builds a context for a UDP flow from its datagrams.
func NewDatagramContext(meta StreamMeta, datagrams []Datagram) *StreamContext {
	ds := append([]Datagram(nil), datagrams...)
	return &StreamContext{StreamMeta: meta, datagrams: ds}
}

// Src returns the initiator endpoint as "ip:port".
func (c *StreamContext) Src() string {
	return net.JoinHostPort(c.SrcIP, strconv.Itoa(int(c.SrcPort)))
}

// Dst returns the responder endpoint as "ip:port".
func (c *StreamContext) Dst() string {
	return net.JoinHostPort(c.DstIP, strconv.Itoa(int(c.DstPort)))
}

// ReaderAt returns a reader over delivered bytes for a direction. A context
// without a source yields an empty reader.
func (c *StreamContext) ReaderAt(dir model.Direction) io.ReaderAt {
	if c.src == nil {
		return bytes.NewReader(nil)
	}
	return c.src.ReaderAt(dir)
}

// Len returns the number of delivered bytes for a direction.
func (c *StreamContext) Len(dir model.Direction) int64 {
	if c.src == nil {
		return 0
	}
	return c.src.Len(dir)
}

// Segments returns the delivered segments for a direction, sorted by offset.
func (c *StreamContext) Segments(dir model.Direction) []reassembly.Segment {
	return c.segments[dir]
}

// Datagrams returns the UDP payloads of this flow in capture order.
func (c *StreamContext) Datagrams() []Datagram { return c.datagrams }

// TimeAtOffset returns the capture timestamp of the bytes at off: the segment
// that delivered them, or the last segment starting before off when off falls
// in a hole. It falls back to the stream start time.
func (c *StreamContext) TimeAtOffset(dir model.Direction, off int64) int64 {
	if seg, ok := c.segmentAt(dir, off); ok {
		return seg.TS
	}
	return c.StartTS
}

// PacketAtOffset returns the packet number of the bytes at off, analogous to
// TimeAtOffset.
func (c *StreamContext) PacketAtOffset(dir model.Direction, off int64) uint64 {
	if seg, ok := c.segmentAt(dir, off); ok {
		return seg.PacketNo
	}
	return c.FirstPacket
}

func (c *StreamContext) segmentAt(dir model.Direction, off int64) (reassembly.Segment, bool) {
	segs := c.segments[dir]
	i := sort.Search(len(segs), func(i int) bool {
		return segs[i].StreamOff+int64(segs[i].Length) > off
	})
	if i < len(segs) {
		if off >= segs[i].StreamOff {
			return segs[i], true
		}
		if i > 0 {
			return segs[i-1], true
		}
		return reassembly.Segment{}, false
	}
	if len(segs) > 0 {
		return segs[len(segs)-1], true
	}
	return reassembly.Segment{}, false
}

// NewEvent builds an event with the context's stream metadata filled in.
func (c *StreamContext) NewEvent(ts int64, packetNo uint64, typ model.EventType, sev model.Severity, title string, details map[string]any) model.Event {
	e := model.Event{
		TS:        ts,
		PacketNo:  packetNo,
		PacketEnd: packetNo,
		Type:      typ,
		Severity:  sev,
		StreamID:  c.ID,
		Src:       c.Src(),
		Dst:       c.Dst(),
		Proto:     c.Proto,
		Title:     title,
		Details:   details,
	}
	c.fill(&e)
	return e
}

// Emit records an event, filling any missing stream metadata.
func (c *StreamContext) Emit(e model.Event) {
	c.fill(&e)
	c.events = append(c.events, e)
}

// Events returns the events emitted so far.
func (c *StreamContext) Events() []model.Event { return c.events }

// Reset discards all emitted events and file sources.
func (c *StreamContext) Reset() {
	c.events = nil
	c.files = nil
}

// EmitFileSource records a decoded body for the carver.
func (c *StreamContext) EmitFileSource(f FileSource) {
	c.files = append(c.files, f)
}

// FileSources returns the file bodies emitted so far.
func (c *StreamContext) FileSources() []FileSource { return c.files }

func (c *StreamContext) fill(e *model.Event) {
	if e.TS == 0 {
		e.TS = c.StartTS
	}
	if e.PacketNo == 0 {
		e.PacketNo = c.FirstPacket
	}
	if e.PacketEnd == 0 {
		e.PacketEnd = e.PacketNo
	}
	if e.StreamID == 0 {
		e.StreamID = c.ID
	}
	if e.Src == "" {
		e.Src = c.Src()
	}
	if e.Dst == "" {
		e.Dst = c.Dst()
	}
	if e.Proto == "" {
		e.Proto = c.Proto
	}
}

// Registry holds the analyzers available to the pipeline. Registration order
// is matching priority.
type Registry struct {
	mu        sync.RWMutex
	analyzers []Analyzer
}

// NewRegistry returns an empty analyzer registry.
func NewRegistry() *Registry { return &Registry{} }

// Register appends an analyzer to the registry.
func (r *Registry) Register(a Analyzer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.analyzers = append(r.analyzers, a)
}

// All returns the registered analyzers in priority order.
func (r *Registry) All() []Analyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Analyzer(nil), r.analyzers...)
}

// Find returns the first analyzer whose Match accepts either direction.
func (r *Registry) Find(firstC2S, firstS2C []byte, ports PortPair) Analyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.analyzers {
		if a.Match(firstC2S, model.C2S, ports) || a.Match(firstS2C, model.S2C, ports) {
			return a
		}
	}
	return nil
}

// Default is the package-level registry. Analyzers are registered explicitly
// by the caller to keep this package free of import cycles.
var Default = NewRegistry()

// Register adds an analyzer to Default.
func Register(a Analyzer) { Default.Register(a) }

// Analyzers returns the analyzers registered in Default.
func Analyzers() []Analyzer { return Default.All() }
