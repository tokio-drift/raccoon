package proto

import (
	"bytes"
	"io"
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/reassembly"
)

type memSource struct {
	data [2][]byte
	segs [2][]reassembly.Segment
}

func (m *memSource) ReaderAt(dir model.Direction) io.ReaderAt {
	return bytes.NewReader(m.data[dir])
}

func (m *memSource) Len(dir model.Direction) int64 { return int64(len(m.data[dir])) }

func (m *memSource) Segments(dir model.Direction) []reassembly.Segment { return m.segs[dir] }

func TestStreamContextOffsets(t *testing.T) {
	src := &memSource{}
	src.data[model.C2S] = []byte("0123456789abcdef")
	src.segs[model.C2S] = []reassembly.Segment{
		{Dir: model.C2S, StreamOff: 0, Length: 4, TS: 100, PacketNo: 1},
		{Dir: model.C2S, StreamOff: 8, Length: 8, TS: 300, PacketNo: 3},
	}
	ctx := NewStreamContext(StreamMeta{StartTS: 50, FirstPacket: 9}, src)

	tests := []struct {
		off    int64
		ts     int64
		packet uint64
	}{
		{0, 100, 1},
		{3, 100, 1},
		{4, 100, 1}, // hole after the first segment
		{7, 100, 1}, // hole before the second segment
		{8, 300, 3},
		{15, 300, 3},
		{16, 300, 3}, // past the end
	}
	for _, tt := range tests {
		if got := ctx.TimeAtOffset(model.C2S, tt.off); got != tt.ts {
			t.Errorf("TimeAtOffset(%d) = %d, want %d", tt.off, got, tt.ts)
		}
		if got := ctx.PacketAtOffset(model.C2S, tt.off); got != tt.packet {
			t.Errorf("PacketAtOffset(%d) = %d, want %d", tt.off, got, tt.packet)
		}
	}

	if got := ctx.TimeAtOffset(model.S2C, 0); got != 50 {
		t.Errorf("empty direction TimeAtOffset = %d, want start time 50", got)
	}
	if got := ctx.PacketAtOffset(model.S2C, 0); got != 9 {
		t.Errorf("empty direction PacketAtOffset = %d, want first packet 9", got)
	}
}

func TestStreamContextSegmentsSorted(t *testing.T) {
	src := &memSource{}
	src.segs[model.C2S] = []reassembly.Segment{
		{StreamOff: 10, Length: 1, TS: 2},
		{StreamOff: 0, Length: 5, TS: 1},
	}
	ctx := NewStreamContext(StreamMeta{}, src)
	segs := ctx.Segments(model.C2S)
	if len(segs) != 2 || segs[0].StreamOff != 0 || segs[1].StreamOff != 10 {
		t.Fatalf("segments not sorted: %+v", segs)
	}
}

func TestStreamContextEmitFillsMetadata(t *testing.T) {
	meta := StreamMeta{
		ID:          7,
		Proto:       "ftp",
		SrcIP:       "10.0.0.1",
		DstIP:       "10.0.0.2",
		SrcPort:     50000,
		DstPort:     21,
		StartTS:     100,
		FirstPacket: 3,
	}
	ctx := NewStreamContext(meta, nil)

	ctx.Emit(model.Event{Type: model.EvFTPCommand, Title: "empty"})
	e := ctx.Events()[0]
	if e.TS != 100 || e.PacketNo != 3 || e.PacketEnd != 3 {
		t.Errorf("packet metadata = (%d,%d,%d), want (100,3,3)", e.TS, e.PacketNo, e.PacketEnd)
	}
	if e.StreamID != 7 || e.Src != "10.0.0.1:50000" || e.Dst != "10.0.0.2:21" || e.Proto != "ftp" {
		t.Errorf("stream metadata not filled: %+v", e)
	}

	ctx.Emit(model.Event{TS: 200, PacketNo: 9, PacketEnd: 11, Src: "x", Dst: "y", Proto: "z", StreamID: 4})
	e = ctx.Events()[1]
	if e.TS != 200 || e.PacketNo != 9 || e.PacketEnd != 11 || e.Src != "x" || e.Dst != "y" || e.Proto != "z" || e.StreamID != 4 {
		t.Errorf("explicit metadata overwritten: %+v", e)
	}
}

func TestStreamContextFileSources(t *testing.T) {
	ctx := NewStreamContext(StreamMeta{}, nil)
	body := []byte("hello")
	ctx.EmitFileSource(FileSource{Name: "a.txt", Reader: bytes.NewReader(body), Len: int64(len(body)), Dir: model.S2C, Origin: "http"})
	files := ctx.FileSources()
	if len(files) != 1 || files[0].Name != "a.txt" || files[0].Len != 5 {
		t.Fatalf("file sources = %+v", files)
	}
	got := make([]byte, files[0].Len)
	if _, err := files[0].Reader.ReadAt(got, 0); err != nil {
		t.Fatalf("read file source: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("file source body = %q", got)
	}
	ctx.Reset()
	if len(ctx.Events()) != 0 || len(ctx.FileSources()) != 0 {
		t.Fatal("Reset did not clear events and files")
	}
}

func TestDatagramContext(t *testing.T) {
	ds := []Datagram{{TS: 1, PacketNo: 2, Dir: model.C2S, Payload: []byte("q")}}
	ctx := NewDatagramContext(StreamMeta{ID: 3, Proto: "dns"}, ds)
	if len(ctx.Datagrams()) != 1 || string(ctx.Datagrams()[0].Payload) != "q" {
		t.Fatalf("datagrams = %+v", ctx.Datagrams())
	}
	if ctx.Len(model.C2S) != 0 {
		t.Fatal("datagram context should have no stream bytes")
	}
}

type stubAnalyzer struct {
	name  string
	match func([]byte, model.Direction) bool
}

func (s stubAnalyzer) Name() string { return s.name }
func (s stubAnalyzer) Match(first []byte, dir model.Direction, _ PortPair) bool {
	return s.match(first, dir)
}
func (s stubAnalyzer) Analyze(*StreamContext, func(model.Event)) error { return nil }

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	a := stubAnalyzer{name: "a", match: func([]byte, model.Direction) bool { return false }}
	b := stubAnalyzer{name: "b", match: func(first []byte, _ model.Direction) bool {
		return bytes.HasPrefix(first, []byte("b:"))
	}}
	r.Register(a)
	r.Register(b)

	if got := len(r.All()); got != 2 {
		t.Fatalf("All len = %d, want 2", got)
	}
	if got := r.Find(nil, []byte("b:hi"), PortPair{}); got == nil || got.Name() != "b" {
		t.Fatalf("Find = %v, want b", got)
	}
	if got := r.Find([]byte("a:hi"), nil, PortPair{}); got != nil {
		t.Fatalf("Find = %v, want nil", got)
	}
}
