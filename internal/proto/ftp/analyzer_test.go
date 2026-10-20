package ftp

import (
	"bytes"
	"io"
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
	"github.com/tokio-drift/raccoon/internal/prototest"
	"github.com/tokio-drift/raccoon/internal/reassembly"
)

type memStream struct {
	data [2][]byte
	segs [2][]reassembly.Segment
}

func (m *memStream) ReaderAt(dir model.Direction) io.ReaderAt {
	return bytes.NewReader(m.data[dir])
}
func (m *memStream) Len(dir model.Direction) int64 { return int64(len(m.data[dir])) }
func (m *memStream) Segments(dir model.Direction) []reassembly.Segment {
	return m.segs[dir]
}

func run(t *testing.T, ctx *proto.StreamContext) []model.Event {
	t.Helper()
	var events []model.Event
	if err := New().Analyze(ctx, func(e model.Event) { events = append(events, e) }); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return events
}

func count(events []model.Event, typ model.EventType) int {
	n := 0
	for _, e := range events {
		if e.Type == typ {
			n++
		}
	}
	return n
}

func TestMatch(t *testing.T) {
	a := New()
	if !a.Match([]byte("220 ready\r\n"), model.S2C, proto.PortPair{Client: 50000, Server: 2121}) {
		t.Error("server greeting should match")
	}
	if !a.Match([]byte("USER bob\r\n"), model.C2S, proto.PortPair{Client: 50000, Server: 21}) {
		t.Error("USER should match")
	}
	if a.Match([]byte("GET / HTTP/1.1\r\n"), model.C2S, proto.PortPair{Client: 50000, Server: 80}) {
		t.Error("HTTP should not match")
	}
}

func TestAnalyzeLoginAndCommands(t *testing.T) {
	src := &memStream{}
	src.data[model.C2S] = []byte("USER bob\r\nPASS s3cr3t\r\nPWD\r\nSTOR secret.png\r\nQUIT\r\n")
	src.data[model.S2C] = []byte("220 ready\r\n331 Password required\r\n230 Logged in\r\n257 \"/\"\r\n150 Send data\r\n221 Bye\r\n")
	src.segs[model.C2S] = []reassembly.Segment{{StreamOff: 0, Length: uint32(len(src.data[model.C2S])), TS: 100, PacketNo: 5}}
	src.segs[model.S2C] = []reassembly.Segment{{StreamOff: 0, Length: uint32(len(src.data[model.S2C])), TS: 200, PacketNo: 6}}

	ctx := proto.NewStreamContext(proto.StreamMeta{ID: 3, Proto: "ftp", StartTS: 1, FirstPacket: 1}, src)
	events := run(t, ctx)

	if got := count(events, model.EvFTPLoginTry); got != 1 {
		t.Errorf("login attempts = %d, want 1", got)
	}
	if got := count(events, model.EvFTPLoginOK); got != 1 {
		t.Errorf("login successes = %d, want 1", got)
	}
	if got := count(events, model.EvFTPLoginFail); got != 0 {
		t.Errorf("login failures = %d, want 0", got)
	}
	if got := count(events, model.EvFTPCommand); got != 3 {
		t.Errorf("commands = %d, want 3 (PWD, STOR, QUIT)", got)
	}

	var ok model.Event
	var stor model.Event
	for _, e := range events {
		switch e.Type {
		case model.EvFTPLoginOK:
			ok = e
		case model.EvFTPCommand:
			if e.Details["command"] == "STOR" {
				stor = e
			}
		}
	}
	if ok.TS != 200 || ok.PacketNo != 6 {
		t.Errorf("login success at (%d,%d), want server reply (200,6)", ok.TS, ok.PacketNo)
	}
	if ok.Details["user"] != "bob" || ok.Details["passwordPresent"] != true || ok.Details["password"] != "s3cr3t" {
		t.Errorf("login credentials = %+v", ok.Details)
	}
	if ok.Severity != model.SevWarning {
		t.Errorf("login with cleartext password severity = %q, want warning", ok.Severity)
	}
	if stor.Details["command"] != "STOR" || stor.Details["filename"] != "secret.png" || stor.Details["arg"] != "secret.png" {
		t.Errorf("STOR details = %+v", stor.Details)
	}
	if events[len(events)-1].PacketNo != 6 {
		t.Errorf("last event packet = %d, want server packet 6", events[len(events)-1].PacketNo)
	}
}

// lineSegments splits data into one segment per line with the given
// timestamps, so tests can interleave the two directions realistically.
func lineSegments(data []byte, times []int64, packetBase uint64) []reassembly.Segment {
	var segs []reassembly.Segment
	off := 0
	for i := 0; off < len(data); i++ {
		n := len(data) - off
		if j := bytes.IndexByte(data[off:], '\n'); j >= 0 {
			n = j + 1
		}
		segs = append(segs, reassembly.Segment{
			StreamOff: int64(off),
			Length:    uint32(n),
			TS:        times[i],
			PacketNo:  packetBase + uint64(i),
		})
		off += n
	}
	return segs
}

func TestAnalyzeFailureAndReset(t *testing.T) {
	src := &memStream{}
	src.data[model.C2S] = []byte("USER alice\r\nPASS nope\r\nUSER bob\r\nPASS s3cr3t\r\n")
	src.data[model.S2C] = []byte("220 ready\r\n331 need pass\r\n530 denied\r\n331 need pass\r\n230 ok\r\n")
	src.segs[model.C2S] = lineSegments(src.data[model.C2S], []int64{10, 30, 50, 70}, 1)
	src.segs[model.S2C] = lineSegments(src.data[model.S2C], []int64{5, 20, 40, 60, 80}, 100)

	ctx := proto.NewStreamContext(proto.StreamMeta{ID: 4, Proto: "ftp", StartTS: 1, FirstPacket: 1}, src)
	events := run(t, ctx)
	if got := count(events, model.EvFTPLoginFail); got != 1 {
		t.Fatalf("login failures = %d, want 1", got)
	}
	if got := count(events, model.EvFTPLoginOK); got != 1 {
		t.Fatalf("login successes = %d, want 1", got)
	}
	for _, e := range events {
		if e.Type == model.EvFTPLoginOK && e.Details["user"] != "bob" {
			t.Errorf("success user = %v, want bob", e.Details["user"])
		}
		if e.Type == model.EvFTPLoginFail && e.Details["user"] != "alice" {
			t.Errorf("failure user = %v, want alice", e.Details["user"])
		}
	}
}

func TestPartialLinesAcrossSegments(t *testing.T) {
	src := &memStream{}
	src.data[model.C2S] = []byte("USER bob\r\nPASS s3cr3t\r\n")
	src.data[model.S2C] = []byte("220 ready\r\n230 Logged in\r\n")
	src.segs[model.C2S] = []reassembly.Segment{
		{StreamOff: 0, Length: 7, TS: 10, PacketNo: 1},
		{StreamOff: 7, Length: uint32(len(src.data[model.C2S]) - 7), TS: 11, PacketNo: 2},
	}
	src.segs[model.S2C] = []reassembly.Segment{{StreamOff: 0, Length: uint32(len(src.data[model.S2C])), TS: 20, PacketNo: 3}}

	ctx := proto.NewStreamContext(proto.StreamMeta{ID: 5, Proto: "ftp", StartTS: 1, FirstPacket: 1}, src)
	events := run(t, ctx)
	if got := count(events, model.EvFTPLoginTry); got != 1 {
		t.Fatalf("login attempts = %d, want 1", got)
	}
	if got := count(events, model.EvFTPLoginOK); got != 1 {
		t.Fatalf("login successes = %d, want 1", got)
	}
}

func TestOverlongLineDropped(t *testing.T) {
	src := &memStream{}
	long := make([]byte, maxLineLen+100)
	for i := range long {
		long[i] = 'A'
	}
	src.data[model.C2S] = append(append(append([]byte(nil), long...), '\n'), []byte("USER bob\r\n")...)
	src.segs[model.C2S] = []reassembly.Segment{{StreamOff: 0, Length: uint32(len(src.data[model.C2S])), TS: 10, PacketNo: 1}}

	ctx := proto.NewStreamContext(proto.StreamMeta{ID: 6, Proto: "ftp", StartTS: 1, FirstPacket: 1}, src)
	events := run(t, ctx)
	if got := count(events, model.EvFTPLoginTry); got != 1 {
		t.Fatalf("login attempts = %d, want 1 after dropping the overlong line", got)
	}
}

func TestBruteforceFixture(t *testing.T) {
	capture := prototest.ReassembleForAnalyzers(t, "ftp_bruteforce.pcap")
	stream := findStream(t, capture, 21)
	events := run(t, stream.Context)
	if got := count(events, model.EvFTPLoginFail); got != 40 {
		t.Errorf("FTP_LOGIN_FAILED = %d, want 40", got)
	}
	if got := count(events, model.EvFTPLoginOK); got != 1 {
		t.Errorf("FTP_LOGIN_SUCCESS = %d, want 1", got)
	}
	if got := count(events, model.EvFTPLoginTry); got != 41 {
		t.Errorf("FTP_LOGIN_ATTEMPT = %d, want 41", got)
	}
}

func TestUploadFixture(t *testing.T) {
	capture := prototest.ReassembleForAnalyzers(t, "ftp_upload_png.pcap")
	control := findStream(t, capture, 21)
	events := run(t, control.Context)

	if got := count(events, model.EvFTPLoginOK); got != 1 {
		t.Fatalf("FTP_LOGIN_SUCCESS = %d, want 1", got)
	}
	var stor model.Event
	for _, e := range events {
		if e.Type == model.EvFTPLoginOK {
			if e.Details["user"] != "bob" || e.Details["password"] != "s3cr3t" || e.Details["passwordPresent"] != true {
				t.Errorf("login credentials = %+v", e.Details)
			}
		}
		if e.Type == model.EvFTPCommand && e.Details["command"] == "STOR" {
			stor = e
		}
	}
	if stor.Type == "" {
		t.Fatal("missing STOR command event")
	}
	if stor.Details["filename"] != "secret.png" {
		t.Errorf("STOR filename = %v, want secret.png", stor.Details["filename"])
	}
	if stor.TS == 0 || stor.TS > control.Flow.EndTS {
		t.Errorf("STOR timestamp %d outside stream interval", stor.TS)
	}
}

func findStream(t *testing.T, capture *prototest.AnalyzerCapture, dstPort uint16) *prototest.AnalyzerStream {
	t.Helper()
	for _, s := range capture.Streams {
		if s.Context.DstPort == dstPort {
			return s
		}
	}
	t.Fatalf("no stream with destination port %d", dstPort)
	return nil
}
