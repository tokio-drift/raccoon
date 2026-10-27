package http

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
	"github.com/tokio-drift/raccoon/internal/prototest"
	"github.com/tokio-drift/raccoon/internal/reassembly"
)

const jpegSHA256 = "bae8839289a550db2da10bf79d22866f69dcf378291a9bd41e46c85f40d4f2b5"

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

func newCtx(c2s, s2c string) *proto.StreamContext {
	src := &memStream{}
	src.data[model.C2S] = []byte(c2s)
	src.data[model.S2C] = []byte(s2c)
	if len(c2s) > 0 {
		src.segs[model.C2S] = []reassembly.Segment{{StreamOff: 0, Length: uint32(len(c2s)), TS: 100, PacketNo: 1}}
	}
	if len(s2c) > 0 {
		src.segs[model.S2C] = []reassembly.Segment{{StreamOff: 0, Length: uint32(len(s2c)), TS: 200, PacketNo: 2}}
	}
	return proto.NewStreamContext(proto.StreamMeta{
		ID: 1, Proto: "http",
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 80,
		StartTS: 50, FirstPacket: 1,
	}, src)
}

func chunkedBody(data []byte, size int) []byte {
	var b bytes.Buffer
	for len(data) > 0 {
		n := size
		if n > len(data) {
			n = len(data)
		}
		fmt.Fprintf(&b, "%x\r\n", n)
		b.Write(data[:n])
		b.WriteString("\r\n")
		data = data[n:]
	}
	b.WriteString("0\r\n\r\n")
	return b.Bytes()
}

func gzipData(data []byte) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return b.Bytes()
}

func readFileSource(t *testing.T, f proto.FileSource) []byte {
	t.Helper()
	buf := make([]byte, f.Len)
	if _, err := io.ReadFull(io.NewSectionReader(f.Reader, 0, f.Len), buf); err != nil {
		t.Fatalf("read file source %q: %v", f.Name, err)
	}
	return buf
}

func TestMatch(t *testing.T) {
	a := New()
	if !a.Match([]byte("GET / HTTP/1.1\r\n"), model.C2S, proto.PortPair{Client: 1, Server: 8081}) {
		t.Error("request should match")
	}
	if !a.Match([]byte("HTTP/1.1 200 OK\r\n"), model.S2C, proto.PortPair{Client: 1, Server: 8081}) {
		t.Error("response should match")
	}
	if a.Match([]byte("USER bob\r\n"), model.C2S, proto.PortPair{Client: 1, Server: 21}) {
		t.Error("FTP should not match")
	}
}

func TestSimpleTransaction(t *testing.T) {
	ctx := newCtx(
		"GET /files/report.txt?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-agent\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
	)
	events := run(t, ctx)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Type != model.EvHTTPTx || e.TS != 200 || e.PacketNo != 2 || e.PacketEnd != 2 {
		t.Errorf("event metadata = %+v", e)
	}
	want := map[string]any{
		"method":      "GET",
		"host":        "example.com",
		"url":         "/files/report.txt?x=1",
		"status":      200,
		"userAgent":   "test-agent",
		"contentType": "text/plain",
		"bodyLen":     5,
	}
	for k, v := range want {
		if e.Details[k] != v {
			t.Errorf("details[%q] = %v, want %v", k, e.Details[k], v)
		}
	}

	files := ctx.FileSources()
	if len(files) != 1 {
		t.Fatalf("file sources = %d, want 1", len(files))
	}
	if files[0].Name != "report.txt" || files[0].Dir != model.S2C || files[0].Origin != "http" {
		t.Errorf("file source = %+v", files[0])
	}
	if got := string(readFileSource(t, files[0])); got != "hello" {
		t.Errorf("file body = %q, want hello", got)
	}
}

func TestKeepAlivePipelining(t *testing.T) {
	ctx := newCtx(
		"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"+
			"POST /b HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nxyz",
		"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"+
			"HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nB",
	)
	events := run(t, ctx)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0].Details["method"] != "GET" || events[0].Details["url"] != "/a" || events[0].Details["status"] != 200 {
		t.Errorf("first event = %+v", events[0].Details)
	}
	if events[1].Details["method"] != "POST" || events[1].Details["url"] != "/b" || events[1].Details["status"] != 201 {
		t.Errorf("second event = %+v", events[1].Details)
	}
	files := ctx.FileSources()
	if len(files) != 2 || files[0].Name != "a" || files[1].Name != "b" {
		t.Fatalf("file sources = %+v", files)
	}
}

func TestHeadResponseHasNoBody(t *testing.T) {
	ctx := newCtx(
		"HEAD /h HTTP/1.1\r\nHost: example.com\r\n\r\n"+
			"GET /g HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"+
			"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody",
	)
	events := run(t, ctx)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0].Details["method"] != "HEAD" || events[0].Details["bodyLen"] != 0 {
		t.Errorf("HEAD event = %+v", events[0].Details)
	}
	if events[1].Details["method"] != "GET" || events[1].Details["bodyLen"] != 4 {
		t.Errorf("GET event = %+v", events[1].Details)
	}
	files := ctx.FileSources()
	if len(files) != 1 || files[0].Name != "g" {
		t.Fatalf("file sources = %+v", files)
	}
}

func TestChunkedGzipBasicAuthAndFilename(t *testing.T) {
	payload := []byte("secret file contents")
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Encoding: gzip\r\n" +
		"Content-Disposition: attachment; filename=\"payload.bin\"\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" +
		string(chunkedBody(gzipData(payload), 7))
	ctx := newCtx(
		"GET /download HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWxpY2U6czNjcjN0\r\n\r\n",
		response,
	)
	events := run(t, ctx)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Details["filename"] != "payload.bin" || e.Details["bodyLen"] != len(payload) {
		t.Errorf("details = %+v", e.Details)
	}
	if e.Details["authUser"] != "alice" || e.Details["password"] != "s3cr3t" || e.Details["passwordPresent"] != true {
		t.Errorf("auth details = %+v", e.Details)
	}
	if e.Severity != model.SevWarning {
		t.Errorf("cleartext basic auth severity = %q, want warning", e.Severity)
	}
	files := ctx.FileSources()
	if len(files) != 1 || files[0].Name != "payload.bin" {
		t.Fatalf("file sources = %+v", files)
	}
	if got := readFileSource(t, files[0]); !bytes.Equal(got, payload) {
		t.Errorf("decoded body = %q, want %q", got, payload)
	}
}

func TestContinueResponseIsNotPaired(t *testing.T) {
	ctx := newCtx(
		"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc",
		"HTTP/1.1 100 Continue\r\n\r\n"+
			"HTTP/1.1 204 No Content\r\n\r\n",
	)
	events := run(t, ctx)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Details["status"] != 204 {
		t.Errorf("status = %v, want 204", events[0].Details["status"])
	}
}

func TestMalformedInputStopsWithoutError(t *testing.T) {
	ctx := newCtx("not a request\r\n\r\n", "garbage\r\n\r\n")
	events := run(t, ctx)
	if len(events) != 0 {
		t.Fatalf("events = %d, want 0", len(events))
	}
}

func TestChunkedJPEGFixture(t *testing.T) {
	capture := prototest.ReassembleForAnalyzers(t, "http_get_jpeg_chunked.pcap")
	var stream *prototest.AnalyzerStream
	for _, s := range capture.Streams {
		if s.Context.DstPort == 8080 {
			stream = s
			break
		}
	}
	if stream == nil {
		t.Fatal("no stream to port 8080")
	}
	events := run(t, stream.Context)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Details["method"] != "GET" || e.Details["url"] != "/img.jpg" || e.Details["status"] != 200 {
		t.Errorf("event details = %+v", e.Details)
	}
	if e.Details["contentType"] != "image/jpeg" {
		t.Errorf("content-type = %v", e.Details["contentType"])
	}
	files := stream.Context.FileSources()
	if len(files) != 1 {
		t.Fatalf("file sources = %d, want 1", len(files))
	}
	body := readFileSource(t, files[0])
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != jpegSHA256 {
		t.Errorf("decoded body sha256 = %s, want %s", got, jpegSHA256)
	}
	if e.Details["bodyLen"] != len(body) {
		t.Errorf("bodyLen = %v, want %d", e.Details["bodyLen"], len(body))
	}
}

func TestHTTPGzipBombCapped(t *testing.T) {
	// Construct a gzip bomb: 110 MB of zero bytes compressed into a few KB.
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zeroBlock := make([]byte, 1024*1024) // 1 MB block
	for i := 0; i < 110; i++ {
		if _, err := zw.Write(zeroBlock); err != nil {
			t.Fatalf("write zero block: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	compressed := b.Bytes()

	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s",
		len(compressed), string(compressed))
	ctx := newCtx("GET /bomb HTTP/1.1\r\nHost: example.com\r\n\r\n", response)
	run(t, ctx)

	files := ctx.FileSources()
	if len(files) != 1 {
		t.Fatalf("file sources = %d, want 1", len(files))
	}
	if files[0].Len > limits.MaxGzipBody {
		t.Fatalf("file source length %d exceeded limits.MaxGzipBody (%d)", files[0].Len, limits.MaxGzipBody)
	}
	if files[0].Len != limits.MaxGzipBody {
		t.Fatalf("file source length = %d, want capped at %d", files[0].Len, limits.MaxGzipBody)
	}
}
