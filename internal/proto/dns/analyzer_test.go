package dns

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

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

func encode(t *testing.T, d *layers.DNS) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, d); err != nil {
		t.Fatalf("serialize dns: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func queryPacket(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	return encode(t, &layers.DNS{
		ID:        id,
		OpCode:    layers.DNSOpCodeQuery,
		RD:        true,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
	})
}

func responsePacket(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	return encode(t, &layers.DNS{
		ID:        id,
		QR:        true,
		RA:        true,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		Answers: []layers.DNSResourceRecord{{
			Name:  []byte(name),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			TTL:   300,
			IP:    net.IPv4(93, 184, 216, 34),
		}},
	})
}

func udpContext(datagrams []proto.Datagram) *proto.StreamContext {
	return proto.NewDatagramContext(proto.StreamMeta{
		ID: 1, Proto: "dns",
		SrcIP: "10.0.0.5", DstIP: "10.0.0.6", SrcPort: 53000, DstPort: 53,
	}, datagrams)
}

func TestMatch(t *testing.T) {
	a := New()
	ports := proto.PortPair{Client: 53000, Server: 53}
	if !a.Match(queryPacket(t, 1, "example.com"), model.C2S, ports) {
		t.Error("UDP payload should match")
	}
	r := responsePacket(t, 1, "example.com")
	framed := make([]byte, 2+len(r))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(r)))
	copy(framed[2:], r)
	if !a.Match(framed, model.S2C, ports) {
		t.Error("TCP framed message should match")
	}
	if a.Match(queryPacket(t, 1, "example.com"), model.C2S, proto.PortPair{Client: 53000, Server: 5353}) {
		t.Error("non-53 port should not match")
	}
}

func TestAnalyzeUDP(t *testing.T) {
	ctx := udpContext([]proto.Datagram{
		{TS: 100, PacketNo: 1, Dir: model.C2S, Payload: queryPacket(t, 1, "example.com")},
		{TS: 110, PacketNo: 2, Dir: model.S2C, Payload: responsePacket(t, 1, "example.com")},
		{TS: 200, PacketNo: 3, Dir: model.C2S, Payload: queryPacket(t, 2, "www.example.com")},
		{TS: 210, PacketNo: 4, Dir: model.S2C, Payload: responsePacket(t, 2, "www.example.com")},
	})
	events := run(t, ctx)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	for i, wantName := range []string{"example.com", "www.example.com"} {
		e := events[i]
		if e.Type != model.EvDNSQuery {
			t.Errorf("event %d type = %s", i, e.Type)
		}
		if e.Details["qname"] != wantName || e.Details["qtype"] != "A" {
			t.Errorf("event %d details = %+v", i, e.Details)
		}
		if e.Details["rcode"] != "No Error" || e.Details["ttl"] != uint32(300) {
			t.Errorf("event %d response details = %+v", i, e.Details)
		}
		if e.TS != int64(100+100*i) {
			t.Errorf("event %d ts = %d, want query time", i, e.TS)
		}
		if e.PacketNo != uint64(1+2*i) || e.PacketEnd != uint64(2+2*i) {
			t.Errorf("event %d packet range = [%d,%d], want [%d,%d]",
				i, e.PacketNo, e.PacketEnd, 1+2*i, 2+2*i)
		}
		answers, ok := e.Details["answers"].([]map[string]any)
		if !ok || len(answers) != 1 {
			t.Fatalf("event %d answers = %#v", i, e.Details["answers"])
		}
		if answers[0]["data"] != "93.184.216.34" || answers[0]["type"] != "A" {
			t.Errorf("event %d answer = %+v", i, answers[0])
		}
	}
}

func TestResponseWindow(t *testing.T) {
	ctx := udpContext([]proto.Datagram{
		{TS: 0, PacketNo: 1, Dir: model.C2S, Payload: queryPacket(t, 7, "late.example.com")},
		{TS: 6_000_000_000, PacketNo: 2, Dir: model.S2C, Payload: responsePacket(t, 7, "late.example.com")},
		{TS: 8_000_000_000, PacketNo: 3, Dir: model.C2S, Payload: queryPacket(t, 8, "ok.example.com")},
		{TS: 9_000_000_000, PacketNo: 4, Dir: model.S2C, Payload: responsePacket(t, 8, "ok.example.com")},
	})
	events := run(t, ctx)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if _, ok := events[0].Details["rcode"]; ok {
		t.Errorf("response after 5s should not be correlated: %+v", events[0].Details)
	}
	if events[1].Details["rcode"] != "No Error" {
		t.Errorf("response within 5s should be correlated: %+v", events[1].Details)
	}
}

func TestAnalyzeTCP(t *testing.T) {
	q := queryPacket(t, 9, "tcp.example.com")
	r := responsePacket(t, 9, "tcp.example.com")
	frame := func(payload []byte) []byte {
		b := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(b[:2], uint16(len(payload)))
		copy(b[2:], payload)
		return b
	}
	src := &memStream{}
	src.data[model.C2S] = frame(q)
	src.data[model.S2C] = frame(r)
	src.segs[model.C2S] = []reassembly.Segment{{StreamOff: 0, Length: uint32(len(src.data[model.C2S])), TS: 10, PacketNo: 1}}
	src.segs[model.S2C] = []reassembly.Segment{{StreamOff: 0, Length: uint32(len(src.data[model.S2C])), TS: 20, PacketNo: 2}}

	ctx := proto.NewStreamContext(proto.StreamMeta{
		ID: 2, Proto: "dns",
		SrcIP: "10.0.0.5", DstIP: "10.0.0.6", SrcPort: 53000, DstPort: 53,
	}, src)
	events := run(t, ctx)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Details["qname"] != "tcp.example.com" || events[0].Details["rcode"] != "No Error" {
		t.Errorf("details = %+v", events[0].Details)
	}
	if events[0].PacketNo != 1 || events[0].PacketEnd != 2 {
		t.Errorf("packet range = [%d,%d], want [1,2]", events[0].PacketNo, events[0].PacketEnd)
	}
}

func TestUnansweredQuery(t *testing.T) {
	ctx := udpContext([]proto.Datagram{
		{TS: 1, PacketNo: 1, Dir: model.C2S, Payload: queryPacket(t, 3, "unanswered.example.com")},
	})
	events := run(t, ctx)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Details["qname"] != "unanswered.example.com" {
		t.Errorf("qname = %v", events[0].Details["qname"])
	}
	if _, ok := events[0].Details["rcode"]; ok {
		t.Errorf("unanswered query should have no rcode: %+v", events[0].Details)
	}
	if events[0].PacketNo != 1 || events[0].PacketEnd != 1 {
		t.Errorf("packet range = [%d,%d], want [1,1]", events[0].PacketNo, events[0].PacketEnd)
	}
}

func TestDNSFixture(t *testing.T) {
	capture := prototest.ReassembleForAnalyzers(t, "dns_queries.pcap")
	if len(capture.DatagramFlows) != 1 {
		t.Fatalf("datagram flows = %d, want 1", len(capture.DatagramFlows))
	}
	events := run(t, capture.DatagramFlows[0])
	want := []string{"example.com", "www.example.com", "mail.example.com", "cdn.example.com"}
	if len(events) != len(want) {
		t.Fatalf("events = %d, want %d", len(events), len(want))
	}
	for i, name := range want {
		e := events[i]
		if e.Details["qname"] != name {
			t.Errorf("event %d qname = %v, want %s", i, e.Details["qname"], name)
		}
		if e.Details["rcode"] != "No Error" || e.Details["ttl"] != uint32(300) {
			t.Errorf("event %d details = %+v", i, e.Details)
		}
	}
}
