package dns

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
	"github.com/tokio-drift/raccoon/internal/reassembly"
)

// FuzzDNS drives the DNS analyzer with arbitrary datagram and stream bytes,
// checking that it never panics, deadlocks, or crashes.
func FuzzDNS(f *testing.F) {
	// Seed with a real query packet
	q := &layers.DNS{
		ID:     0x1234,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		RD:     true,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, q); err == nil {
		f.Add(buf.Bytes())
	}

	// Seed with a real response packet
	resp := &layers.DNS{
		ID:           0x1234,
		QR:           true,
		OpCode:       layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNoErr,
		AA:           true,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   300,
				IP:    []byte{93, 184, 216, 34},
			},
		},
	}
	bufResp := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(bufResp, gopacket.SerializeOptions{FixLengths: true}, resp); err == nil {
		f.Add(bufResp.Bytes())
	}

	f.Add([]byte{})
	f.Add([]byte("\x00\x00\x00\x00"))

	analyzer := New()

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 64*1024 {
			t.Skip()
		}

		// 1. Direct decode check
		_, _ = decode(payload)

		// 2. Match check
		_ = analyzer.Match(payload, model.C2S, proto.PortPair{Client: 50000, Server: 53})
		_ = analyzer.Match(payload, model.S2C, proto.PortPair{Client: 53, Server: 50000})

		// 3. Datagram context analyze
		dctx := proto.NewDatagramContext(
			proto.StreamMeta{
				ID: 1, Proto: "dns",
				SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: 50000, DstPort: 53,
				StartTS: 1000, FirstPacket: 1,
			},
			[]proto.Datagram{
				{Payload: payload, Dir: model.C2S, TS: 1000, PacketNo: 1},
			},
		)
		_ = analyzer.Analyze(dctx, func(model.Event) {})

		// 4. Stream context analyze (DNS over TCP: 2-byte length prefix)
		var tcpStream bytes.Buffer
		_ = binary.Write(&tcpStream, binary.BigEndian, uint16(len(payload)))
		tcpStream.Write(payload)

		src := &memStream{}
		src.data[model.C2S] = tcpStream.Bytes()
		src.segs[model.C2S] = []reassembly.Segment{
			{StreamOff: 0, Length: uint32(tcpStream.Len()), TS: 1000, PacketNo: 1},
		}

		sctx := proto.NewStreamContext(
			proto.StreamMeta{
				ID: 2, Proto: "dns",
				SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: 50000, DstPort: 53,
				StartTS: 1000, FirstPacket: 1,
			},
			src,
		)
		_ = analyzer.Analyze(sctx, func(model.Event) {})
	})
}
