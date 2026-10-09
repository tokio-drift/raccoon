package decode

import (
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/tokio-drift/raccoon/internal/capture"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

func fixturePath(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func decodeFixture(t *testing.T, name string) []Packet {
	t.Helper()
	rd, _, err := capture.Open(testutil.Pcap(t, name))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rd.Close()
	d := NewDecoder()
	var out []Packet
	for {
		raw, err := rd.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		pkt, err := d.Decode(raw)
		if err != nil {
			if errors.Is(err, ErrSkip) {
				continue
			}
			t.Fatalf("Decode: %v", err)
		}
		// Copy fields we assert on; Payload points into the reused buffer.
		pkt.Payload = append([]byte(nil), pkt.Payload...)
		out = append(out, pkt)
	}
	return out
}

func TestDecodeTCPBasic(t *testing.T) {
	pkts := decodeFixture(t, "tcp_basic.pcap")
	if len(pkts) != 15 {
		t.Fatalf("packets = %d, want 15", len(pkts))
	}
	first := pkts[0]
	if first.Proto != ProtoTCP {
		t.Fatalf("proto = %q, want tcp", first.Proto)
	}
	if first.SrcPort != 50000 || first.DstPort != 80 {
		t.Fatalf("ports = %d->%d, want 50000->80", first.SrcPort, first.DstPort)
	}
	if first.TCPFlags&FlagSYN == 0 {
		t.Fatalf("first packet flags = %#x, want SYN", first.TCPFlags)
	}
	if string(first.SrcIP) != string([]byte{10, 0, 0, 1}) {
		t.Fatalf("src IP = %v, want 10.0.0.1", first.SrcIP)
	}
}

func TestDecodePcapngBasic(t *testing.T) {
	pkts := decodeFixture(t, "pcapng_basic.pcapng")
	if len(pkts) != 15 {
		t.Fatalf("packets = %d, want 15", len(pkts))
	}
	if pkts[0].Proto != ProtoTCP || pkts[0].TCPFlags&FlagSYN == 0 {
		t.Fatalf("first packet = %+v, want TCP SYN", pkts[0])
	}
}

func TestDecodeDNS(t *testing.T) {
	pkts := decodeFixture(t, "dns_queries.pcap")
	var udp int
	for _, p := range pkts {
		if p.Proto == ProtoUDP && (p.SrcPort == 53 || p.DstPort == 53) {
			udp++
		}
	}
	if udp == 0 {
		t.Fatalf("no DNS (port 53) datagrams found in %d packets", len(pkts))
	}
}

func benchRawPackets(b testing.TB, name string) []capture.RawPacket {
	b.Helper()
	rd, _, err := capture.Open(fixturePath(name))
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer rd.Close()
	var raws []capture.RawPacket
	for {
		p, err := rd.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			b.Fatalf("Next: %v", err)
		}
		raws = append(raws, capture.RawPacket{
			No:       p.No,
			TS:       p.TS,
			Offset:   p.Offset,
			LinkType: p.LinkType,
			Data:     append([]byte(nil), p.Data...),
		})
	}
	return raws
}

func TestDecodeZeroAlloc(t *testing.T) {
	raws := benchRawPackets(t, "tcp_basic.pcap")
	d := NewDecoder()
	for i := 0; i < 3; i++ {
		for j := range raws {
			if _, err := d.Decode(raws[j]); err != nil {
				t.Fatalf("Decode: %v", err)
			}
		}
	}
	allocs := testing.AllocsPerRun(100, func() {
		for j := range raws {
			_, _ = d.Decode(raws[j])
		}
	})
	if allocs != 0 {
		t.Fatalf("allocs per run = %v, want 0", allocs)
	}
}

func BenchmarkDecode(b *testing.B) {
	raws := benchRawPackets(b, "tcp_basic.pcap")
	d := NewDecoder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range raws {
			if _, err := d.Decode(raws[j]); err != nil {
				b.Fatalf("Decode: %v", err)
			}
		}
	}
}
