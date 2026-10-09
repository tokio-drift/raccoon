package flow

import (
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/tokio-drift/raccoon/internal/capture"
	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

func collectFlows(t *testing.T, name string) []*Flow {
	t.Helper()
	rd, _, err := capture.Open(testutil.Pcap(t, name))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rd.Close()
	d := decode.NewDecoder()
	tab := NewTable(nil)
	var order []*Flow
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
			if errors.Is(err, decode.ErrSkip) {
				continue
			}
			t.Fatalf("Decode: %v", err)
		}
		f, _, isNew := tab.Lookup(pkt)
		if f != nil && isNew {
			order = append(order, f)
		}
	}
	return order
}

func TestFlowCounts(t *testing.T) {
	cases := []struct {
		name      string
		want      int
		midstream bool
	}{
		{"tcp_basic.pcap", 1, false},
		{"tcp_ooo.pcap", 1, false},
		{"tcp_retrans.pcap", 1, false},
		{"tcp_overlap_conflict.pcap", 1, false},
		{"tcp_wrap.pcap", 1, false},
		{"tcp_gap.pcap", 1, false},
		{"tcp_midstream.pcap", 1, true},
		{"tcp_portreuse.pcap", 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := collectFlows(t, tc.name)
			if len(flows) != tc.want {
				t.Fatalf("flows = %d, want %d", len(flows), tc.want)
			}
			if tc.midstream {
				for _, f := range flows {
					if !f.Midstream {
						t.Fatalf("flow %d: Midstream = false, want true", f.ID)
					}
				}
			}
		})
	}
}

func TestFlowInitiator(t *testing.T) {
	flows := collectFlows(t, "tcp_basic.pcap")
	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(flows))
	}
	f := flows[0]
	if f.Proto != "tcp" {
		t.Fatalf("proto = %q, want tcp", f.Proto)
	}
	want := Endpoint{IP: netip.MustParseAddr("10.0.0.1"), Port: 50000}
	if f.Initiator != want {
		t.Fatalf("initiator = %v, want %v", f.Initiator, want)
	}
	if f.State != StateClosed {
		t.Fatalf("state = %v, want CLOSED", f.State)
	}
}

func TestPortReuseDistinctIDs(t *testing.T) {
	flows := collectFlows(t, "tcp_portreuse.pcap")
	if len(flows) != 2 {
		t.Fatalf("flows = %d, want 2", len(flows))
	}
	if flows[0].ID == flows[1].ID {
		t.Fatalf("reused flow has duplicate ID %d", flows[0].ID)
	}
}

func TestKeySameBothDirections(t *testing.T) {
	a := decode.Packet{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, SrcPort: 50000, DstPort: 80, Proto: decode.ProtoTCP}
	b := decode.Packet{SrcIP: a.DstIP, DstIP: a.SrcIP, SrcPort: 80, DstPort: 50000, Proto: decode.ProtoTCP}
	ka, kb := MakeKey(a), MakeKey(b)
	if ka != kb {
		t.Fatalf("keys differ: %+v vs %+v", ka, kb)
	}
	if ka.Hash() != kb.Hash() {
		t.Fatalf("hashes differ: %d vs %d", ka.Hash(), kb.Hash())
	}
}

func TestKeyIPv4MappedIPv6(t *testing.T) {
	v4 := decode.Packet{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, SrcPort: 1, DstPort: 2, Proto: decode.ProtoTCP}
	mapped := decode.Packet{
		SrcIP:   netip.MustParseAddr("::ffff:10.0.0.1").AsSlice(),
		DstIP:   netip.MustParseAddr("::ffff:10.0.0.2").AsSlice(),
		SrcPort: 1, DstPort: 2, Proto: decode.ProtoTCP,
	}
	if MakeKey(v4) != MakeKey(mapped) {
		t.Fatalf("IPv4 and IPv4-mapped IPv6 keys differ")
	}
}

func TestTCPStateMachine(t *testing.T) {
	a := []byte{10, 0, 0, 1}
	b := []byte{10, 0, 0, 2}
	mk := func(no uint64, fromA bool, flags uint8) decode.Packet {
		p := decode.Packet{No: no, TS: int64(no) * 1000, Proto: decode.ProtoTCP, TCPFlags: flags, SrcIP: a, DstIP: b, SrcPort: 1, DstPort: 2}
		if !fromA {
			p.SrcIP, p.DstIP = b, a
			p.SrcPort, p.DstPort = 2, 1
		}
		return p
	}
	tab := NewTable(nil)
	f, dir, isNew := tab.Lookup(mk(1, true, decode.FlagSYN))
	if !isNew || dir != model.C2S || f.State != StateSynSeen {
		t.Fatalf("SYN: new=%v dir=%v state=%v", isNew, dir, f.State)
	}
	if _, dir, _ := tab.Lookup(mk(2, false, decode.FlagSYN|decode.FlagACK)); dir != model.S2C {
		t.Fatalf("SYN-ACK dir = %v, want S2C", dir)
	}
	if _, _, _ = tab.Lookup(mk(3, true, decode.FlagACK)); f.State != StateEstablished {
		t.Fatalf("after ACK state = %v, want ESTABLISHED", f.State)
	}
	if _, _, _ = tab.Lookup(mk(4, true, decode.FlagFIN|decode.FlagACK)); f.State != StateClosing {
		t.Fatalf("after FIN state = %v, want CLOSING", f.State)
	}
	tab.Lookup(mk(5, false, decode.FlagFIN|decode.FlagACK))
	if _, _, _ = tab.Lookup(mk(6, true, decode.FlagACK)); f.State != StateClosed {
		t.Fatalf("after final ACK state = %v, want CLOSED", f.State)
	}
}

func TestRSTCloses(t *testing.T) {
	a := []byte{10, 0, 0, 1}
	b := []byte{10, 0, 0, 2}
	tab := NewTable(nil)
	tab.Lookup(decode.Packet{No: 1, Proto: decode.ProtoTCP, TCPFlags: decode.FlagSYN, SrcIP: a, DstIP: b, SrcPort: 1, DstPort: 2})
	f, _, _ := tab.Lookup(decode.Packet{No: 2, Proto: decode.ProtoTCP, TCPFlags: decode.FlagRST, SrcIP: a, DstIP: b, SrcPort: 1, DstPort: 2})
	if f.State != StateClosed {
		t.Fatalf("state = %v, want CLOSED", f.State)
	}
}

func TestExpire(t *testing.T) {
	a := []byte{10, 0, 0, 1}
	b := []byte{10, 0, 0, 2}
	tab := NewTable(nil)
	tab.Lookup(decode.Packet{No: 1, TS: 1000, Proto: decode.ProtoTCP, TCPFlags: decode.FlagSYN, SrcIP: a, DstIP: b, SrcPort: 1, DstPort: 2})
	timeout := limits.FlowIdleTimeout.Nanoseconds()
	if got := tab.Expire(1000 + timeout - 1); len(got) != 0 {
		t.Fatalf("Expire before timeout returned %d flows", len(got))
	}
	got := tab.Expire(1000 + timeout)
	if len(got) != 1 {
		t.Fatalf("Expire at timeout returned %d flows, want 1", len(got))
	}
	if tab.Len() != 0 {
		t.Fatalf("Table.Len = %d, want 0", tab.Len())
	}
}
