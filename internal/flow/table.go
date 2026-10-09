package flow

import (
	"sync/atomic"

	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
)

// State is the TCP state of a flow.
type State uint8

// TCP flow states.
const (
	StateNew State = iota
	StateSynSeen
	StateEstablished
	StateClosing
	StateClosed
)

// String returns the human-readable state name.
func (s State) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateSynSeen:
		return "SYN_SEEN"
	case StateEstablished:
		return "ESTABLISHED"
	case StateClosing:
		return "CLOSING"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// DatagramRef references a single UDP datagram in the capture file.
type DatagramRef struct {
	Offset   int64
	Length   int
	TS       int64
	PacketNo uint64
	Dir      model.Direction
}

// Flow is a tracked bidirectional flow.
type Flow struct {
	ID          int64
	Key         Key
	Initiator   Endpoint
	Proto       string
	State       State
	Midstream   bool
	StartTS     int64
	EndTS       int64
	Packets     int64
	BytesC2S    int64
	BytesS2C    int64
	FirstPacket uint64
	LastPacket  uint64
	Datagrams   []DatagramRef

	lastSeen  int64
	clientISN uint32
	finC2S    bool
	finS2C    bool
}

// IsUDP reports whether the flow carries UDP rather than TCP.
func (f *Flow) IsUDP() bool { return f.Proto == string(decode.ProtoUDP) }

// Table tracks flows keyed by their canonical tuple.
type Table struct {
	flows map[Key]*Flow
	alloc func() int64
}

// NewTable returns a table using alloc to assign flow IDs. A nil alloc uses a
// private atomic counter starting at 1.
func NewTable(alloc func() int64) *Table {
	if alloc == nil {
		alloc = NewCounter(1)
	}
	return &Table{flows: make(map[Key]*Flow), alloc: alloc}
}

// NewCounter returns an allocation function backed by a shared atomic counter.
func NewCounter(start int64) func() int64 {
	n := start - 1
	return func() int64 { return atomic.AddInt64(&n, 1) }
}

// Len returns the number of live flows.
func (t *Table) Len() int { return len(t.flows) }

// Lookup finds or creates the flow for pkt, updates its state and statistics,
// and returns the flow, the packet's direction and whether a flow was created.
// It returns (nil, 0, false) for protocols other than TCP and UDP.
func (t *Table) Lookup(pkt decode.Packet) (*Flow, model.Direction, bool) {
	if pkt.Proto != decode.ProtoTCP && pkt.Proto != decode.ProtoUDP {
		return nil, 0, false
	}
	key := MakeKey(pkt)
	src := Endpoint{IP: addr(pkt.SrcIP), Port: pkt.SrcPort}

	f := t.flows[key]
	isNew := false
	if f == nil {
		f = t.newFlow(key, pkt, src)
		isNew = true
	} else if pkt.Proto == decode.ProtoTCP && isPureSYN(pkt) &&
		(f.State == StateClosed || f.State == StateClosing) && pkt.Seq != f.clientISN {
		f = t.newFlow(key, pkt, src)
		isNew = true
	}

	dir := DirectionOf(src, f.Initiator)

	f.Packets++
	if f.FirstPacket == 0 {
		f.FirstPacket = pkt.No
		f.StartTS = pkt.TS
	}
	f.LastPacket = pkt.No
	f.EndTS = pkt.TS
	f.lastSeen = pkt.TS
	if dir == model.C2S {
		f.BytesC2S += int64(len(pkt.Payload))
	} else {
		f.BytesS2C += int64(len(pkt.Payload))
	}

	if pkt.Proto == decode.ProtoUDP {
		f.Datagrams = append(f.Datagrams, DatagramRef{
			Offset:   pkt.Offset,
			Length:   len(pkt.Payload),
			TS:       pkt.TS,
			PacketNo: pkt.No,
			Dir:      dir,
		})
		return f, dir, isNew
	}

	t.updateTCP(f, pkt, dir)
	return f, dir, isNew
}

func (t *Table) newFlow(key Key, pkt decode.Packet, src Endpoint) *Flow {
	f := &Flow{
		ID:        t.alloc(),
		Key:       key,
		Initiator: src,
		Proto:     string(pkt.Proto),
		State:     StateNew,
		lastSeen:  pkt.TS,
	}
	switch {
	case pkt.Proto == decode.ProtoUDP:
		f.State = StateEstablished
	case isPureSYN(pkt):
		f.State = StateSynSeen
		f.clientISN = pkt.Seq
	default:
		f.Midstream = true
		f.State = StateEstablished
	}
	t.flows[key] = f
	return f
}

func (t *Table) updateTCP(f *Flow, pkt decode.Packet, dir model.Direction) {
	switch {
	case pkt.TCPFlags&decode.FlagRST != 0:
		f.State = StateClosed
	case pkt.TCPFlags&decode.FlagFIN != 0:
		if dir == model.C2S {
			f.finC2S = true
		} else {
			f.finS2C = true
		}
		f.State = StateClosing
	case pkt.TCPFlags&decode.FlagSYN != 0:
		if f.State == StateNew {
			f.State = StateSynSeen
		}
	case pkt.TCPFlags&decode.FlagACK != 0:
		switch f.State {
		case StateSynSeen:
			f.State = StateEstablished
		case StateClosing:
			if f.finC2S && f.finS2C {
				f.State = StateClosed
			}
		}
	}
}

// Expire removes and returns flows idle for at least limits.FlowIdleTimeout on
// the capture clock.
func (t *Table) Expire(now int64) []*Flow {
	timeout := limits.FlowIdleTimeout.Nanoseconds()
	var expired []*Flow
	for k, f := range t.flows {
		if now-f.lastSeen >= timeout {
			expired = append(expired, f)
			delete(t.flows, k)
		}
	}
	return expired
}

func isPureSYN(pkt decode.Packet) bool {
	return pkt.TCPFlags&decode.FlagSYN != 0 && pkt.TCPFlags&decode.FlagACK == 0
}
