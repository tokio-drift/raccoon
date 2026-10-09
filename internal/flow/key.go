package flow

import (
	"encoding/binary"
	"net/netip"

	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/model"
)

// Endpoint is one side of a flow: an IP address and a transport port.
type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

// Key identifies a bidirectional flow. A and B are stored in canonical order so
// that packets travelling in either direction produce the same key.
type Key struct {
	A, B  Endpoint
	Proto string
}

// MakeKey builds the canonical key for a decoded packet.
func MakeKey(pkt decode.Packet) Key {
	a := Endpoint{IP: addr(pkt.SrcIP), Port: pkt.SrcPort}
	b := Endpoint{IP: addr(pkt.DstIP), Port: pkt.DstPort}
	if endpointLess(b, a) {
		a, b = b, a
	}
	return Key{A: a, B: b, Proto: string(pkt.Proto)}
}

// addr converts a 4- or 16-byte IP into a comparable, unmapped netip.Addr.
func addr(b []byte) netip.Addr {
	a, _ := netip.AddrFromSlice(b)
	return a.Unmap()
}

func endpointLess(a, b Endpoint) bool {
	if c := a.IP.Compare(b.IP); c != 0 {
		return c < 0
	}
	return a.Port < b.Port
}

const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

// Hash returns an FNV-1a hash of the normalized key, suitable for sharding.
func (k Key) Hash() uint64 {
	h := uint64(fnvOffset64)
	for i := 0; i < len(k.Proto); i++ {
		h = (h ^ uint64(k.Proto[i])) * fnvPrime64
	}
	h = hashEndpoint(h, k.A)
	h = hashEndpoint(h, k.B)
	return h
}

func hashEndpoint(h uint64, e Endpoint) uint64 {
	ip := e.IP.As16()
	for _, c := range ip {
		h = (h ^ uint64(c)) * fnvPrime64
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], e.Port)
	for _, c := range port {
		h = (h ^ uint64(c)) * fnvPrime64
	}
	return h
}

// DirectionOf returns the direction of a packet whose source endpoint is src,
// relative to the flow initiator.
func DirectionOf(src, initiator Endpoint) model.Direction {
	if src == initiator {
		return model.C2S
	}
	return model.S2C
}
