package decode

import (
	"errors"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"

	"github.com/tokio-drift/raccoon/internal/capture"
)

// ErrSkip indicates a packet that cannot be decoded into a supported network
// packet (e.g. ARP, an unsupported link type or a malformed header). Callers
// should count it and continue.
var ErrSkip = errors.New("decode: packet skipped")

// Proto is the decoded transport protocol.
type Proto string

// Decoded transport protocols.
const (
	ProtoTCP   Proto = "tcp"
	ProtoUDP   Proto = "udp"
	ProtoOther Proto = "other"
)

// TCP flag bits used in Packet.TCPFlags.
const (
	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
	FlagURG uint8 = 1 << 5
	FlagECE uint8 = 1 << 6
	FlagCWR uint8 = 1 << 7
)

// Packet is a decoded IPv4/IPv6 packet. SrcIP/DstIP and Payload reference the
// input buffer and are only valid until the decoder is reused.
type Packet struct {
	No       uint64
	TS       int64
	Offset   int64
	SrcIP    netIP
	DstIP    netIP
	SrcPort  uint16
	DstPort  uint16
	Proto    Proto
	TCPFlags uint8
	Seq      uint32
	Ack      uint32
	Window   uint16
	Payload  []byte
}

// netIP aliases a byte slice so the decoded packet keeps gopacket's zero-copy
// net.IP values without importing net at call sites.
type netIP = []byte

// Decoder decodes raw packets using a reusable gopacket layer parser. It is not
// safe for concurrent use.
type Decoder struct {
	lanes  map[gopacket.LayerType]*lane
	defrag *ip4defrag.IPv4Defragmenter

	// Transport layers reused by the IP fragment path.
	tcp   layers.TCP
	udp   layers.UDP
	icmp4 layers.ICMPv4
}

// NewDecoder returns a Decoder ready for use.
func NewDecoder() *Decoder {
	return &Decoder{
		lanes:  make(map[gopacket.LayerType]*lane, 6),
		defrag: ip4defrag.NewIPv4Defragmenter(),
	}
}

// lane bundles a DecodingLayerParser with its reusable layer instances.
type lane struct {
	parser  *gopacket.DecodingLayerParser
	eth     layers.Ethernet
	dot1q   layers.Dot1Q
	sll     layers.LinuxSLL
	sll2    linuxSLL2
	lo      layers.Loopback
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmp4   layers.ICMPv4
	payload gopacket.Payload
	decoded []gopacket.LayerType
}

func newLane(first gopacket.LayerType) *lane {
	l := &lane{decoded: make([]gopacket.LayerType, 0, 12)}
	l.parser = gopacket.NewDecodingLayerParser(first,
		&l.eth, &l.dot1q, &l.sll, &l.sll2, &l.lo,
		&l.ip4, &l.ip6, &l.tcp, &l.udp, &l.icmp4,
		&l.payload,
	)
	l.parser.IgnorePanic = true
	l.parser.IgnoreUnsupported = true
	return l
}

func (d *Decoder) laneFor(linkType uint16, data []byte) *lane {
	switch linkType {
	case 1:
		return d.lane(layers.LayerTypeEthernet)
	case 113:
		return d.lane(layers.LayerTypeLinuxSLL)
	case 276:
		return d.lane(LayerTypeLinuxSLL2)
	case 0, 108:
		return d.lane(layers.LayerTypeLoopback)
	case 228:
		return d.lane(layers.LayerTypeIPv4)
	case 229:
		return d.lane(layers.LayerTypeIPv6)
	case 101, 12:
		if len(data) > 0 {
			switch data[0] >> 4 {
			case 4:
				return d.lane(layers.LayerTypeIPv4)
			case 6:
				return d.lane(layers.LayerTypeIPv6)
			}
		}
	}
	return nil
}

func (d *Decoder) lane(first gopacket.LayerType) *lane {
	if l, ok := d.lanes[first]; ok {
		return l
	}
	l := newLane(first)
	d.lanes[first] = l
	return l
}

// Decode decodes one raw packet. It returns ErrSkip for unsupported or
// malformed packets.
func (d *Decoder) Decode(raw capture.RawPacket) (Packet, error) {
	l := d.laneFor(raw.LinkType, raw.Data)
	if l == nil {
		return Packet{}, ErrSkip
	}
	err := l.parser.DecodeLayers(raw.Data, &l.decoded)
	isV4 := hasLayer(l.decoded, layers.LayerTypeIPv4)
	isV6 := hasLayer(l.decoded, layers.LayerTypeIPv6)

	if isV4 && (l.ip4.Flags&layers.IPv4MoreFragments != 0 || l.ip4.FragOffset != 0) {
		return d.decodeFragmented(raw, l)
	}
	if !isV4 && !isV6 {
		return Packet{}, ErrSkip
	}
	if err != nil && !hasLayer(l.decoded, layers.LayerTypeTCP) && !hasLayer(l.decoded, layers.LayerTypeUDP) {
		return Packet{}, ErrSkip
	}

	pkt := Packet{No: raw.No, TS: raw.TS, Offset: raw.Offset}
	if isV4 {
		pkt.SrcIP = l.ip4.SrcIP
		pkt.DstIP = l.ip4.DstIP
	} else {
		pkt.SrcIP = l.ip6.SrcIP
		pkt.DstIP = l.ip6.DstIP
	}
	switch {
	case hasLayer(l.decoded, layers.LayerTypeTCP):
		fillTCP(&pkt, &l.tcp)
	case hasLayer(l.decoded, layers.LayerTypeUDP):
		fillUDP(&pkt, &l.udp)
	default:
		pkt.Proto = ProtoOther
		if isV4 {
			pkt.Payload = l.ip4.Payload
		} else {
			pkt.Payload = l.ip6.Payload
		}
	}
	return pkt, nil
}

// decodeFragmented handles an IPv4 fragment: it feeds the defragmenter and, once
// a datagram is complete, decodes its transport header.
func (d *Decoder) decodeFragmented(raw capture.RawPacket, l *lane) (Packet, error) {
	frag := cloneIPv4(&l.ip4)
	ip, err := d.defrag.DefragIPv4WithTimestamp(frag, time.Unix(0, raw.TS))
	if err != nil || ip == nil {
		return Packet{}, ErrSkip
	}
	pkt := Packet{No: raw.No, TS: raw.TS, Offset: raw.Offset, SrcIP: ip.SrcIP, DstIP: ip.DstIP}
	switch ip.Protocol {
	case layers.IPProtocolTCP:
		if err := d.tcp.DecodeFromBytes(ip.Payload, gopacket.NilDecodeFeedback); err != nil {
			return Packet{}, ErrSkip
		}
		fillTCP(&pkt, &d.tcp)
	case layers.IPProtocolUDP:
		if err := d.udp.DecodeFromBytes(ip.Payload, gopacket.NilDecodeFeedback); err != nil {
			return Packet{}, ErrSkip
		}
		fillUDP(&pkt, &d.udp)
	default:
		pkt.Proto = ProtoOther
		pkt.Payload = ip.Payload
	}
	return pkt, nil
}

// cloneIPv4 deep-copies an IPv4 layer so the defragmenter can retain it while
// the parser's instance is reused for the next packet.
func cloneIPv4(in *layers.IPv4) *layers.IPv4 {
	out := *in
	out.BaseLayer = layers.BaseLayer{}
	out.Payload = append([]byte(nil), in.Payload...)
	if in.Padding != nil {
		out.Padding = append([]byte(nil), in.Padding...)
	}
	if in.Options != nil {
		out.Options = append([]layers.IPv4Option(nil), in.Options...)
	}
	return &out
}

func fillTCP(pkt *Packet, t *layers.TCP) {
	pkt.Proto = ProtoTCP
	pkt.SrcPort = uint16(t.SrcPort)
	pkt.DstPort = uint16(t.DstPort)
	pkt.Seq = t.Seq
	pkt.Ack = t.Ack
	pkt.Window = t.Window
	pkt.Payload = t.Payload
	var f uint8
	if t.FIN {
		f |= FlagFIN
	}
	if t.SYN {
		f |= FlagSYN
	}
	if t.RST {
		f |= FlagRST
	}
	if t.PSH {
		f |= FlagPSH
	}
	if t.ACK {
		f |= FlagACK
	}
	if t.URG {
		f |= FlagURG
	}
	if t.ECE {
		f |= FlagECE
	}
	if t.CWR {
		f |= FlagCWR
	}
	pkt.TCPFlags = f
}

func fillUDP(pkt *Packet, u *layers.UDP) {
	pkt.Proto = ProtoUDP
	pkt.SrcPort = uint16(u.SrcPort)
	pkt.DstPort = uint16(u.DstPort)
	pkt.Payload = u.Payload
}

func hasLayer(decoded []gopacket.LayerType, want gopacket.LayerType) bool {
	for _, t := range decoded {
		if t == want {
			return true
		}
	}
	return false
}
