package decode

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerTypeLinuxSLL2 is the Linux cooked capture v2 link type (DLT_LINUX_SLL2,
// 276). gopacket does not provide it, so it is registered here.
var LayerTypeLinuxSLL2 = gopacket.RegisterLayerType(276, gopacket.LayerTypeMetadata{
	Name:    "Linux SLL2",
	Decoder: gopacket.DecodeFunc(decodeLinuxSLL2),
})

var errShortSLL2 = errors.New("decode: short Linux SLL2 header")

func decodeLinuxSLL2(data []byte, p gopacket.PacketBuilder) error {
	l := &linuxSLL2{}
	if err := l.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(l)
	return p.NextDecoder(l.NextLayerType())
}

// linuxSLL2 is a minimal decoder for the DLT_LINUX_SLL2 header.
type linuxSLL2 struct {
	ProtocolType   layers.EthernetType
	InterfaceIndex uint32
	ARPHRDType     uint16
	PacketType     uint8
	AddrLen        uint8
	Addr           [8]byte
	layers.BaseLayer
}

func (l *linuxSLL2) DecodeFromBytes(data []byte, _ gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		return errShortSLL2
	}
	l.ProtocolType = layers.EthernetType(binary.BigEndian.Uint16(data[0:2]))
	l.InterfaceIndex = binary.BigEndian.Uint32(data[4:8])
	l.ARPHRDType = binary.BigEndian.Uint16(data[8:10])
	l.PacketType = data[10]
	l.AddrLen = data[11]
	copy(l.Addr[:], data[12:20])
	l.BaseLayer = layers.BaseLayer{Contents: data[:20], Payload: data[20:]}
	return nil
}

func (l *linuxSLL2) CanDecode() gopacket.LayerClass { return LayerTypeLinuxSLL2 }

func (l *linuxSLL2) LayerType() gopacket.LayerType { return LayerTypeLinuxSLL2 }

func (l *linuxSLL2) NextLayerType() gopacket.LayerType {
	switch l.ProtocolType {
	case layers.EthernetTypeIPv4:
		return layers.LayerTypeIPv4
	case layers.EthernetTypeIPv6:
		return layers.LayerTypeIPv6
	case layers.EthernetTypeARP:
		return layers.LayerTypeARP
	default:
		return gopacket.LayerTypePayload
	}
}

func (l *linuxSLL2) LayerPayload() []byte { return l.Payload }
