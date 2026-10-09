package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	ngBlockInterfaceDesc  uint32 = 0x00000001
	ngBlockSimplePacket   uint32 = 0x00000003
	ngBlockEnhancedPacket uint32 = 0x00000006
	ngBlockSectionHeader  uint32 = 0x0A0D0D0A

	// maxNgBlockLen bounds a single pcapng block to avoid unbounded allocations
	// from malicious or corrupt length fields.
	maxNgBlockLen = 16 << 20
)

type ngBlock struct {
	typ    uint32
	body   []byte
	offset int64
}

type ngInterface struct {
	linkType uint16
	snaplen  uint32
	tsresol  byte
}

// ngReader is a streaming reader for pcapng files.
type ngReader struct {
	br         io.Reader
	closer     io.Closer
	order      binary.ByteOrder
	ifaces     []ngInterface
	seenLinks  []uint16
	no         uint64
	offset     int64
	buf        []byte
	pending    RawPacket
	hasPending bool
}

func newNgReader(br io.Reader) (*ngReader, error) {
	return &ngReader{br: br, order: binary.LittleEndian}, nil
}

func (r *ngReader) linkTypes() []uint16 {
	out := make([]uint16, len(r.seenLinks))
	copy(out, r.seenLinks)
	return out
}

// scanHeaders consumes section and interface blocks up to the first packet
// block, retaining that packet for the first Next call.
func (r *ngReader) scanHeaders() error {
	pkt, err := r.readNext()
	if err != nil {
		return err
	}
	r.pending = pkt
	r.hasPending = true
	return nil
}

func (r *ngReader) Next() (RawPacket, error) {
	if r.hasPending {
		r.hasPending = false
		return r.pending, nil
	}
	return r.readNext()
}

func (r *ngReader) readNext() (RawPacket, error) {
	for {
		blk, err := r.readBlock()
		if err != nil {
			return RawPacket{}, err
		}
		switch blk.typ {
		case ngBlockSectionHeader:
			// readBlock already reset the interface table.
		case ngBlockInterfaceDesc:
			r.parseInterfaceDesc(blk.body)
		case ngBlockEnhancedPacket:
			pkt, err := r.parseEnhancedPacket(blk)
			if err != nil {
				return RawPacket{}, err
			}
			return pkt, nil
		case ngBlockSimplePacket:
			pkt, err := r.parseSimplePacket(blk)
			if err != nil {
				return RawPacket{}, err
			}
			return pkt, nil
		default:
			// Skip unknown blocks.
		}
	}
}

func (r *ngReader) readBlock() (*ngBlock, error) {
	start := r.offset
	var hdr [8]byte
	n, err := io.ReadFull(r.br, hdr[:])
	if err != nil {
		if errors.Is(err, io.EOF) && n == 0 {
			return nil, io.EOF
		}
		return nil, ErrTruncatedTail
	}
	typ := r.order.Uint32(hdr[0:4])
	if typ == ngBlockSectionHeader {
		return r.readSectionHeader(start, hdr)
	}
	length := r.order.Uint32(hdr[4:8])
	if length < 12 || length%4 != 0 || length > maxNgBlockLen {
		return nil, fmt.Errorf("%w: block length %d", ErrCorrupt, length)
	}
	body := make([]byte, int(length)-12)
	if _, err := io.ReadFull(r.br, body); err != nil {
		return nil, ErrTruncatedTail
	}
	var trailer [4]byte
	if _, err := io.ReadFull(r.br, trailer[:]); err != nil {
		return nil, ErrTruncatedTail
	}
	if r.order.Uint32(trailer[:]) != length {
		return nil, fmt.Errorf("%w: block trailer mismatch", ErrCorrupt)
	}
	r.offset = start + int64(length)
	return &ngBlock{typ: typ, body: body, offset: start}, nil
}

func (r *ngReader) readSectionHeader(start int64, hdr [8]byte) (*ngBlock, error) {
	var bom [4]byte
	if _, err := io.ReadFull(r.br, bom[:]); err != nil {
		return nil, ErrTruncatedTail
	}
	switch {
	case bom == [4]byte{0x1A, 0x2B, 0x3C, 0x4D}:
		r.order = binary.BigEndian
	case bom == [4]byte{0x4D, 0x3C, 0x2B, 0x1A}:
		r.order = binary.LittleEndian
	default:
		return nil, fmt.Errorf("%w: bad section byte-order magic", ErrCorrupt)
	}
	length := r.order.Uint32(hdr[4:8])
	if length < 28 || length%4 != 0 || length > maxNgBlockLen {
		return nil, fmt.Errorf("%w: section length %d", ErrCorrupt, length)
	}
	remain := int(length) - 16 // minus 8 header, 4 magic, 4 trailer
	if remain < 0 {
		return nil, fmt.Errorf("%w: section length %d", ErrCorrupt, length)
	}
	rest := make([]byte, remain)
	if _, err := io.ReadFull(r.br, rest); err != nil {
		return nil, ErrTruncatedTail
	}
	var trailer [4]byte
	if _, err := io.ReadFull(r.br, trailer[:]); err != nil {
		return nil, ErrTruncatedTail
	}
	if r.order.Uint32(trailer[:]) != length {
		return nil, fmt.Errorf("%w: section trailer mismatch", ErrCorrupt)
	}
	body := append(append([]byte{}, bom[:]...), rest...)
	r.ifaces = r.ifaces[:0]
	r.offset = start + int64(length)
	return &ngBlock{typ: ngBlockSectionHeader, body: body, offset: start}, nil
}

func (r *ngReader) parseInterfaceDesc(body []byte) {
	if len(body) < 8 {
		return
	}
	iface := ngInterface{
		linkType: r.order.Uint16(body[0:2]),
		snaplen:  r.order.Uint32(body[4:8]),
		tsresol:  6,
	}
	for off := 8; off+4 <= len(body); {
		code := r.order.Uint16(body[off : off+2])
		l := int(r.order.Uint16(body[off+2 : off+4]))
		if code == 0 {
			break
		}
		if off+4+l > len(body) {
			break
		}
		if code == 9 && l >= 1 {
			iface.tsresol = body[off+4]
		}
		off += 4 + ((l + 3) / 4 * 4)
	}
	r.ifaces = append(r.ifaces, iface)
	if !containsLink(r.seenLinks, iface.linkType) {
		r.seenLinks = append(r.seenLinks, iface.linkType)
	}
}

func containsLink(links []uint16, lt uint16) bool {
	for _, l := range links {
		if l == lt {
			return true
		}
	}
	return false
}

func (r *ngReader) parseEnhancedPacket(blk *ngBlock) (RawPacket, error) {
	body := blk.body
	if len(body) < 20 {
		return RawPacket{}, fmt.Errorf("%w: short enhanced packet block", ErrCorrupt)
	}
	ifaceID := r.order.Uint32(body[0:4])
	tsHigh := r.order.Uint32(body[4:8])
	tsLow := r.order.Uint32(body[8:12])
	capLen := r.order.Uint32(body[12:16])
	origLen := r.order.Uint32(body[16:20])
	if capLen > maxCaptureLen {
		return RawPacket{}, fmt.Errorf("%w: block caplen %d exceeds limit", ErrCorrupt, capLen)
	}
	if int(20)+int(capLen) > len(body) {
		return RawPacket{}, fmt.Errorf("%w: enhanced packet data overruns block", ErrCorrupt)
	}
	if int(ifaceID) >= len(r.ifaces) {
		return RawPacket{}, fmt.Errorf("%w: packet references unknown interface %d", ErrCorrupt, ifaceID)
	}
	iface := r.ifaces[ifaceID]
	ts := tsToNanos(uint64(tsHigh)<<32|uint64(tsLow), iface.tsresol)
	r.no++
	return r.copyPacket(body[20:20+capLen], blk.offset, ts, capLen, origLen, iface.linkType), nil
}

func (r *ngReader) parseSimplePacket(blk *ngBlock) (RawPacket, error) {
	body := blk.body
	if len(body) < 4 {
		return RawPacket{}, fmt.Errorf("%w: short simple packet block", ErrCorrupt)
	}
	origLen := r.order.Uint32(body[0:4])
	data := body[4:]
	capLen := uint32(len(data))
	if capLen > origLen {
		capLen = origLen
	}
	var iface ngInterface
	if len(r.ifaces) > 0 {
		iface = r.ifaces[0]
	}
	ts := tsToNanos(0, iface.tsresol)
	r.no++
	return r.copyPacket(data[:capLen], blk.offset, ts, capLen, origLen, iface.linkType), nil
}

func (r *ngReader) copyPacket(src []byte, offset int64, ts int64, capLen, origLen uint32, linkType uint16) RawPacket {
	if cap(r.buf) < len(src) {
		r.buf = make([]byte, len(src))
	}
	copy(r.buf, src)
	return RawPacket{
		No:       r.no,
		TS:       ts,
		Offset:   offset,
		CapLen:   capLen,
		OrigLen:  origLen,
		LinkType: linkType,
		Data:     r.buf[:len(src)],
	}
}

func (r *ngReader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

// tsToNanos converts a pcapng timestamp expressed in interface units to Unix
// nanoseconds using the if_tsresol value.
func tsToNanos(ts uint64, resol byte) int64 {
	if resol&0x80 == 0 {
		if resol == 0 {
			return int64(ts) * 1e9
		}
		units := uint64(1)
		for i := 0; i < int(resol) && units <= 1<<60; i++ {
			units *= 10
		}
		if units <= 1_000_000_000 {
			return int64(ts * (1_000_000_000 / units))
		}
		return int64(ts / (units / 1_000_000_000))
	}
	exp := int(resol & 0x7f)
	return int64(float64(ts) * 1e9 / math.Pow(2, float64(exp)))
}
