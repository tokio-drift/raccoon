package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// pcapReader is a streaming reader for classic pcap files.
type pcapReader struct {
	br       io.Reader
	closer   io.Closer
	order    binary.ByteOrder
	nanos    bool
	linkType uint16
	no       uint64
	offset   int64
	buf      []byte
}

// newPCAPReader parses the global header and returns a reader positioned at the
// first record.
func newPCAPReader(br io.Reader) (*pcapReader, error) {
	linkType, order, nanos, err := readPCAPGlobalHeader(br)
	if err != nil {
		return nil, err
	}
	return &pcapReader{br: br, order: order, nanos: nanos, linkType: linkType, offset: 24}, nil
}

func (r *pcapReader) Next() (RawPacket, error) {
	var hdr [16]byte
	n, err := io.ReadFull(r.br, hdr[:])
	if err != nil {
		if errors.Is(err, io.EOF) && n == 0 {
			return RawPacket{}, io.EOF
		}
		return RawPacket{}, ErrTruncatedTail
	}

	tsSec := r.order.Uint32(hdr[0:4])
	tsFrac := r.order.Uint32(hdr[4:8])
	capLen := r.order.Uint32(hdr[8:12])
	origLen := r.order.Uint32(hdr[12:16])
	if capLen > maxCaptureLen {
		return RawPacket{}, fmt.Errorf("%w: record %d caplen %d exceeds limit", ErrCorrupt, r.no+1, capLen)
	}

	if uint32(cap(r.buf)) < capLen {
		r.buf = make([]byte, capLen)
	}
	if _, err := io.ReadFull(r.br, r.buf[:capLen]); err != nil {
		return RawPacket{}, ErrTruncatedTail
	}

	var ts int64
	if r.nanos {
		ts = int64(tsSec)*1e9 + int64(tsFrac)
	} else {
		ts = int64(tsSec)*1e9 + int64(tsFrac)*1000
	}

	r.no++
	pkt := RawPacket{
		No:       r.no,
		TS:       ts,
		Offset:   r.offset,
		CapLen:   capLen,
		OrigLen:  origLen,
		LinkType: r.linkType,
		Data:     r.buf[:capLen],
	}
	r.offset += 16 + int64(capLen)
	return pkt, nil
}

func (r *pcapReader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}
