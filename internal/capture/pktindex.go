package capture

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// IndexRecord is one entry in the packet index. It mirrors the on-disk 24-byte
// layout: offset, timestamp, capture length, interface id and padding.
type IndexRecord struct {
	Offset int64
	TS     int64
	CapLen uint32
	Iface  uint16
	Pad    uint16
}

const indexRecordSize = 24

// IndexWriter appends fixed-size 24-byte records to an index stream.
type IndexWriter struct {
	w   io.Writer
	buf [indexRecordSize]byte
}

// NewIndexWriter returns a writer that appends index records to w.
func NewIndexWriter(w io.Writer) *IndexWriter { return &IndexWriter{w: w} }

// Add appends rec to the index.
func (iw *IndexWriter) Add(rec IndexRecord) error {
	binary.LittleEndian.PutUint64(iw.buf[0:8], uint64(rec.Offset))
	binary.LittleEndian.PutUint64(iw.buf[8:16], uint64(rec.TS))
	binary.LittleEndian.PutUint32(iw.buf[16:20], rec.CapLen)
	binary.LittleEndian.PutUint16(iw.buf[20:22], rec.Iface)
	binary.LittleEndian.PutUint16(iw.buf[22:24], rec.Pad)
	_, err := iw.w.Write(iw.buf[:])
	return err
}

// IndexReader reads records from a random-access index of known size.
type IndexReader struct {
	ra   io.ReaderAt
	size int64
}

// NewIndexReader returns an index reader over ra, which must hold size bytes.
func NewIndexReader(ra io.ReaderAt, size int64) *IndexReader {
	return &IndexReader{ra: ra, size: size}
}

// Len returns the number of indexed records.
func (ir *IndexReader) Len() int64 { return ir.size / indexRecordSize }

// At returns record no, where no is 1-based. It returns io.EOF when no is past
// the end of the index.
func (ir *IndexReader) At(no uint64) (IndexRecord, error) {
	if no == 0 {
		return IndexRecord{}, fmt.Errorf("capture: index record number is 1-based")
	}
	off := int64(no-1) * indexRecordSize
	if off+indexRecordSize > ir.size {
		return IndexRecord{}, io.EOF
	}
	var buf [indexRecordSize]byte
	if _, err := ir.ra.ReadAt(buf[:], off); err != nil {
		return IndexRecord{}, err
	}
	return IndexRecord{
		Offset: int64(binary.LittleEndian.Uint64(buf[0:8])),
		TS:     int64(binary.LittleEndian.Uint64(buf[8:16])),
		CapLen: binary.LittleEndian.Uint32(buf[16:20]),
		Iface:  binary.LittleEndian.Uint16(buf[20:22]),
		Pad:    binary.LittleEndian.Uint16(buf[22:24]),
	}, nil
}

// ReadPacketAt re-reads a single indexed packet's bytes from pcapPath.
func ReadPacketAt(pcapPath string, rec IndexRecord) ([]byte, error) {
	f, err := os.Open(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("capture: open %s: %w", pcapPath, err)
	}
	defer f.Close()
	format, err := Detect(f)
	if err != nil {
		return nil, err
	}
	return ReadPacketAtFile(f, format, rec)
}

// ReadPacketAtFile re-reads a single indexed packet's bytes from an already
// open capture file whose format was returned by Detect.
func ReadPacketAtFile(f *os.File, format Format, rec IndexRecord) ([]byte, error) {
	switch format {
	case FormatPCAP:
		data := make([]byte, rec.CapLen)
		if _, err := f.ReadAt(data, rec.Offset+16); err != nil {
			return nil, fmt.Errorf("capture: read packet: %w", err)
		}
		return data, nil
	case FormatPCAPNG:
		return readNgPacketAt(f, rec)
	default:
		return nil, ErrNotCapture
	}
}

func readNgPacketAt(f *os.File, rec IndexRecord) ([]byte, error) {
	var head [12]byte
	if _, err := f.ReadAt(head[:], 0); err != nil {
		return nil, fmt.Errorf("capture: read section header: %w", err)
	}
	var order binary.ByteOrder
	switch {
	case head[8] == 0x1A && head[9] == 0x2B && head[10] == 0x3C && head[11] == 0x4D:
		order = binary.BigEndian
	case head[8] == 0x4D && head[9] == 0x3C && head[10] == 0x2B && head[11] == 0x1A:
		order = binary.LittleEndian
	default:
		return nil, fmt.Errorf("%w: missing section header", ErrCorrupt)
	}

	var hdr [8]byte
	if _, err := f.ReadAt(hdr[:], rec.Offset); err != nil {
		return nil, fmt.Errorf("capture: read block header: %w", err)
	}
	typ := order.Uint32(hdr[0:4])
	length := order.Uint32(hdr[4:8])
	if length < 12 {
		return nil, fmt.Errorf("%w: block length %d", ErrCorrupt, length)
	}
	body := make([]byte, int(length)-12)
	if _, err := f.ReadAt(body, rec.Offset+8); err != nil {
		return nil, fmt.Errorf("capture: read block body: %w", err)
	}
	switch typ {
	case ngBlockEnhancedPacket:
		if len(body) < 20 {
			return nil, fmt.Errorf("%w: short enhanced packet block", ErrCorrupt)
		}
		capLen := order.Uint32(body[12:16])
		if int(20)+int(capLen) > len(body) {
			return nil, fmt.Errorf("%w: enhanced packet data overruns block", ErrCorrupt)
		}
		out := make([]byte, capLen)
		copy(out, body[20:20+capLen])
		return out, nil
	case ngBlockSimplePacket:
		if len(body) < 4 {
			return nil, fmt.Errorf("%w: short simple packet block", ErrCorrupt)
		}
		origLen := order.Uint32(body[0:4])
		capLen := uint32(len(body) - 4)
		if capLen > origLen {
			capLen = origLen
		}
		out := make([]byte, capLen)
		copy(out, body[4:4+capLen])
		return out, nil
	default:
		return nil, fmt.Errorf("%w: indexed block is not a packet", ErrCorrupt)
	}
}
