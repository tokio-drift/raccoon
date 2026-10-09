package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// Format identifies a supported capture file container.
type Format uint8

// Supported capture formats.
const (
	FormatUnknown Format = iota
	FormatPCAP
	FormatPCAPNG
)

// String returns the human-readable format name.
func (f Format) String() string {
	switch f {
	case FormatPCAP:
		return "pcap"
	case FormatPCAPNG:
		return "pcapng"
	default:
		return "unknown"
	}
}

// Info describes a capture file at the container level.
type Info struct {
	Format    Format
	Size      int64
	LinkTypes []uint16
}

// Sentinel errors returned by the capture package.
var (
	// ErrNotCapture is returned when the input is not a PCAP or PCAPNG file.
	ErrNotCapture = errors.New("capture: not a pcap or pcapng file")
	// ErrCorrupt is returned when a recognised container is structurally invalid.
	ErrCorrupt = errors.New("capture: corrupt capture file")
	// ErrTruncatedTail is returned when the final record is cut short; all
	// complete packets have already been delivered.
	ErrTruncatedTail = errors.New("capture: truncated final record")
)

const maxCaptureLen = 262144

var (
	pcapMagicBEus = [4]byte{0xA1, 0xB2, 0xC3, 0xD4}
	pcapMagicLEus = [4]byte{0xD4, 0xC3, 0xB2, 0xA1}
	pcapMagicBEns = [4]byte{0xA1, 0xB2, 0x3C, 0x4D}
	pcapMagicLEns = [4]byte{0x4D, 0x3C, 0xB2, 0xA1}
	pcapngMagic   = [4]byte{0x0A, 0x0D, 0x0D, 0x0A}
)

// Detect identifies the capture container by its first four bytes. It consumes
// those bytes from r.
func Detect(r io.Reader) (Format, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return FormatUnknown, fmt.Errorf("%w: %v", ErrNotCapture, err)
	}
	switch magic {
	case pcapngMagic:
		return FormatPCAPNG, nil
	case pcapMagicBEus, pcapMagicLEus, pcapMagicBEns, pcapMagicLEns:
		return FormatPCAP, nil
	default:
		return FormatUnknown, ErrNotCapture
	}
}

// Validate opens path, detects its format and reads its container headers only,
// returning the format, file size and link types.
func Validate(path string) (Info, error) {
	f, err := os.Open(path)
	if err != nil {
		return Info{}, fmt.Errorf("capture: open %s: %w", path, err)
	}
	defer f.Close()

	format, err := Detect(f)
	if err != nil {
		return Info{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Info{}, fmt.Errorf("capture: seek %s: %w", path, err)
	}
	info := Info{Format: format}
	if st, err := f.Stat(); err == nil {
		info.Size = st.Size()
	}

	switch format {
	case FormatPCAP:
		linkType, _, _, err := readPCAPGlobalHeader(f)
		if err != nil {
			return Info{}, err
		}
		info.LinkTypes = []uint16{linkType}
	case FormatPCAPNG:
		rd, err := newNgReader(f)
		if err != nil {
			return Info{}, err
		}
		if err := rd.scanHeaders(); err != nil && !errors.Is(err, io.EOF) {
			return Info{}, err
		}
		info.LinkTypes = rd.linkTypes()
	}
	return info, nil
}

// readPCAPGlobalHeader parses the 24-byte classic pcap global header and
// returns the link type, the correct byte order and whether timestamps are in
// nanoseconds.
func readPCAPGlobalHeader(r io.Reader) (uint16, binary.ByteOrder, bool, error) {
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, false, fmt.Errorf("%w: short global header", ErrCorrupt)
		}
		return 0, nil, false, fmt.Errorf("capture: read global header: %w", err)
	}
	magic := [4]byte{hdr[0], hdr[1], hdr[2], hdr[3]}
	var order binary.ByteOrder
	var nanos bool
	switch magic {
	case pcapMagicBEus:
		order, nanos = binary.BigEndian, false
	case pcapMagicLEus:
		order, nanos = binary.LittleEndian, false
	case pcapMagicBEns:
		order, nanos = binary.BigEndian, true
	case pcapMagicLEns:
		order, nanos = binary.LittleEndian, true
	default:
		return 0, nil, false, ErrNotCapture
	}
	snaplen := order.Uint32(hdr[16:20])
	if snaplen > 1<<24 {
		return 0, nil, false, fmt.Errorf("%w: implausible snaplen %d", ErrCorrupt, snaplen)
	}
	linkType := order.Uint32(hdr[20:24])
	if linkType > 0xFFFF {
		return 0, nil, false, fmt.Errorf("%w: link type %d out of range", ErrCorrupt, linkType)
	}
	return uint16(linkType), order, nanos, nil
}
