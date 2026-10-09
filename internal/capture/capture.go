package capture

// RawPacket is a single packet as read from a capture file. The Data slice is
// owned by the Reader and is only valid until the next call to Next.
type RawPacket struct {
	No       uint64 // 1-based packet number
	TS       int64  // capture timestamp, Unix nanoseconds UTC
	Offset   int64  // byte offset of the record/block in the capture file
	CapLen   uint32
	OrigLen  uint32
	LinkType uint16
	Data     []byte
}

// Reader is a streaming capture reader. Data returned in RawPacket is valid
// only until the next call. A final truncated record yields ErrTruncatedTail
// after all complete packets have been delivered. A clean end yields io.EOF.
type Reader interface {
	Next() (RawPacket, error)
	Close() error
}
