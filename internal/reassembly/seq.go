package reassembly

const (
	mask32 = uint64(1)<<32 - 1
	two32  = uint64(1) << 32
	half32 = uint64(1) << 31
)

// Unwrap maps a 32-bit TCP sequence number to a 64-bit stream offset. The
// result is congruent to seq-base modulo 2³² and is the value closest to next,
// which tracks the stream as sequence numbers wrap around 0xFFFFFFFF.
func Unwrap(seq, base uint32, next uint64) uint64 {
	delta := int64(uint32(seq - base)) // 0 .. 2³²-1
	d := delta - int64(next&mask32)    // (-(2³²), 2³²)
	switch {
	case d > int64(half32):
		d -= int64(two32)
	case d < -int64(half32):
		d += int64(two32)
	}
	return next + uint64(d)
}
