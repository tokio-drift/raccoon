package reassembly

import (
	"math/rand"
	"testing"
)

func TestUnwrap(t *testing.T) {
	cases := []struct {
		name string
		seq  uint32
		base uint32
		next uint64
		want uint64
	}{
		{"at base", 1000, 1000, 0, 0},
		{"forward", 1003, 1000, 0, 3},
		{"forward from next", 1003, 1000, 3, 3},
		{"duplicate far behind", 1000, 1000, 100, 0},
		{"wrap forward", 0xFFFFFF10, 0xFFFFFF00, 0, 16},
		{"at boundary", 0xFFFFFFF0, 0, 0xFFFFFFF0, 0xFFFFFFF0},
		{"wrapped continues", 0x00000010, 0, 0xFFFFFFF0, 0x100000010},
		{"out of order near wrap", 0xFFFFFFF0, 0, 0x100000000, 0xFFFFFFF0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Unwrap(tc.seq, tc.base, tc.next); got != tc.want {
				t.Fatalf("Unwrap(%#x,%#x,%d)=%#x want %#x", tc.seq, tc.base, tc.next, got, tc.want)
			}
		})
	}
}

// TestUnwrapProperties checks that Unwrap is congruent to seq-base mod 2^32 and
// returns the value closest to next.
func TestUnwrapProperties(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 100000; i++ {
		base := r.Uint32()
		seq := r.Uint32()
		next := uint64(r.Uint32()) + uint64(r.Intn(1<<33))
		got := Unwrap(seq, base, next)
		if uint32(got) != seq-base {
			t.Fatalf("not congruent: seq=%#x base=%#x next=%d got=%#x", seq, base, next, got)
		}
		d := int64(got - next)
		if d > 1<<31 || d < -(1<<31) {
			t.Fatalf("not closest: seq=%#x base=%#x next=%d got=%#x diff=%d", seq, base, next, got, d)
		}
	}
}
