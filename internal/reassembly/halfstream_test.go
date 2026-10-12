package reassembly

import (
	"bytes"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/model"
)

type halfFixture struct {
	h       *HalfStream
	out     *bytes.Buffer
	idx     *SegmentIndex
	anomaly []Anomaly
}

func newHalfFixture(base uint32, maxPending int64, holeTimeout time.Duration) *halfFixture {
	f := &halfFixture{out: &bytes.Buffer{}, idx: NewSegmentIndex(nil)}
	f.h = NewHalfStream(HalfStreamConfig{
		Dir:         model.C2S,
		Base:        base,
		Writer:      f.out,
		Index:       f.idx,
		Accountant:  NoopAccountant{},
		MaxPending:  maxPending,
		HoleTimeout: holeTimeout,
		OnAnomaly:   func(a Anomaly) { f.anomaly = append(f.anomaly, a) },
	})
	return f
}

func (f *halfFixture) add(seq uint32, s string, ts int64) int {
	return f.h.Add(seq, []byte(s), ts, 1)
}

func TestHalfStreamInOrder(t *testing.T) {
	f := newHalfFixture(1000, 0, 0)
	f.add(1000, "111", 0)
	f.add(1003, "222", 0)
	f.add(1006, "333", 0)
	if got := f.out.String(); got != "111222333" {
		t.Fatalf("out=%q", got)
	}
	if f.h.Next() != 9 {
		t.Fatalf("next=%d", f.h.Next())
	}
	if len(f.idx.Segments(model.C2S)) != 3 {
		t.Fatalf("segments=%d", len(f.idx.Segments(model.C2S)))
	}
}

func TestHalfStreamRetransmitIdentical(t *testing.T) {
	f := newHalfFixture(1000, 0, 0)
	f.add(1000, "111", 0)
	f.add(1000, "111", 0)
	if got := f.out.String(); got != "111" {
		t.Fatalf("out=%q", got)
	}
	if f.h.Retransmits != 1 || f.h.OverlapConflicts != 0 {
		t.Fatalf("retx=%d conflicts=%d", f.h.Retransmits, f.h.OverlapConflicts)
	}
}

func TestHalfStreamOverlapConflict(t *testing.T) {
	f := newHalfFixture(1000, 0, 0)
	f.add(1000, "AAAA", 0)
	f.add(1000, "BBBB", 0)
	if got := f.out.String(); got != "AAAA" {
		t.Fatalf("out=%q", got)
	}
	if f.h.OverlapConflicts != 1 {
		t.Fatalf("conflicts=%d", f.h.OverlapConflicts)
	}
	if len(f.anomaly) != 1 || f.anomaly[0].Kind != AnomalyOverlapConflict {
		t.Fatalf("anomaly=%+v", f.anomaly)
	}
}

func TestHalfStreamOutOfOrderFill(t *testing.T) {
	f := newHalfFixture(1000, 0, 0)
	if n := f.add(1006, "333", 0); n != 0 {
		t.Fatalf("pending add returned %d", n)
	}
	if n := f.add(1000, "111222", 0); n != 9 {
		t.Fatalf("fill add returned %d", n)
	}
	if got := f.out.String(); got != "111222333" {
		t.Fatalf("out=%q", got)
	}
	if f.h.Next() != 9 {
		t.Fatalf("next=%d", f.h.Next())
	}
}

func TestHalfStreamPartialOverlap(t *testing.T) {
	f := newHalfFixture(1000, 0, 0)
	f.add(1000, "111222", 0)
	f.add(1004, "223333", 0)
	if got := f.out.String(); got != "1112223333" {
		t.Fatalf("out=%q", got)
	}
}

func TestHalfStreamGapOnTimeout(t *testing.T) {
	f := newHalfFixture(1000, 0, time.Second)
	f.add(1003, "333", 0)
	if len(f.anomaly) != 0 {
		t.Fatalf("unexpected anomaly before timeout: %+v", f.anomaly)
	}
	f.add(1006, "666", 2*int64(time.Second))
	if got := f.out.String(); got != "333666" {
		t.Fatalf("out=%q", got)
	}
	gaps := f.idx.Gaps(model.C2S)
	if len(gaps) != 1 || gaps[0].Offset != 0 || gaps[0].Length != 3 {
		t.Fatalf("gaps=%+v", gaps)
	}
	if len(f.anomaly) != 1 || f.anomaly[0].Kind != AnomalyGap {
		t.Fatalf("anomaly=%+v", f.anomaly)
	}
}

func TestHalfStreamGapOnCap(t *testing.T) {
	f := newHalfFixture(1000, 4, 0)
	f.add(1003, "333", 0)
	f.add(1006, "666", 0)
	if got := f.out.String(); got != "333666" {
		t.Fatalf("out=%q", got)
	}
}

func TestHalfStreamFlush(t *testing.T) {
	f := newHalfFixture(1000, 0, 0)
	f.add(1003, "333", 0)
	f.h.Flush()
	if got := f.out.String(); got != "333" {
		t.Fatalf("out=%q", got)
	}
	gaps := f.idx.Gaps(model.C2S)
	if len(gaps) != 1 || gaps[0].Offset != 0 || gaps[0].Length != 3 {
		t.Fatalf("gaps=%+v", gaps)
	}
}

func TestHalfStreamWrap(t *testing.T) {
	f := newHalfFixture(0xFFFFFFF0, 0, 0)
	f.add(0xFFFFFFF0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0)
	f.add(0x00000010, "BBBB", 0)
	if got := f.out.String(); got != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB" {
		t.Fatalf("out=%q", got)
	}
}

func TestHalfStreamWrapOutOfOrder(t *testing.T) {
	f := newHalfFixture(0xFFFFFFF0, 0, 0)
	f.add(0x00000010, "BBBB", 0)
	f.add(0xFFFFFFF0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0)
	if got := f.out.String(); got != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB" {
		t.Fatalf("out=%q", got)
	}
}
