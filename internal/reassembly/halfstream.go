package reassembly

import (
	"io"
	"sort"
	"time"

	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
)

// recentWindow is how many recently delivered bytes are kept in memory to
// detect overlapping retransmissions that carry different data.
const recentWindow = 1 << 16

// Accountant tracks reassembly memory. It is satisfied by the Phase 5
// resource.Accountant.
type Accountant interface {
	Reserve(n int64) bool
	Release(n int64)
}

// NoopAccountant is an Accountant that never refuses a reservation.
type NoopAccountant struct{}

// Reserve always succeeds.
func (NoopAccountant) Reserve(int64) bool { return true }

// Release does nothing.
func (NoopAccountant) Release(int64) {}

// HalfStream reassembles one direction of a TCP stream. It is not safe for
// concurrent use.
type HalfStream struct {
	dir  model.Direction
	base uint32
	next uint64

	w   io.Writer
	idx *SegmentIndex
	acc Accountant

	pending      []pendingSeg
	pendingBytes int64
	maxPending   int64
	holeActive   bool
	holeSince    int64
	holeTimeout  int64
	accExceeded  bool

	recent      []byte // fixed recentWindow backing, lazily allocated
	recentLen   int
	recentPos   int
	recentStart uint64

	// OverlapConflicts counts retransmissions whose bytes differ from data
	// already delivered.
	OverlapConflicts int64
	// Retransmits counts segments dropped because they were already delivered.
	Retransmits int64

	onAnomaly AnomalyFunc
	err       error
}

type pendingSeg struct {
	rel   uint64
	data  []byte
	ts    int64
	pktNo uint64
}

func (p pendingSeg) end() uint64 { return p.rel + uint64(len(p.data)) }

// HalfStreamConfig configures a HalfStream.
type HalfStreamConfig struct {
	Dir         model.Direction
	Base        uint32
	Writer      io.Writer
	Index       *SegmentIndex
	Accountant  Accountant
	MaxPending  int64
	HoleTimeout time.Duration
	OnAnomaly   AnomalyFunc
}

// NewHalfStream returns a HalfStream positioned at relative offset zero.
func NewHalfStream(cfg HalfStreamConfig) *HalfStream {
	acc := cfg.Accountant
	if acc == nil {
		acc = NoopAccountant{}
	}
	maxPending := cfg.MaxPending
	if maxPending <= 0 {
		maxPending = limits.PendingBufferPerDir
	}
	holeTimeout := cfg.HoleTimeout
	if holeTimeout <= 0 {
		holeTimeout = limits.HoleTimeout
	}
	return &HalfStream{
		dir:         cfg.Dir,
		base:        cfg.Base,
		w:           cfg.Writer,
		idx:         cfg.Index,
		acc:         acc,
		maxPending:  maxPending,
		holeTimeout: holeTimeout.Nanoseconds(),
		onAnomaly:   cfg.OnAnomaly,
	}
}

// Base returns the sequence number that maps to relative offset zero.
func (h *HalfStream) Base() uint32 { return h.base }

// Next returns the next expected relative offset.
func (h *HalfStream) Next() uint64 { return h.next }

// Err returns the first write error encountered, if any.
func (h *HalfStream) Err() error { return h.err }

// Add feeds one TCP segment payload. It returns the number of new bytes
// delivered to the output writer.
func (h *HalfStream) Add(seq uint32, payload []byte, ts int64, pktNo uint64) int {
	if len(payload) == 0 || h.err != nil {
		return 0
	}
	rel := Unwrap(seq, h.base, h.next)
	end := rel + uint64(len(payload))

	if end <= h.next {
		h.detectConflict(rel, payload)
		h.Retransmits++
		return 0
	}
	if rel < h.next {
		trim := h.next - rel
		h.detectConflict(rel, payload[:trim])
		payload = payload[trim:]
		rel = h.next
		end = rel + uint64(len(payload))
	}

	if rel == h.next {
		return h.deliver(payload, ts, pktNo) + h.drain()
	}

	// rel > h.next: there is a hole before this segment.
	h.pendingInsert(rel, payload, ts, pktNo)
	if !h.holeActive {
		h.holeActive = true
		h.holeSince = ts
	}
	if h.pendingBytes > h.maxPending || h.accExceeded ||
		(h.holeTimeout > 0 && ts-h.holeSince > h.holeTimeout) {
		return h.jumpGap()
	}
	return 0
}

// Flush delivers any remaining out-of-order data, recording gaps, and is called
// when the stream closes.
func (h *HalfStream) Flush() {
	h.trimPendingBeforeNext()
	for len(h.pending) > 0 {
		first := h.pending[0].rel
		if first > h.next {
			h.recordGap(first - h.next)
			h.next = first
		}
		seg := h.pending[0]
		h.pending = h.pending[1:]
		h.releasePending(int64(len(seg.data)))
		h.deliver(seg.data, seg.ts, seg.pktNo)
		h.trimPendingBeforeNext()
	}
	h.pendingBytes = 0
	h.holeActive = false
}

// deliver writes payload at h.next and advances the stream.
func (h *HalfStream) deliver(payload []byte, ts int64, pktNo uint64) int {
	off := h.next
	n, err := h.w.Write(payload)
	if err != nil {
		h.err = err
		return 0
	}
	h.next += uint64(n)
	if h.idx != nil {
		_ = h.idx.Add(Segment{
			Dir:       h.dir,
			StreamOff: int64(off),
			Length:    uint32(n),
			TS:        ts,
			PacketNo:  pktNo,
		})
	}
	h.pushRecent(payload[:n])
	return n
}

// drain delivers pending data that is now contiguous with h.next.
func (h *HalfStream) drain() int {
	h.trimPendingBeforeNext()
	total := 0
	for len(h.pending) > 0 && h.pending[0].rel == h.next {
		seg := h.pending[0]
		h.pending = h.pending[1:]
		h.releasePending(int64(len(seg.data)))
		total += h.deliver(seg.data, seg.ts, seg.pktNo)
	}
	if len(h.pending) == 0 {
		h.holeActive = false
	}
	return total
}

// trimPendingBeforeNext drops pending bytes that are already delivered (offsets
// below h.next), trimming a straddling segment to start at h.next.
func (h *HalfStream) trimPendingBeforeNext() {
	for len(h.pending) > 0 && h.pending[0].end() <= h.next {
		seg := h.pending[0]
		h.pending = h.pending[1:]
		h.releasePending(int64(len(seg.data)))
	}
	if len(h.pending) > 0 && h.pending[0].rel < h.next {
		drop := h.next - h.pending[0].rel
		h.releasePending(int64(drop))
		h.pending[0].data = h.pending[0].data[drop:]
		h.pending[0].rel = h.next
	}
}

// jumpGap gives up on the current hole, records it and delivers the pending
// data that follows.
func (h *HalfStream) jumpGap() int {
	h.trimPendingBeforeNext()
	if len(h.pending) == 0 {
		return 0
	}
	first := h.pending[0].rel
	if first > h.next {
		h.recordGap(first - h.next)
		h.next = first
	}
	return h.drain()
}

func (h *HalfStream) recordGap(length uint64) {
	if h.idx != nil {
		h.idx.AddGap(h.dir, Gap{Offset: int64(h.next), Length: int64(length)})
	}
	if h.onAnomaly != nil {
		h.onAnomaly(Anomaly{
			Kind:   AnomalyGap,
			Dir:    h.dir,
			Offset: int64(h.next),
			Length: int64(length),
		})
	}
}

// pendingInsert stores out-of-order bytes, filling only holes not already
// buffered (existing bytes win). It returns the number of bytes added.
func (h *HalfStream) pendingInsert(rel uint64, data []byte, ts int64, pktNo uint64) int64 {
	start := rel
	end := rel + uint64(len(data))
	var added int64
	cur := start
	i := 0
	for i < len(h.pending) && h.pending[i].end() <= cur {
		i++
	}
	for cur < end {
		if i >= len(h.pending) || h.pending[i].rel >= end {
			hi := end
			h.insertSeg(pendingSeg{
				rel:   cur,
				data:  cloneBytes(data[cur-start : hi-start]),
				ts:    ts,
				pktNo: pktNo,
			})
			added += int64(hi - cur)
			break
		}
		seg := h.pending[i]
		if seg.rel > cur {
			hi := seg.rel
			if hi > end {
				hi = end
			}
			h.insertSeg(pendingSeg{
				rel:   cur,
				data:  cloneBytes(data[cur-start : hi-start]),
				ts:    ts,
				pktNo: pktNo,
			})
			added += int64(hi - cur)
			cur = hi
			if cur >= end {
				break
			}
		}
		if seg.end() > cur {
			cur = seg.end()
		}
		i++
	}
	return added
}

func (h *HalfStream) insertSeg(s pendingSeg) {
	if !h.acc.Reserve(int64(len(s.data))) {
		h.accExceeded = true
	}
	h.pendingBytes += int64(len(s.data))
	idx := sort.Search(len(h.pending), func(i int) bool { return h.pending[i].rel >= s.rel })
	h.pending = append(h.pending, pendingSeg{})
	copy(h.pending[idx+1:], h.pending[idx:])
	h.pending[idx] = s
}

func (h *HalfStream) releasePending(n int64) {
	if n <= 0 {
		return
	}
	h.pendingBytes -= n
	h.acc.Release(n)
}

// detectConflict compares an already-delivered range against the recent window
// and flags a conflict if any byte differs.
func (h *HalfStream) detectConflict(rel uint64, payload []byte) {
	if h.recentLen == 0 || len(payload) == 0 {
		return
	}
	recentEnd := h.recentStart + uint64(h.recentLen)
	if rel >= recentEnd || rel+uint64(len(payload)) <= h.recentStart {
		return
	}
	for i := range payload {
		off := rel + uint64(i)
		if off < h.recentStart {
			continue
		}
		j := off - h.recentStart
		if j >= uint64(h.recentLen) {
			break
		}
		if h.recent[(h.recentPos+int(j))%recentWindow] != payload[i] {
			h.OverlapConflicts++
			if h.onAnomaly != nil {
				h.onAnomaly(Anomaly{
					Kind:   AnomalyOverlapConflict,
					Dir:    h.dir,
					Offset: int64(off),
				})
			}
			return
		}
	}
}

// pushRecent records the recently delivered window of bytes in a fixed-size
// ring so overlap detection stays cheap.
func (h *HalfStream) pushRecent(b []byte) {
	if h.recent == nil {
		h.recent = make([]byte, recentWindow)
	}
	if len(b) >= recentWindow {
		h.recentStart = h.next - recentWindow
		h.recentPos = 0
		h.recentLen = recentWindow
		copy(h.recent, b[len(b)-recentWindow:])
		return
	}
	start := (h.recentPos + h.recentLen) % recentWindow
	first := recentWindow - start
	if first > len(b) {
		first = len(b)
	}
	copy(h.recent[start:start+first], b[:first])
	if rest := len(b) - first; rest > 0 {
		copy(h.recent[:rest], b[first:])
	}
	h.recentLen += len(b)
	if h.recentLen > recentWindow {
		drop := h.recentLen - recentWindow
		h.recentPos = (h.recentPos + drop) % recentWindow
		h.recentLen = recentWindow
	}
	h.recentStart = h.next - uint64(h.recentLen)
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
