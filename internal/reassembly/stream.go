package reassembly

import (
	"io"

	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
)

// Stream reassembles both directions of one TCP connection.
type Stream struct {
	ID    int64
	Proto string

	spool *Spool
	acc   Accountant

	c2s *HalfStream
	s2c *HalfStream

	midstream         bool
	midstreamReported bool

	finC2S bool
	finS2C bool
	closed bool
	lastTS int64

	onAnomaly AnomalyFunc
}

// StreamConfig configures a Stream.
type StreamConfig struct {
	ID         int64
	Proto      string
	Spool      *Spool
	Accountant Accountant
	Midstream  bool
	OnAnomaly  AnomalyFunc
}

// NewStream returns an empty Stream backed by spool.
func NewStream(cfg StreamConfig) *Stream {
	return &Stream{
		ID:        cfg.ID,
		Proto:     cfg.Proto,
		spool:     cfg.Spool,
		acc:       cfg.Accountant,
		midstream: cfg.Midstream,
		onAnomaly: cfg.OnAnomaly,
	}
}

// AddPacket feeds one TCP packet. flags uses the decode.Flag* bits. It returns
// the number of newly delivered bytes.
func (s *Stream) AddPacket(dir model.Direction, seq uint32, flags uint8, payload []byte, ts int64, pktNo uint64) int {
	if s.closed {
		return 0
	}
	s.lastTS = ts

	if s.midstream && !s.midstreamReported {
		s.midstreamReported = true
		if s.onAnomaly != nil {
			s.onAnomaly(Anomaly{Kind: AnomalyMidstream, Dir: dir})
		}
	}

	h := s.half(dir)
	addSeq := seq
	if h == nil {
		syn := flags&decode.FlagSYN != 0
		if syn {
			addSeq = seq + 1
		}
		h = s.initHalf(dir, seq, syn)
	}

	n := 0
	if len(payload) > 0 {
		n = h.Add(addSeq, payload, ts, pktNo)
	}

	if flags&decode.FlagFIN != 0 {
		s.markFin(dir)
	}
	if flags&decode.FlagRST != 0 {
		s.finC2S, s.finS2C = true, true
	}
	if s.finC2S && s.finS2C {
		_ = s.Close()
	}
	return n
}

// Close flushes pending data, records remaining gaps and finalises the spool.
func (s *Stream) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.c2s != nil {
		s.c2s.Flush()
	}
	if s.s2c != nil {
		s.s2c.Flush()
	}
	return s.spool.Finalize()
}

// Closed reports whether the stream has been closed.
func (s *Stream) Closed() bool { return s.closed }

// Expire closes the stream if it has been idle longer than the flow idle
// timeout. It returns true if the stream was closed.
func (s *Stream) Expire(now int64) bool {
	if s.closed {
		return false
	}
	if now-s.lastTS <= limits.FlowIdleTimeout.Nanoseconds() {
		return false
	}
	_ = s.Close()
	return true
}

// Spool returns the underlying spool.
func (s *Stream) Spool() *Spool { return s.spool }

// ReaderAt returns a reader over delivered bytes for a direction.
func (s *Stream) ReaderAt(dir model.Direction) io.ReaderAt { return s.spool.ReaderAt(dir) }

// Len returns the number of delivered bytes for a direction.
func (s *Stream) Len(dir model.Direction) int64 { return s.spool.Len(dir) }

// Segments returns the segments for a direction.
func (s *Stream) Segments(dir model.Direction) []Segment { return s.spool.Segments(dir) }

// Gaps returns the gaps for a direction.
func (s *Stream) Gaps(dir model.Direction) []Gap { return s.spool.Gaps(dir) }

func (s *Stream) half(dir model.Direction) *HalfStream {
	if dir == model.S2C {
		return s.s2c
	}
	return s.c2s
}

func (s *Stream) initHalf(dir model.Direction, seq uint32, syn bool) *HalfStream {
	base := seq
	if syn {
		base = seq + 1
	}
	h := NewHalfStream(HalfStreamConfig{
		Dir:        dir,
		Base:       base,
		Writer:     s.spool.Writer(dir),
		Index:      s.spool.Index(),
		Accountant: s.acc,
		OnAnomaly:  s.onAnomaly,
	})
	if dir == model.S2C {
		s.s2c = h
	} else {
		s.c2s = h
	}
	return h
}

func (s *Stream) markFin(dir model.Direction) {
	if dir == model.S2C {
		s.finS2C = true
	} else {
		s.finC2S = true
	}
}
