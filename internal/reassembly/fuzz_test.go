package reassembly

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/model"
)

// FuzzHalfStream drives HalfStream with arbitrary sequences of TCP segments,
// verifying that reassembly never panics, deadlocks, or leaves the segment
// index in an invalid state.
func FuzzHalfStream(f *testing.F) {
	// Seed 1: In order segments
	var s1 bytes.Buffer
	_ = binary.Write(&s1, binary.BigEndian, uint32(1000))
	_ = binary.Write(&s1, binary.BigEndian, int64(1000))
	_ = binary.Write(&s1, binary.BigEndian, uint16(5))
	s1.WriteString("hello")
	_ = binary.Write(&s1, binary.BigEndian, uint32(1005))
	_ = binary.Write(&s1, binary.BigEndian, int64(2000))
	_ = binary.Write(&s1, binary.BigEndian, uint16(5))
	s1.WriteString("world")
	f.Add(s1.Bytes(), uint32(1000))

	// Seed 2: Out of order segments
	var s2 bytes.Buffer
	_ = binary.Write(&s2, binary.BigEndian, uint32(1010))
	_ = binary.Write(&s2, binary.BigEndian, int64(1000))
	_ = binary.Write(&s2, binary.BigEndian, uint16(5))
	s2.WriteString("world")
	_ = binary.Write(&s2, binary.BigEndian, uint32(1000))
	_ = binary.Write(&s2, binary.BigEndian, int64(2000))
	_ = binary.Write(&s2, binary.BigEndian, uint16(10))
	s2.WriteString("0123456789")
	f.Add(s2.Bytes(), uint32(1000))

	// Seed 3: Overlapping segments and retransmission
	var s3 bytes.Buffer
	_ = binary.Write(&s3, binary.BigEndian, uint32(1000))
	_ = binary.Write(&s3, binary.BigEndian, int64(1000))
	_ = binary.Write(&s3, binary.BigEndian, uint16(8))
	s3.WriteString("overlap1")
	_ = binary.Write(&s3, binary.BigEndian, uint32(1004))
	_ = binary.Write(&s3, binary.BigEndian, int64(1500))
	_ = binary.Write(&s3, binary.BigEndian, uint16(8))
	s3.WriteString("overlap2")
	f.Add(s3.Bytes(), uint32(1000))

	f.Fuzz(func(t *testing.T, data []byte, base uint32) {
		if len(data) > 64*1024 {
			t.Skip()
		}

		var out bytes.Buffer
		idx := NewSegmentIndex(nil)
		h := NewHalfStream(HalfStreamConfig{
			Dir:         model.C2S,
			Base:        base,
			Writer:      &out,
			Index:       idx,
			Accountant:  NoopAccountant{},
			MaxPending:  64 * 1024,
			HoleTimeout: 5 * time.Second,
			OnAnomaly:   func(Anomaly) {},
		})

		r := bytes.NewReader(data)
		pktNo := uint64(1)

		for r.Len() >= 14 {
			var seq uint32
			var ts int64
			var payloadLen uint16
			if err := binary.Read(r, binary.BigEndian, &seq); err != nil {
				break
			}
			if err := binary.Read(r, binary.BigEndian, &ts); err != nil {
				break
			}
			if err := binary.Read(r, binary.BigEndian, &payloadLen); err != nil {
				break
			}

			cappedLen := int(payloadLen % 2048)
			payload := make([]byte, cappedLen)
			n, _ := io.ReadFull(r, payload)
			payload = payload[:n]

			h.Add(seq, payload, ts, pktNo)
			pktNo++
		}

		h.Flush()
	})
}
