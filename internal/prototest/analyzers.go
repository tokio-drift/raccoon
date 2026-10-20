// Package prototest prepares capture fixtures for protocol analyzer tests.
package prototest

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/tokio-drift/raccoon/internal/capture"
	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/flow"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
	"github.com/tokio-drift/raccoon/internal/reassembly"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

// AnalyzerStream is one reassembled TCP flow prepared for an analyzer test.
type AnalyzerStream struct {
	Context *proto.StreamContext
	Flow    *flow.Flow
	Stream  *reassembly.Stream
	C2S     []byte
	S2C     []byte
}

// AnalyzerCapture holds the flows of a capture prepared for analyzer tests.
type AnalyzerCapture struct {
	Streams       []*AnalyzerStream
	DatagramFlows []*proto.StreamContext
}

// ReassembleForAnalyzers drives capture -> decode -> flow -> reassembly for a
// fixture and returns one context per TCP stream plus one datagram context per
// UDP flow, in first-seen order.
func ReassembleForAnalyzers(t *testing.T, name string) *AnalyzerCapture {
	t.Helper()
	rd, _, err := capture.Open(testutil.Pcap(t, name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer rd.Close()

	dec := decode.NewDecoder()
	tbl := flow.NewTable(nil)
	streams := map[int64]*reassembly.Stream{}
	flows := map[int64]*flow.Flow{}
	datagrams := map[int64][]proto.Datagram{}
	var order []int64
	caseDir := t.TempDir()

	for {
		raw, err := rd.Next()
		if err == io.EOF || err == capture.ErrTruncatedTail {
			break
		}
		if err != nil {
			t.Fatalf("%s: next: %v", name, err)
		}
		pkt, err := dec.Decode(raw)
		if err != nil {
			continue
		}
		f, dir, isNew := tbl.Lookup(pkt)
		if f == nil {
			continue
		}
		if isNew {
			flows[f.ID] = f
			order = append(order, f.ID)
		}
		if f.IsUDP() {
			payload := append([]byte(nil), pkt.Payload...)
			datagrams[f.ID] = append(datagrams[f.ID], proto.Datagram{
				TS:       pkt.TS,
				PacketNo: pkt.No,
				Dir:      dir,
				Payload:  payload,
			})
			continue
		}
		if isNew {
			spool, err := reassembly.NewSpool(filepath.Join(caseDir, "streams"), f.ID)
			if err != nil {
				t.Fatalf("%s: spool: %v", name, err)
			}
			streams[f.ID] = reassembly.NewStream(reassembly.StreamConfig{
				ID:        f.ID,
				Proto:     f.Proto,
				Spool:     spool,
				Midstream: f.Midstream,
			})
		}
		streams[f.ID].AddPacket(dir, pkt.Seq, pkt.TCPFlags, pkt.Payload, pkt.TS, pkt.No)
	}

	out := &AnalyzerCapture{}
	for _, id := range order {
		f := flows[id]
		meta := analyzerMeta(f)
		if f.IsUDP() {
			out.DatagramFlows = append(out.DatagramFlows, proto.NewDatagramContext(meta, datagrams[id]))
			continue
		}
		st := streams[id]
		if err := st.Close(); err != nil {
			t.Fatalf("%s: close stream %d: %v", name, id, err)
		}
		out.Streams = append(out.Streams, &AnalyzerStream{
			Context: proto.NewStreamContext(meta, st),
			Flow:    f,
			Stream:  st,
			C2S:     readAnalyzerDir(st, model.C2S),
			S2C:     readAnalyzerDir(st, model.S2C),
		})
	}
	return out
}

func analyzerMeta(f *flow.Flow) proto.StreamMeta {
	responder := f.Key.A
	if responder == f.Initiator {
		responder = f.Key.B
	}
	return proto.StreamMeta{
		ID:          f.ID,
		Proto:       f.Proto,
		SrcIP:       f.Initiator.IP.String(),
		DstIP:       responder.IP.String(),
		SrcPort:     f.Initiator.Port,
		DstPort:     responder.Port,
		StartTS:     f.StartTS,
		EndTS:       f.EndTS,
		FirstPacket: f.FirstPacket,
		LastPacket:  f.LastPacket,
	}
}

func readAnalyzerDir(st *reassembly.Stream, dir model.Direction) []byte {
	n := st.Len(dir)
	if n == 0 {
		return nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(io.NewSectionReader(st.ReaderAt(dir), 0, n), buf); err != nil {
		return buf
	}
	return buf
}
