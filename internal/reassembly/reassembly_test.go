package reassembly

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/capture"
	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/flow"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

// expStream mirrors the stream entry of testdata/expected/*.json.
type expStream struct {
	Proto     string `json:"proto"`
	SrcIP     string `json:"srcIp"`
	SrcPort   uint16 `json:"srcPort"`
	DstIP     string `json:"dstIp"`
	DstPort   uint16 `json:"dstPort"`
	C2SBytes  int    `json:"c2sBytes"`
	S2CBytes  int    `json:"s2cBytes"`
	C2SSHA256 string `json:"c2sSha256"`
	S2CSHA256 string `json:"s2cSha256"`
	Midstream bool   `json:"midstream"`
	HasGaps   bool   `json:"hasGaps"`
}

type expDoc struct {
	Name    string      `json:"name"`
	Packets int         `json:"packets"`
	Streams []expStream `json:"streams"`
}

type reassembled struct {
	flow    *flow.Flow
	c2s     []byte
	s2c     []byte
	gapsC2S []Gap
	gapsS2C []Gap
}

// runReassembly drives capture -> decode -> flow -> reassembly for a fixture.
func runReassembly(t *testing.T, name string) ([]reassembled, []Anomaly) {
	t.Helper()
	rd, _, err := capture.Open(testutil.Pcap(t, name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer rd.Close()

	dec := decode.NewDecoder()
	tbl := flow.NewTable(nil)
	streams := map[int64]*Stream{}
	flows := map[int64]*flow.Flow{}
	var order []int64
	var anomalies []Anomaly
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
			spool, err := NewSpool(filepath.Join(caseDir, "streams"), f.ID)
			if err != nil {
				t.Fatalf("%s: spool: %v", name, err)
			}
			streams[f.ID] = NewStream(StreamConfig{
				ID:        f.ID,
				Proto:     f.Proto,
				Spool:     spool,
				Midstream: f.Midstream,
				OnAnomaly: func(a Anomaly) { anomalies = append(anomalies, a) },
			})
			flows[f.ID] = f
			order = append(order, f.ID)
		}
		streams[f.ID].AddPacket(dir, pkt.Seq, pkt.TCPFlags, pkt.Payload, pkt.TS, pkt.No)
		if f.State == flow.StateClosed {
			if err := streams[f.ID].Close(); err != nil {
				t.Fatalf("%s: close stream %d: %v", name, f.ID, err)
			}
		}
	}

	out := make([]reassembled, 0, len(order))
	for _, id := range order {
		st := streams[id]
		if err := st.Close(); err != nil {
			t.Fatalf("%s: final close %d: %v", name, id, err)
		}
		out = append(out, reassembled{
			flow:    flows[id],
			c2s:     readDir(t, st, model.C2S),
			s2c:     readDir(t, st, model.S2C),
			gapsC2S: st.Gaps(model.C2S),
			gapsS2C: st.Gaps(model.S2C),
		})
	}
	return out, anomalies
}

func readDir(t *testing.T, st *Stream, dir model.Direction) []byte {
	t.Helper()
	n := st.Len(dir)
	buf := make([]byte, n)
	if n > 0 {
		if _, err := st.ReaderAt(dir).ReadAt(buf, 0); err != nil && err != io.EOF {
			t.Fatalf("read stream %d dir %d: %v", st.ID, dir, err)
		}
	}
	return buf
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestReassemblyFixtures(t *testing.T) {
	fixtures := []string{
		"tcp_basic.pcap",
		"tcp_ooo.pcap",
		"tcp_retrans.pcap",
		"tcp_overlap_conflict.pcap",
		"tcp_wrap.pcap",
		"tcp_gap.pcap",
		"tcp_midstream.pcap",
		"tcp_portreuse.pcap",
		"pcapng_basic.pcapng",
		"truncated_tail.pcap",
	}
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			var exp expDoc
			testutil.LoadExpected(t, strings.TrimSuffix(name, filepath.Ext(name))+".json", &exp)
			got, _ := runReassembly(t, name)

			if len(got) != len(exp.Streams) {
				t.Fatalf("streams=%d want %d", len(got), len(exp.Streams))
			}
			for i, e := range exp.Streams {
				g := got[i]
				if g.flow.Proto != e.Proto {
					t.Errorf("stream %d proto=%q want %q", i, g.flow.Proto, e.Proto)
				}
				if g.flow.Initiator.IP.String() != e.SrcIP || uint16(g.flow.Initiator.Port) != e.SrcPort {
					t.Errorf("stream %d initiator=%v:%d want %s:%d", i, g.flow.Initiator.IP, g.flow.Initiator.Port, e.SrcIP, e.SrcPort)
				}
				if len(g.c2s) != e.C2SBytes {
					t.Errorf("stream %d c2s bytes=%d want %d", i, len(g.c2s), e.C2SBytes)
				}
				if len(g.s2c) != e.S2CBytes {
					t.Errorf("stream %d s2c bytes=%d want %d", i, len(g.s2c), e.S2CBytes)
				}
				if sha256hex(g.c2s) != e.C2SSHA256 {
					t.Errorf("stream %d c2s sha=%s want %s", i, sha256hex(g.c2s), e.C2SSHA256)
				}
				if sha256hex(g.s2c) != e.S2CSHA256 {
					t.Errorf("stream %d s2c sha=%s want %s", i, sha256hex(g.s2c), e.S2CSHA256)
				}
				if (len(g.gapsC2S)+len(g.gapsS2C) > 0) != e.HasGaps {
					t.Errorf("stream %d hasGaps=%v want %v", i, len(g.gapsC2S)+len(g.gapsS2C) > 0, e.HasGaps)
				}
			}
		})
	}
}

func TestReassemblyGapFixture(t *testing.T) {
	got, anomalies := runReassembly(t, "tcp_gap.pcap")
	if len(got) != 1 {
		t.Fatalf("streams=%d", len(got))
	}
	if len(got[0].gapsC2S) != 0 {
		t.Fatalf("unexpected c2s gaps: %+v", got[0].gapsC2S)
	}
	if len(got[0].gapsS2C) != 1 {
		t.Fatalf("s2c gaps=%+v want exactly one", got[0].gapsS2C)
	}
	g := got[0].gapsS2C[0]
	if g.Offset != 3 || g.Length != 3 {
		t.Fatalf("s2c gap=%+v want {3 3}", g)
	}
	if countKind(anomalies, AnomalyGap) != 1 {
		t.Fatalf("gap anomalies=%d want 1", countKind(anomalies, AnomalyGap))
	}
	if string(got[0].s2c) != "111333" {
		t.Fatalf("s2c=%q", got[0].s2c)
	}
}

func TestReassemblyOverlapConflict(t *testing.T) {
	got, anomalies := runReassembly(t, "tcp_overlap_conflict.pcap")
	if len(got) != 1 {
		t.Fatalf("streams=%d", len(got))
	}
	if string(got[0].s2c) != "AAAACCCC" {
		t.Fatalf("s2c=%q", got[0].s2c)
	}
	if countKind(anomalies, AnomalyOverlapConflict) != 1 {
		t.Fatalf("overlap conflicts=%d want 1 (%+v)", countKind(anomalies, AnomalyOverlapConflict), anomalies)
	}
}

func TestReassemblyMidstreamAnomaly(t *testing.T) {
	_, anomalies := runReassembly(t, "tcp_midstream.pcap")
	if countKind(anomalies, AnomalyMidstream) != 1 {
		t.Fatalf("midstream anomalies=%d want 1", countKind(anomalies, AnomalyMidstream))
	}
}

func countKind(a []Anomaly, k AnomalyKind) int {
	n := 0
	for _, x := range a {
		if x.Kind == k {
			n++
		}
	}
	return n
}

func BenchmarkReassemblyInOrder(b *testing.B) {
	const seg = 1460
	payload := bytes.Repeat([]byte{0xAB}, seg)
	const iters = 4096
	b.SetBytes(int64(seg) * iters)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := NewHalfStream(HalfStreamConfig{
			Dir:    model.C2S,
			Base:   1000,
			Writer: io.Discard,
			Index:  NewSegmentIndex(nil),
		})
		seq := uint32(1000)
		for j := 0; j < iters; j++ {
			h.Add(seq, payload, 0, 1)
			seq += seg
		}
	}
}

func TestReassemblyThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput test skipped in -short mode")
	}
	const seg = 1460
	const total = int64(256 << 20)
	payload := bytes.Repeat([]byte{0xAB}, seg)

	h := NewHalfStream(HalfStreamConfig{
		Dir:    model.C2S,
		Base:   1000,
		Writer: io.Discard,
		Index:  NewSegmentIndex(nil),
	})
	seq := uint32(1000)
	var written int64
	start := time.Now()
	for written < total {
		written += int64(h.Add(seq, payload, 0, 1))
		seq += seg
	}
	elapsed := time.Since(start)
	mbps := float64(written) / elapsed.Seconds() / 1e6
	if mbps < 200 {
		t.Fatalf("reassembly throughput %.1f MB/s < 200 MB/s", mbps)
	}
	t.Logf("reassembly throughput %.1f MB/s", mbps)
}
