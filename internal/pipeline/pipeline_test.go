package pipeline

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/resource"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

func TestRunBasic(t *testing.T) {
	pcapPath := testutil.Pcap(t, "tcp_basic.pcap")
	caseBase := t.TempDir()

	res, err := Run(context.Background(), Options{
		PCAPPath: pcapPath,
		BaseDir:  caseBase,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.Packets == 0 {
		t.Errorf("expected packets > 0, got %d", res.Packets)
	}
	if res.Streams != 1 {
		t.Errorf("expected 1 stream, got %d", res.Streams)
	}
	if res.PcapSHA256 == "" {
		t.Error("expected non-empty PcapSHA256")
	}
	if res.PcapSize == 0 {
		t.Error("expected non-zero PcapSize")
	}

	// Verify database content.
	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("open case db: %v", err)
	}
	defer db.Close()

	streams, _, err := db.Streams(store.StreamFilter{})
	if err != nil {
		t.Fatalf("query streams: %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("expected 1 stream in DB, got %d", len(streams))
	}
	st := streams[0]
	if st.Proto != "tcp" {
		t.Errorf("stream proto = %s, want tcp", st.Proto)
	}
	if st.HasGaps {
		t.Errorf("stream has gaps = %v, want false", st.HasGaps)
	}
	if st.Midstream {
		t.Errorf("stream midstream = %v, want false", st.Midstream)
	}

	// Verify segments.
	segsC2S, err := db.SegmentsFor(st.ID, model.C2S)
	if err != nil {
		t.Fatalf("query segments C2S: %v", err)
	}
	segsS2C, err := db.SegmentsFor(st.ID, model.S2C)
	if err != nil {
		t.Fatalf("query segments S2C: %v", err)
	}
	if len(segsC2S)+len(segsS2C) == 0 {
		t.Error("expected segments in DB, got 0")
	}

	// Verify metadata.
	meta, err := db.Meta()
	if err != nil {
		t.Fatalf("query meta: %v", err)
	}
	if meta["pcap_name"] != "tcp_basic.pcap" {
		t.Errorf("meta pcap_name = %q, want tcp_basic.pcap", meta["pcap_name"])
	}
	if meta["pcap_sha256"] != res.PcapSHA256 {
		t.Errorf("meta pcap_sha256 = %q, want %q", meta["pcap_sha256"], res.PcapSHA256)
	}
}

func TestRunWorkers(t *testing.T) {
	pcapPath := testutil.Pcap(t, "tcp_basic.pcap")

	for _, workers := range []int{1, 2, 4} {
		t.Run("workers_"+string(rune('0'+workers)), func(t *testing.T) {
			b, err := resource.NewBudget(256*1024*1024, 0, workers)
			if err != nil {
				t.Fatalf("NewBudget: %v", err)
			}

			res, err := Run(context.Background(), Options{
				PCAPPath: pcapPath,
				BaseDir:  t.TempDir(),
				Budget:   b,
			})
			if err != nil {
				t.Fatalf("Run with %d workers failed: %v", workers, err)
			}
			if res.Streams != 1 {
				t.Errorf("workers=%d: streams = %d, want 1", workers, res.Streams)
			}
		})
	}
}

func TestRunGap(t *testing.T) {
	pcapPath := testutil.Pcap(t, "tcp_gap.pcap")

	res, err := Run(context.Background(), Options{
		PCAPPath: pcapPath,
		BaseDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	streams, _, err := db.Streams(store.StreamFilter{})
	if err != nil {
		t.Fatalf("query streams: %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(streams))
	}
	if !streams[0].HasGaps {
		t.Error("expected HasGaps = true for tcp_gap.pcap")
	}

	// Verify EvTCPAnomaly event.
	events, _, err := db.Events(store.EventFilter{Types: []model.EventType{model.EvTCPAnomaly}})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) == 0 {
		t.Error("expected TCP anomaly event, got 0")
	}
}

func TestRunCancel(t *testing.T) {
	pcapPath := testutil.Pcap(t, "tcp_basic.pcap")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := Run(ctx, Options{
		PCAPPath: pcapPath,
		BaseDir:  t.TempDir(),
	})
	if err == nil {
		t.Error("expected error on cancelled context, got nil")
	}
}

func TestRunProgressAndHooks(t *testing.T) {
	pcapPath := testutil.Pcap(t, "tcp_basic.pcap")
	prog := NewProgress()

	var hookCalled bool
	var progressSnapshots []ProgressSnapshot

	res, err := Run(context.Background(), Options{
		PCAPPath: pcapPath,
		BaseDir:  t.TempDir(),
		Progress: prog,
		OnProgress: func(s ProgressSnapshot) {
			progressSnapshots = append(progressSnapshots, s)
		},
		Hooks: Hooks{
			AnalyzeStream: func(ctx context.Context, cs *ClosedStream) error {
				hookCalled = true
				if cs.Flow == nil {
					t.Error("expected cs.Flow to be non-nil")
				}
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !hookCalled {
		t.Error("expected AnalyzeStream hook to be called")
	}
	if prog.Stage() != "done" {
		t.Errorf("final progress stage = %q, want done", prog.Stage())
	}
	if len(progressSnapshots) == 0 {
		t.Error("expected progress snapshots to be recorded")
	}
	if res.Duration <= 0 {
		t.Errorf("expected positive duration, got %v", res.Duration)
	}
}

func generateUDPPCAP(t *testing.T, count int) string {
	t.Helper()
	pcapFile := filepath.Join(t.TempDir(), "udp_flows.pcap")
	f, err := os.Create(pcapFile)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()

	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	for i := 0; i < count; i++ {
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IPv4(10, 0, byte(i/256), byte(i%256)),
			DstIP:    net.IPv4(10, 1, 0, 1),
		}
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(10000 + (i % 50000)),
			DstPort: 53,
		}
		_ = udp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, udp, gopacket.Payload([]byte("udp-payload")))
		data := buf.Bytes()
		err := pw.WritePacket(gopacket.CaptureInfo{
			Timestamp:     ts.Add(time.Duration(i) * time.Millisecond),
			CaptureLength: len(data),
			Length:        len(data),
		}, data)
		if err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}
	return pcapFile
}

func TestHookError300UDPFlowsWithin5s(t *testing.T) {
	pcapPath := generateUDPPCAP(t, 300)
	budget, err := resource.NewBudget(256*1024*1024, 0, 1)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}

	hookErr := errors.New("hook intentional failure")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err = Run(ctx, Options{
		PCAPPath: pcapPath,
		BaseDir:  t.TempDir(),
		Budget:   budget,
		Hooks: Hooks{
			AnalyzeStream: func(ctx context.Context, cs *ClosedStream) error {
				return hookErr
			},
		},
	})

	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("Run took %v, want <= 5s", elapsed)
	}
	if !errors.Is(err, hookErr) {
		t.Fatalf("Run error = %v, want %v", err, hookErr)
	}
}

func TestContextCancelledMidRunWithin5s(t *testing.T) {
	pcapPath := generateUDPPCAP(t, 300)
	budget, err := resource.NewBudget(256*1024*1024, 0, 2)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runCtx, runCancel := context.WithCancel(ctx)

	start := time.Now()
	_, err = Run(runCtx, Options{
		PCAPPath: pcapPath,
		BaseDir:  t.TempDir(),
		Budget:   budget,
		Hooks: Hooks{
			AnalyzeStream: func(ctx context.Context, cs *ClosedStream) error {
				runCancel()
				return nil
			},
		},
	})

	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("Run took %v, want <= 5s", elapsed)
	}
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
}

func TestSpoolFailureReadOnlyStreamsDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping read-only streams dir test when running as root")
	}

	pcapPath := testutil.Pcap(t, "tcp_basic.pcap")
	baseDir := t.TempDir()

	c, err := casedir.Create(baseDir, casedir.Options{PCAP: pcapPath})
	if err != nil {
		t.Fatalf("casedir.Create: %v", err)
	}

	streamsDir := c.StreamsDir()
	if err := os.Chmod(streamsDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(streamsDir, 0o700)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err = Run(ctx, Options{
		PCAPPath: pcapPath,
		Case:     c,
	})
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("Run took %v, want <= 5s", elapsed)
	}
	if err == nil {
		t.Fatal("expected error from spool failure, got nil")
	}
}

func TestOnProgressContract(t *testing.T) {
	pcapPath := testutil.Pcap(t, "tcp_basic.pcap")
	prog := NewProgress()

	var inCallback atomic.Int32
	var maxConcurrent atomic.Int32
	var snapshots []ProgressSnapshot
	var mu sync.Mutex

	res, err := Run(context.Background(), Options{
		PCAPPath: pcapPath,
		BaseDir:  t.TempDir(),
		Progress: prog,
		OnProgress: func(s ProgressSnapshot) {
			cur := inCallback.Add(1)
			defer inCallback.Add(-1)
			if cur > 1 {
				maxConcurrent.Store(cur)
			}
			time.Sleep(2 * time.Millisecond)

			mu.Lock()
			snapshots = append(snapshots, s)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}

	// (a) OnProgress is never called concurrently
	if mc := maxConcurrent.Load(); mc > 1 {
		t.Errorf("OnProgress called concurrently: max concurrency was %d, want 1", mc)
	}

	// (b) the last snapshot has stage "done"
	if len(snapshots) == 0 {
		t.Fatal("expected at least one snapshot, got 0")
	}
	last := snapshots[len(snapshots)-1]
	if last.Stage != "done" {
		t.Errorf("last snapshot stage = %q, want %q", last.Stage, "done")
	}

	// (c) packet and byte counts never decrease between snapshots
	for i := 1; i < len(snapshots); i++ {
		prev := snapshots[i-1]
		curr := snapshots[i]
		if curr.PacketsRead < prev.PacketsRead {
			t.Errorf("snapshot %d: packet count decreased from %d to %d", i, prev.PacketsRead, curr.PacketsRead)
		}
		if curr.BytesRead < prev.BytesRead {
			t.Errorf("snapshot %d: byte count decreased from %d to %d", i, prev.BytesRead, curr.BytesRead)
		}
	}
}

func TestSetMetaFailureReturnsError(t *testing.T) {
	pcapPath := testutil.Pcap(t, "tcp_basic.pcap")
	baseDir := t.TempDir()

	c, err := casedir.Create(baseDir, casedir.Options{PCAP: pcapPath})
	if err != nil {
		t.Fatalf("casedir.Create: %v", err)
	}

	db, err := store.Open(c.DB())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	// Drop the meta table so SetMeta fails when Run tries to insert metadata.
	if _, err := db.Conn().Exec("DROP TABLE meta;"); err != nil {
		t.Fatalf("drop meta table: %v", err)
	}

	res, err := Run(context.Background(), Options{
		PCAPPath: pcapPath,
		Case:     c,
		Store:    db,
	})
	if err == nil {
		t.Fatal("expected error from SetMeta failure, got nil")
	}
	if res != nil {
		t.Errorf("expected nil result on SetMeta failure, got %v", res)
	}
	if !strings.Contains(err.Error(), "set meta") {
		t.Errorf("expected error mentioning 'set meta', got: %v", err)
	}
}

func TestTCPPortReuseEmitsBothStreams(t *testing.T) {
	pcapFile := filepath.Join(t.TempDir(), "tcp_port_reuse.pcap")
	f, err := os.Create(pcapFile)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}

	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write header: %v", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    net.ParseIP("192.168.1.10").To4(),
		DstIP:    net.ParseIP("192.168.1.20").To4(),
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}

	writeTCPPacket := func(ts time.Time, seq uint32, ack uint32, syn, ackFlag, fin bool, payload []byte) {
		tcp := &layers.TCP{
			SrcPort: 40001,
			DstPort: 80,
			Seq:     seq,
			Ack:     ack,
			SYN:     syn,
			ACK:     ackFlag,
			FIN:     fin,
			Window:  65535,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		var pLayer gopacket.SerializableLayer
		if len(payload) > 0 {
			pLayer = gopacket.Payload(payload)
			_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, tcp, pLayer)
		} else {
			_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, tcp)
		}
		data := buf.Bytes()
		err := pw.WritePacket(gopacket.CaptureInfo{
			Timestamp:     ts,
			CaptureLength: len(data),
			Length:        len(data),
		}, data)
		if err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// 1. SYN
	writeTCPPacket(t0, 1000, 0, true, false, false, nil)
	// 2. Data
	writeTCPPacket(t0.Add(10*time.Millisecond), 1001, 0, false, true, false, []byte("hello stream 1"))
	// 3. FIN from one side only
	writeTCPPacket(t0.Add(20*time.Millisecond), 1015, 0, false, true, true, nil)
	// 4. Pure SYN with same 4-tuple and new ISN
	writeTCPPacket(t0.Add(30*time.Millisecond), 50000, 0, true, false, false, nil)

	if err := f.Close(); err != nil {
		t.Fatalf("close pcap: %v", err)
	}

	baseDir := t.TempDir()
	res, err := Run(context.Background(), Options{
		PCAPPath: pcapFile,
		BaseDir:  baseDir,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	streams, _, err := db.Streams(store.StreamFilter{})
	if err != nil {
		t.Fatalf("query streams: %v", err)
	}
	if len(streams) != 2 {
		t.Fatalf("expected 2 stream rows in DB, got %d", len(streams))
	}
}

func TestRun300UDPFlows(t *testing.T) {
	pcapPath := generateUDPPCAP(t, 300)
	baseDir := t.TempDir()

	res, err := Run(context.Background(), Options{
		PCAPPath: pcapPath,
		BaseDir:  baseDir,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.Streams != 300 {
		t.Errorf("res.Streams = %d, want 300", res.Streams)
	}

	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	streams, _, err := db.Streams(store.StreamFilter{Limit: 1000})
	if err != nil {
		t.Fatalf("query streams: %v", err)
	}
	if len(streams) != 300 {
		t.Fatalf("expected 300 stream rows in DB, got %d", len(streams))
	}

	for _, st := range streams {
		segsC2S, err := db.SegmentsFor(st.ID, model.C2S)
		if err != nil {
			t.Fatalf("query segments C2S: %v", err)
		}
		segsS2C, err := db.SegmentsFor(st.ID, model.S2C)
		if err != nil {
			t.Fatalf("query segments S2C: %v", err)
		}
		if len(segsC2S)+len(segsS2C) != 0 {
			t.Errorf("stream %d has segments, want 0", st.ID)
		}
	}

	events, _, err := db.Events(store.EventFilter{})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestFlowsExpiredBy1sThrottleEmitted(t *testing.T) {
	pcapFile := filepath.Join(t.TempDir(), "throttle_expire.pcap")
	f, err := os.Create(pcapFile)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}

	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Create 4 UDP flows spaced 150 seconds apart (> FlowIdleTimeout 120s, > 1s throttle).
	// Flows 0, 1, 2 expire via the 1s throttle in runWorker as subsequent packets arrive.
	// Flow 3 expires at final drain.
	const numFlows = 4
	for i := 0; i < numFlows; i++ {
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IPv4(10, 0, 0, byte(i+1)),
			DstIP:    net.IPv4(10, 1, 0, 1),
		}
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(20000 + i),
			DstPort: 53,
		}
		_ = udp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, udp, gopacket.Payload([]byte("udp-throttle-test")))
		data := buf.Bytes()
		pktTS := t0.Add(time.Duration(i*150) * time.Second)
		err := pw.WritePacket(gopacket.CaptureInfo{
			Timestamp:     pktTS,
			CaptureLength: len(data),
			Length:        len(data),
		}, data)
		if err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close pcap: %v", err)
	}

	var emitted atomic.Int64
	baseDir := t.TempDir()
	res, err := Run(context.Background(), Options{
		PCAPPath: pcapFile,
		BaseDir:  baseDir,
		Hooks: Hooks{
			AnalyzeStream: func(ctx context.Context, cs *ClosedStream) error {
				emitted.Add(1)
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if emitted.Load() != numFlows {
		t.Errorf("emitted = %d, want %d", emitted.Load(), numFlows)
	}
	if res.Streams != numFlows {
		t.Errorf("res.Streams = %d, want %d", res.Streams, numFlows)
	}

	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	streams, _, err := db.Streams(store.StreamFilter{})
	if err != nil {
		t.Fatalf("query streams: %v", err)
	}
	if len(streams) != numFlows {
		t.Fatalf("expected %d stream rows in DB, got %d", numFlows, len(streams))
	}
}

func TestWorkerSafetyInjectedPanic(t *testing.T) {
	// Create synthetic capture with two TCP streams:
	// Stream 1: port 10001 -> 80
	// Stream 2: port 10002 -> 80
	pcapFile := filepath.Join(t.TempDir(), "worker_panic.pcap")
	f, err := os.Create(pcapFile)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}

	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	writeTCPPacket := func(srcPort uint16, seq uint32, flags uint8, payload []byte, offsetSec int) {
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    net.IPv4(10, 0, 0, 1),
			DstIP:    net.IPv4(10, 0, 0, 2),
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: 80,
			Seq:     seq,
			SYN:     flags&0x02 != 0,
			ACK:     flags&0x10 != 0,
			FIN:     flags&0x01 != 0,
			Window:  65535,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		var pLayer gopacket.SerializableLayer
		if len(payload) > 0 {
			pLayer = gopacket.Payload(payload)
		}
		if pLayer != nil {
			_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, tcp, pLayer)
		} else {
			_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, tcp)
		}
		data := buf.Bytes()
		err := pw.WritePacket(gopacket.CaptureInfo{
			Timestamp:     t0.Add(time.Duration(offsetSec) * time.Second),
			CaptureLength: len(data),
			Length:        len(data),
		}, data)
		if err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}

	// Stream 1 (port 10001): SYN, DATA (panics here), FIN
	writeTCPPacket(10001, 1000, 0x02, nil, 0)
	writeTCPPacket(10001, 1001, 0x10, []byte("stream1-data"), 1)
	writeTCPPacket(10001, 1013, 0x01, nil, 2)

	// Stream 2 (port 10002): SYN, DATA, FIN
	writeTCPPacket(10002, 2000, 0x02, nil, 3)
	writeTCPPacket(10002, 2001, 0x10, []byte("stream2-data"), 4)
	writeTCPPacket(10002, 2013, 0x01, nil, 5)

	if err := f.Close(); err != nil {
		t.Fatalf("close pcap: %v", err)
	}

	// Set hook to panic on stream 1 data packet
	var panickedCount atomic.Int64
	SetTestWorkerPanicHook(func(pkt decode.Packet) {
		if pkt.SrcPort == 10001 && len(pkt.Payload) > 0 {
			panickedCount.Add(1)
			panic("injected panic on stream 1 data packet")
		}
	})
	defer SetTestWorkerPanicHook(nil)

	res, err := Run(context.Background(), Options{
		PCAPPath: pcapFile,
		BaseDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Run failed despite worker recovery: %v", err)
	}

	if panickedCount.Load() == 0 {
		t.Fatal("expected test hook panic to be triggered, but was not")
	}

	if res.Streams != 2 {
		t.Errorf("res.Streams = %d, want 2", res.Streams)
	}

	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	// Verify both streams exist in DB
	streams, _, err := db.Streams(store.StreamFilter{})
	if err != nil {
		t.Fatalf("query streams: %v", err)
	}
	if len(streams) != 2 {
		t.Fatalf("expected 2 streams in DB, got %d", len(streams))
	}

	var stream1ID, stream2ID int64
	for _, st := range streams {
		if st.SrcPort == 10001 {
			stream1ID = st.ID
		} else if st.SrcPort == 10002 {
			stream2ID = st.ID
		}
	}
	if stream1ID == 0 || stream2ID == 0 {
		t.Fatalf("could not identify stream IDs: stream1=%d, stream2=%d", stream1ID, stream2ID)
	}

	// Verify anomaly events
	events, _, err := db.Events(store.EventFilter{
		Types: []model.EventType{model.EvTCPAnomaly},
	})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}

	// Exactly one parse_error event should be present, associated with stream 1
	var foundParseError bool
	for _, ev := range events {
		if ev.StreamID == stream1ID {
			if k, ok := ev.Details["kind"].(string); ok && k == "parse_error" {
				foundParseError = true
				if ev.Type != model.EvTCPAnomaly {
					t.Errorf("event type = %v, want %v", ev.Type, model.EvTCPAnomaly)
				}
				if ev.Severity != model.SevWarning {
					t.Errorf("event severity = %v, want %v", ev.Severity, model.SevWarning)
				}
				if !strings.Contains(ev.Title, "parse_error") {
					t.Errorf("event title %q does not contain parse_error", ev.Title)
				}
			}
		}
		if ev.StreamID == stream2ID {
			t.Errorf("unexpected anomaly event for stream 2: %+v", ev)
		}
	}

	if !foundParseError {
		t.Errorf("expected parse_error EvTCPAnomaly event for stream 1, but found none in %d events", len(events))
	}
}

func TestWorkerSafetyInjectedPanicOnSYN(t *testing.T) {
	pcapFile := filepath.Join(t.TempDir(), "worker_panic_syn.pcap")
	f, err := os.Create(pcapFile)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}

	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	writeTCPPacket := func(srcPort uint16, seq uint32, flags uint8, payload []byte, offsetSec int) {
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    net.IPv4(10, 0, 0, 1),
			DstIP:    net.IPv4(10, 0, 0, 2),
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: 80,
			Seq:     seq,
			SYN:     flags&0x02 != 0,
			ACK:     flags&0x10 != 0,
			FIN:     flags&0x01 != 0,
			Window:  65535,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		var pLayer gopacket.SerializableLayer
		if len(payload) > 0 {
			pLayer = gopacket.Payload(payload)
		}
		if pLayer != nil {
			_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, tcp, pLayer)
		} else {
			_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, tcp)
		}
		data := buf.Bytes()
		err := pw.WritePacket(gopacket.CaptureInfo{
			Timestamp:     t0.Add(time.Duration(offsetSec) * time.Second),
			CaptureLength: len(data),
			Length:        len(data),
		}, data)
		if err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}

	// Stream 1 (port 10001): SYN (panics on SYN)
	writeTCPPacket(10001, 1000, 0x02, nil, 0)

	// Stream 2 (port 10002): SYN, DATA, FIN
	writeTCPPacket(10002, 2000, 0x02, nil, 1)
	writeTCPPacket(10002, 2001, 0x10, []byte("ok"), 2)
	writeTCPPacket(10002, 2003, 0x01, nil, 3)

	if err := f.Close(); err != nil {
		t.Fatalf("close pcap: %v", err)
	}

	SetTestWorkerPanicHook(func(pkt decode.Packet) {
		if pkt.SrcPort == 10001 {
			panic("injected panic on SYN")
		}
	})
	defer SetTestWorkerPanicHook(nil)

	res, err := Run(context.Background(), Options{
		PCAPPath: pcapFile,
		BaseDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.Streams != 2 {
		t.Errorf("res.Streams = %d, want 2", res.Streams)
	}

	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	events, _, err := db.Events(store.EventFilter{
		Types: []model.EventType{model.EvTCPAnomaly},
	})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}

	var foundParseError bool
	for _, ev := range events {
		if k, ok := ev.Details["kind"].(string); ok && k == "parse_error" {
			foundParseError = true
		}
	}
	if !foundParseError {
		t.Error("expected parse_error event for SYN panic, got none")
	}
}

// expStream mirrors the stream entry of testdata/expected/*.json.
type expStream struct {
	Proto     string `json:"proto"`
	SrcIP     string `json:"srcIp"`
	SrcPort   uint16 `json:"srcPort"`
	DstIP     string `json:"dstIp"`
	DstPort   uint16 `json:"dstPort"`
	C2SBytes  int    `json:"c2sBytes"`
	S2CBytes  int    `json:"s2cBytes"`
	Midstream bool   `json:"midstream"`
	HasGaps   bool   `json:"hasGaps"`
}

type expDoc struct {
	Name    string      `json:"name"`
	Packets int         `json:"packets"`
	Streams []expStream `json:"streams"`
}

func TestSortEvents(t *testing.T) {
	events := []model.Event{
		{TS: 20, PacketNo: 5, Src: "b", Type: model.EvTCPAnomaly, Title: "x"},
		{TS: 10, PacketNo: 9, Src: "a", Type: model.EvTCPAnomaly, Title: "y"},
		{TS: 10, PacketNo: 2, Src: "z", Type: model.EvTCPAnomaly, Title: "z"},
		{TS: 10, PacketNo: 2, Src: "a", Type: model.EvTCPAnomaly, Title: "a"},
		{TS: 10, PacketNo: 2, Src: "a", Type: model.EvTCPAnomaly, Title: "b",
			Details: map[string]any{"k": "v"}},
	}
	sortEvents(events)

	var got []string
	for _, e := range events {
		got = append(got, e.Src+"/"+e.Title)
	}
	want := []string{"a/a", "a/b", "z/z", "a/y", "b/x"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", got, want)
	}

	// Sorting is stable and repeated calls are a no-op.
	second := append([]model.Event(nil), events...)
	sortEvents(second)
	for i := range events {
		if events[i].Src != second[i].Src || events[i].Title != second[i].Title {
			t.Fatalf("sort not deterministic at %d: %v vs %v", i, events[i], second[i])
		}
	}
}

func TestDeterministicOutput(t *testing.T) {
	fixtures := []string{
		"tcp_gap.pcap",
		"tcp_midstream.pcap",
		"tcp_overlap_conflict.pcap",
		"tcp_portreuse.pcap",
	}
	budget, err := resource.NewBudget(256*1024*1024, 0, 4)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}

	run := func(name string) string {
		t.Helper()
		res, err := Run(context.Background(), Options{
			PCAPPath: testutil.Pcap(t, name),
			BaseDir:  t.TempDir(),
			Budget:   budget,
		})
		if err != nil {
			t.Fatalf("%s: Run: %v", name, err)
		}
		db, err := store.Open(res.Case.DB())
		if err != nil {
			t.Fatalf("%s: open DB: %v", name, err)
		}
		defer db.Close()

		verifyEventIDOrder(t, db)
		return normalizedDump(t, db)
	}

	for _, name := range fixtures {
		first := run(name)
		second := run(name)
		if first != second {
			t.Errorf("%s: normalized DB content differs between runs\n--- first ---\n%s\n--- second ---\n%s",
				name, first, second)
		}
	}
}

func TestMetadataKeys(t *testing.T) {
	res, err := Run(context.Background(), Options{
		PCAPPath: testutil.Pcap(t, "tcp_gap.pcap"),
		BaseDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("open DB: %v", err)
	}
	defer db.Close()

	meta, err := db.Meta()
	if err != nil {
		t.Fatalf("Meta: %v", err)
	}
	want := map[string]string{
		"pcap_name":   "tcp_gap.pcap",
		"pcap_sha256": res.PcapSHA256,
		"pcap_size":   strconv.FormatInt(res.PcapSize, 10),
		"packets":     strconv.FormatInt(res.Packets, 10),
		"streams":     strconv.FormatInt(res.Streams, 10),
		"max_mem":     "2147483648",
		"max_disk":    "0",
	}
	for k, v := range want {
		if meta[k] != v {
			t.Errorf("meta[%q] = %q, want %q", k, meta[k], v)
		}
	}
	if meta["pcap_sha256"] == "" {
		t.Errorf("meta[pcap_sha256] is empty")
	}
	if meta["tool_version"] == "" {
		t.Errorf("meta[tool_version] is empty")
	}
	if meta["duration_ns"] == "" || meta["duration_ns"] == "0" {
		t.Errorf("meta[duration_ns] = %q, want positive", meta["duration_ns"])
	}
	if meta["workers"] == "" {
		t.Errorf("meta[workers] missing")
	}
}

func TestEndToEndTCPFixtures(t *testing.T) {
	fixtures := []string{
		"tcp_basic.pcap",
		"tcp_gap.pcap",
		"tcp_midstream.pcap",
		"tcp_ooo.pcap",
		"tcp_overlap_conflict.pcap",
		"tcp_portreuse.pcap",
		"tcp_retrans.pcap",
		"tcp_wrap.pcap",
	}
	for _, name := range fixtures {
		name := name
		t.Run(strings.TrimSuffix(name, filepath.Ext(name)), func(t *testing.T) {
			var exp expDoc
			testutil.LoadExpected(t, strings.TrimSuffix(name, filepath.Ext(name))+".json", &exp)

			budget, err := resource.NewBudget(256*1024*1024, 0, 2)
			if err != nil {
				t.Fatalf("NewBudget: %v", err)
			}
			res, err := Run(context.Background(), Options{
				PCAPPath: testutil.Pcap(t, name),
				BaseDir:  t.TempDir(),
				Budget:   budget,
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			db, err := store.Open(res.Case.DB())
			if err != nil {
				t.Fatalf("open DB: %v", err)
			}
			defer db.Close()

			streams, _, err := db.Streams(store.StreamFilter{})
			if err != nil {
				t.Fatalf("query streams: %v", err)
			}
			if len(streams) != len(exp.Streams) {
				t.Fatalf("DB streams = %d, want %d", len(streams), len(exp.Streams))
			}

			used := make([]bool, len(streams))
			for _, want := range exp.Streams {
				match := -1
				for i, got := range streams {
					if used[i] {
						continue
					}
					if got.Proto == want.Proto &&
						got.SrcIP == want.SrcIP && int(got.SrcPort) == int(want.SrcPort) &&
						got.DstIP == want.DstIP && int(got.DstPort) == int(want.DstPort) &&
						int(got.BytesC2S) == want.C2SBytes && int(got.BytesS2C) == want.S2CBytes &&
						got.HasGaps == want.HasGaps && got.Midstream == want.Midstream {
						match = i
						break
					}
				}
				if match < 0 {
					t.Errorf("no DB stream matches expected %+v; DB streams = %+v", want, streams)
					continue
				}
				used[match] = true
			}
		})
	}
}

// verifyEventIDOrder asserts that event ids were assigned in (ts, packetNo)
// order, so reading by (ts, id) yields the required (ts, packetNo, id) ordering.
func verifyEventIDOrder(t *testing.T, db *store.DB) {
	t.Helper()
	rows, err := db.Conn().Query(`SELECT ts, packet_no, id FROM events ORDER BY id ASC`)
	if err != nil {
		t.Fatalf("query event order: %v", err)
	}
	defer rows.Close()

	var prevTS, prevPacket int64
	first := true
	for rows.Next() {
		var ts, packetNo, id int64
		if err := rows.Scan(&ts, &packetNo, &id); err != nil {
			t.Fatalf("scan event order: %v", err)
		}
		if !first && (ts < prevTS || (ts == prevTS && packetNo < prevPacket)) {
			t.Fatalf("event id %d is out of (ts, packet_no) order: (%d,%d) after (%d,%d)",
				id, ts, packetNo, prevTS, prevPacket)
		}
		prevTS, prevPacket = ts, packetNo
		first = false
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate event order: %v", err)
	}
}

// normalizedDump renders the semantic content of a case database so that two
// runs can be compared without depending on internal auto-increment ids or
// wall-clock metadata.
func normalizedDump(t *testing.T, db *store.DB) string {
	t.Helper()
	conn := db.Conn()
	var out strings.Builder

	// Streams: assign canonical ids in content order.
	type streamRec struct {
		id, parent int64
		fields     []any
	}
	rows, err := conn.Query(`SELECT id,coalesce(parent_id,0),proto,src_ip,src_port,dst_ip,dst_port,` +
		`start_ts,end_ts,bytes_c2s,bytes_s2c,packets,first_packet,last_packet,midstream,has_gaps,udp` +
		` FROM streams`)
	if err != nil {
		t.Fatalf("dump streams: %v", err)
	}
	var recs []streamRec
	for rows.Next() {
		var r streamRec
		var proto, srcIP, dstIP string
		var srcPort, dstPort, start, end, c2s, s2c, packets, first, last, mid, gaps, udp int64
		if err := rows.Scan(&r.id, &r.parent, &proto, &srcIP, &srcPort, &dstIP, &dstPort,
			&start, &end, &c2s, &s2c, &packets, &first, &last, &mid, &gaps, &udp); err != nil {
			t.Fatalf("scan stream: %v", err)
		}
		r.fields = []any{proto, srcIP, srcPort, dstIP, dstPort, start, end, c2s, s2c,
			packets, first, last, mid, gaps, udp}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate streams: %v", err)
	}
	sort.SliceStable(recs, func(i, j int) bool {
		return fmt.Sprint(recs[i].fields) < fmt.Sprint(recs[j].fields)
	})
	canon := make(map[int64]int, len(recs))
	for i, r := range recs {
		canon[r.id] = i + 1
	}
	for i, r := range recs {
		parent := int64(0)
		if r.parent != 0 {
			parent = int64(canon[r.parent])
		}
		fmt.Fprintf(&out, "stream %d parent=%d %v\n", i+1, parent, r.fields)
	}

	// Segments: canonicalise stream ids, then order by content.
	type segRec struct {
		stream, dir, off, length, ts, packet int64
	}
	rows, err = conn.Query(`SELECT stream_id,dir,stream_off,length,ts,packet_no FROM segments`)
	if err != nil {
		t.Fatalf("dump segments: %v", err)
	}
	var segs []segRec
	for rows.Next() {
		var s segRec
		if err := rows.Scan(&s.stream, &s.dir, &s.off, &s.length, &s.ts, &s.packet); err != nil {
			t.Fatalf("scan segment: %v", err)
		}
		segs = append(segs, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate segments: %v", err)
	}
	sort.SliceStable(segs, func(i, j int) bool {
		a, b := segs[i], segs[j]
		if ca, cb := canon[a.stream], canon[b.stream]; ca != cb {
			return ca < cb
		}
		if a.dir != b.dir {
			return a.dir < b.dir
		}
		if a.off != b.off {
			return a.off < b.off
		}
		if a.length != b.length {
			return a.length < b.length
		}
		if a.ts != b.ts {
			return a.ts < b.ts
		}
		return a.packet < b.packet
	})
	for _, s := range segs {
		fmt.Fprintf(&out, "segment stream=%d dir=%d off=%d len=%d ts=%d pkt=%d\n",
			canon[s.stream], s.dir, s.off, s.length, s.ts, s.packet)
	}

	// Events: order by content and canonicalise stream references. Internal
	// event ids are intentionally omitted; their ordering is asserted separately.
	type eventRec struct{ fields []string }
	rows, err = conn.Query(`SELECT ts,packet_no,packet_end,type,severity,phase,stream_id,src,dst,` +
		`proto,title,details_json,explain,parent_id,file_id,finding_ids FROM events`)
	if err != nil {
		t.Fatalf("dump events: %v", err)
	}
	var evs []eventRec
	for rows.Next() {
		var ts, packetNo, packetEnd int64
		var typ, severity, phase, src, dst, proto, title, explain string
		var streamID, parentID, fileID sql.NullInt64
		var details, findingIDs sql.NullString
		if err := rows.Scan(&ts, &packetNo, &packetEnd, &typ, &severity, &phase, &streamID,
			&src, &dst, &proto, &title, &details, &explain, &parentID, &fileID, &findingIDs); err != nil {
			t.Fatalf("scan event: %v", err)
		}
		sid := int64(0)
		if streamID.Valid && streamID.Int64 != 0 {
			sid = int64(canon[streamID.Int64])
		}
		evs = append(evs, eventRec{fields: []string{
			fmt.Sprint(ts), fmt.Sprint(packetNo), fmt.Sprint(packetEnd), typ, severity, phase,
			fmt.Sprint(sid), src, dst, proto, title, details.String, explain,
			fmt.Sprint(parentID.Int64), fmt.Sprint(fileID.Int64), findingIDs.String,
		}})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate events: %v", err)
	}
	sort.SliceStable(evs, func(i, j int) bool {
		return strings.Join(evs[i].fields, "\x00") < strings.Join(evs[j].fields, "\x00")
	})
	for _, e := range evs {
		fmt.Fprintf(&out, "event %s\n", strings.Join(e.fields, "|"))
	}

	// Meta: exclude wall-clock duration; everything else must be reproducible.
	rows, err = conn.Query(`SELECT key,value FROM meta WHERE key <> 'duration_ns' ORDER BY key`)
	if err != nil {
		t.Fatalf("dump meta: %v", err)
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatalf("scan meta: %v", err)
		}
		fmt.Fprintf(&out, "meta %s=%s\n", k, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate meta: %v", err)
	}

	return out.String()
}
