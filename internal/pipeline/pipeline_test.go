package pipeline

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/tokio-drift/raccoon/internal/casedir"
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
