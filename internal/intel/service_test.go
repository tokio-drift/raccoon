package intel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/tokio-drift/raccoon/internal/carve"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
)

// eicarFormat implements carve.Format to recognize and carve an EICAR file
// directly from a packet stream.
type eicarFormat struct{}

func (eicarFormat) Name() string { return "eicar" }
func (eicarFormat) Ext() string  { return "com" }

func (eicarFormat) Headers() [][]byte {
	// Use split string parts so this test file does not contain literal EICAR.
	part1 := "X5O!P%@AP[4" + `\` + "PZX54(P^)7CC)7}"
	return [][]byte{[]byte(part1)}
}

func (eicarFormat) MaxSize() int64 { return 1024 }

func (eicarFormat) Extent(r io.ReaderAt, start, streamLen int64) (int64, string, error) {
	if streamLen-start < 68 {
		return streamLen, carve.StatusTruncated, nil
	}
	return start + 68, carve.StatusComplete, nil
}

// generateEICARPCAP builds an in-memory or on-disk PCAP containing a TCP
// stream with the EICAR test string payload.
func generateEICARPCAP(t *testing.T, payload []byte) (string, []byte) {
	t.Helper()
	pcapPath := filepath.Join(t.TempDir(), "eicar_carve.pcap")
	f, err := os.Create(pcapPath)
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
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 50000,
		DstPort: 80,
		Seq:     1000,
		Ack:     2000,
		ACK:     true,
		PSH:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	rawPkt := buf.Bytes()
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		CaptureLength: len(rawPkt),
		Length:        len(rawPkt),
	}
	if err := pw.WritePacket(ci, rawPkt); err != nil {
		t.Fatalf("write packet: %v", err)
	}

	return pcapPath, payload
}

// carveFromPCAP opens the generated PCAP and carves files using an eicarFormat.
func carveFromPCAP(t *testing.T, pcapPath string, carvedDir string) carve.Carved {
	t.Helper()
	f, err := os.Open(pcapPath)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer f.Close()

	pr, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}

	var streamPayload []byte
	for {
		data, _, err := pr.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read packet data: %v", err)
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if len(tcp.Payload) > 0 {
				streamPayload = append(streamPayload, tcp.Payload...)
			}
		}
	}

	reg := carve.NewRegistry()
	if err := reg.Register(eicarFormat{}); err != nil {
		t.Fatalf("register eicar format: %v", err)
	}

	scanner, err := carve.NewScanner(carve.Config{
		Registry:  reg,
		CarvedDir: carvedDir,
	})
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}

	var carvedFiles []carve.Carved
	target := carve.Target{
		Reader: bytes.NewReader(streamPayload),
		Len:    int64(len(streamPayload)),
		Dir:    model.C2S,
		Name:   "eicar.com",
	}
	err = scanner.Scan(target, func(c carve.Carved) {
		carvedFiles = append(carvedFiles, c)
	})
	if err != nil {
		t.Fatalf("carve scan: %v", err)
	}

	if len(carvedFiles) != 1 {
		t.Fatalf("carved %d files, want 1", len(carvedFiles))
	}
	return carvedFiles[0]
}

// openTestDB creates and returns an open SQLite store.DB in a temporary dir.
func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_case.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// failingTransport fails the test immediately if any HTTP request is issued.
type failingTransport struct {
	t *testing.T
}

func (ft *failingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ft.t.Fatalf("offline mode: unexpected HTTP request sent to %s", req.URL.String())
	return nil, errors.New("offline mode: HTTP requests forbidden")
}

// mockRuleEngine satisfies RuleEngine for testing without the yara binary.
type mockRuleEngine struct {
	available bool
	matches   []Match
	err       error
}

func (m *mockRuleEngine) Available() bool { return m.available }
func (m *mockRuleEngine) Scan(path string) ([]Match, error) {
	return m.matches, m.err
}

// TestServiceYARAEICARCarvedFromPCAP verifies:
// EICAR carved from a generated pcap → YARA hit → critical (skip with t.Skip if yara missing).
func TestServiceYARAEICARCarvedFromPCAP(t *testing.T) {
	eng, err := NewSubprocessEngine("")
	if err != nil || !eng.Available() {
		t.Skip("yara missing; skipping EICAR subprocess test")
	}
	defer os.RemoveAll(eng.rulesDir)

	part1 := "X5O!P%@AP[4" + `\` + "PZX54(P^)7CC)7}"
	part2 := "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	eicarBytes := []byte(part1 + part2)

	pcapPath, _ := generateEICARPCAP(t, eicarBytes)
	carvedDir := filepath.Join(t.TempDir(), "carved")
	carved := carveFromPCAP(t, pcapPath, carvedDir)

	db := openTestDB(t)

	// Insert initial FILE_CARVED event with Info severity.
	const fileID int64 = 101
	_, err = db.InsertEvents([]model.Event{
		{
			ID:       1,
			TS:       time.Now().UnixNano(),
			Type:     model.EvFileCarved,
			Severity: model.SevInfo,
			FileID:   fileID,
			Title:    "File carved: eicar.com",
		},
	})
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var sseVerdict model.Verdict
	verdictCh := make(chan model.Verdict, 1)

	svc := NewService(context.Background(), ServiceConfig{
		Store:   db,
		YARA:    eng,
		Offline: true,
		OnVerdict: func(v model.Verdict) {
			sseVerdict = v
			verdictCh <- v
		},
	})
	defer svc.Close()

	info := FileInfo{
		FileID:   fileID,
		SHA256:   carved.SHA256,
		AbsPath:  carved.Path,
		StreamID: 1,
		Src:      "10.0.0.1:50000",
		Dst:      "10.0.0.2:80",
		Proto:    "tcp",
		TS:       time.Now().UnixNano(),
		PacketNo: 1,
	}

	svc.ProcessFile(info)

	select {
	case <-verdictCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for YARA verdict callback")
	}

	if sseVerdict.Status != "malicious" {
		t.Errorf("verdict status = %q, want \"malicious\"", sseVerdict.Status)
	}
	if sseVerdict.Source != "yara" {
		t.Errorf("verdict source = %q, want \"yara\"", sseVerdict.Source)
	}

	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// 1. Assert verdict row exists in store.
	verdicts, err := db.Verdicts(carved.SHA256)
	if err != nil {
		t.Fatalf("get verdicts: %v", err)
	}
	var foundYARA bool
	for _, v := range verdicts {
		if v.Source == "yara" {
			foundYARA = true
			if v.Status != "malicious" {
				t.Errorf("store verdict status = %q, want malicious", v.Status)
			}
		}
	}
	if !foundYARA {
		t.Errorf("no yara verdict row found in store for sha %s", carved.SHA256)
	}

	// 2. Assert FILE_CARVED event severity escalated to critical.
	events, _, err := db.Events(store.EventFilter{
		Types: []model.EventType{model.EvFileCarved},
		Flat:  true,
	})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 FILE_CARVED event, got %d", len(events))
	}
	if events[0].Severity != model.SevCritical {
		t.Errorf("FILE_CARVED severity = %q, want %q", events[0].Severity, model.SevCritical)
	}

	// 3. Assert EvVerdict event was inserted with critical severity.
	verdictEvents, _, err := db.Events(store.EventFilter{
		Types: []model.EventType{model.EvVerdict},
		Flat:  true,
	})
	if err != nil {
		t.Fatalf("query verdict events: %v", err)
	}
	if len(verdictEvents) != 1 {
		t.Fatalf("expected 1 EvVerdict event, got %d", len(verdictEvents))
	}
	if verdictEvents[0].Severity != model.SevCritical {
		t.Errorf("EvVerdict severity = %q, want %q", verdictEvents[0].Severity, model.SevCritical)
	}
	if verdictEvents[0].FileID != fileID {
		t.Errorf("EvVerdict fileID = %d, want %d", verdictEvents[0].FileID, fileID)
	}
}

// TestServiceYARAMockEngineEscalation verifies YARA severity escalation logic
// independently of whether the yara binary is available on the system.
func TestServiceYARAMockEngineEscalation(t *testing.T) {
	mockEng := &mockRuleEngine{
		available: true,
		matches: []Match{
			{Rule: "eicar_test_file", File: "/tmp/eicar.com"},
		},
	}

	db := openTestDB(t)
	const fileID int64 = 202

	_, err := db.InsertEvents([]model.Event{
		{
			ID:       1,
			TS:       time.Now().UnixNano(),
			Type:     model.EvFileCarved,
			Severity: model.SevInfo,
			FileID:   fileID,
			Title:    "File carved: test.com",
		},
	})
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var sseCalled bool
	svc := NewService(context.Background(), ServiceConfig{
		Store:   db,
		YARA:    mockEng,
		Offline: true,
		OnVerdict: func(v model.Verdict) {
			sseCalled = true
		},
	})
	defer svc.Close()

	testHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	svc.ProcessFile(FileInfo{
		FileID:  fileID,
		SHA256:  testHash,
		AbsPath: "/tmp/dummy",
	})

	if !sseCalled {
		t.Error("expected SSE callback to be invoked")
	}

	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	events, _, err := db.Events(store.EventFilter{
		Types: []model.EventType{model.EvFileCarved},
		Flat:  true,
	})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 || events[0].Severity != model.SevCritical {
		t.Errorf("FILE_CARVED severity = %v, want critical", events)
	}
}

// TestServiceVTMockReturnsMaliciousEscalatesEvent verifies:
// VT mock returns malicious → event escalated.
func TestServiceVTMockReturnsMaliciousEscalatesEvent(t *testing.T) {
	// VT mock returns 5 malicious, 0 suspicious -> status "malicious"
	srv := makeVTServer(t, http.StatusOK, vtResponse(5, 0, 10, 30))
	defer srv.Close()

	vtClient := &Client{
		HTTP:    srv.Client(),
		BaseURL: srv.URL,
		APIKey:  "test-api-key",
	}

	db := openTestDB(t)
	const fileID int64 = 303
	h := sha256.Sum256([]byte("malicious-payload-sample"))
	testSHA := hex.EncodeToString(h[:])

	// Initial FILE_CARVED event at Info severity.
	_, err := db.InsertEvents([]model.Event{
		{
			ID:       1,
			TS:       time.Now().UnixNano(),
			Type:     model.EvFileCarved,
			Severity: model.SevInfo,
			FileID:   fileID,
			Title:    "File carved: trojan.exe",
		},
	})
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	verdictCh := make(chan model.Verdict, 2)
	svc := NewService(context.Background(), ServiceConfig{
		Store:           db,
		YARA:            NopEngine{},
		VTClient:        vtClient,
		VTRatePerMinute: 600, // fast token bucket for tests
		OnVerdict: func(v model.Verdict) {
			if v.Source == "virustotal" {
				verdictCh <- v
			}
		},
	})
	defer svc.Close()

	svc.ProcessFile(FileInfo{
		FileID:   fileID,
		SHA256:   testSHA,
		AbsPath:  "/tmp/trojan.exe",
		StreamID: 10,
		Src:      "192.168.1.50:4444",
		Dst:      "10.0.0.1:80",
		Proto:    "tcp",
		TS:       time.Now().UnixNano(),
	})

	select {
	case v := <-verdictCh:
		if v.Status != "malicious" {
			t.Errorf("VT verdict status = %q, want \"malicious\"", v.Status)
		}
		if v.Score != 5 {
			t.Errorf("VT verdict score = %d, want 5", v.Score)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for VirusTotal verdict")
	}

	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Verify FILE_CARVED event severity escalated from info to critical.
	events, _, err := db.Events(store.EventFilter{
		Types: []model.EventType{model.EvFileCarved},
		Flat:  true,
	})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 FILE_CARVED event, got %d", len(events))
	}
	if events[0].Severity != model.SevCritical {
		t.Errorf("FILE_CARVED severity = %q, want %q", events[0].Severity, model.SevCritical)
	}

	// Verify EvVerdict event was created with critical severity and links to fileID.
	verdictEvents, _, err := db.Events(store.EventFilter{
		Types: []model.EventType{model.EvVerdict},
		Flat:  true,
	})
	if err != nil {
		t.Fatalf("query verdict events: %v", err)
	}
	if len(verdictEvents) != 1 {
		t.Fatalf("expected 1 EvVerdict event, got %d", len(verdictEvents))
	}
	if verdictEvents[0].Severity != model.SevCritical {
		t.Errorf("EvVerdict severity = %q, want %q", verdictEvents[0].Severity, model.SevCritical)
	}
	if verdictEvents[0].FileID != fileID {
		t.Errorf("EvVerdict fileID = %d, want %d", verdictEvents[0].FileID, fileID)
	}
}

// TestServiceVTMockReturnsSuspiciousEscalatesToWarning checks that a suspicious
// VT response escalates FILE_CARVED severity to warning.
func TestServiceVTMockReturnsSuspiciousEscalatesToWarning(t *testing.T) {
	// 1 malicious + 1 suspicious -> suspicious
	srv := makeVTServer(t, http.StatusOK, vtResponse(1, 1, 10, 30))
	defer srv.Close()

	vtClient := &Client{
		HTTP:    srv.Client(),
		BaseURL: srv.URL,
		APIKey:  "test-api-key",
	}

	db := openTestDB(t)
	const fileID int64 = 404
	h := sha256.Sum256([]byte("suspicious-payload-sample"))
	testSHA := hex.EncodeToString(h[:])

	_, err := db.InsertEvents([]model.Event{
		{
			ID:       1,
			TS:       time.Now().UnixNano(),
			Type:     model.EvFileCarved,
			Severity: model.SevInfo,
			FileID:   fileID,
			Title:    "File carved: suspect.js",
		},
	})
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	verdictCh := make(chan model.Verdict, 2)
	svc := NewService(context.Background(), ServiceConfig{
		Store:           db,
		YARA:            NopEngine{},
		VTClient:        vtClient,
		VTRatePerMinute: 600,
		OnVerdict: func(v model.Verdict) {
			if v.Source == "virustotal" {
				verdictCh <- v
			}
		},
	})
	defer svc.Close()

	svc.ProcessFile(FileInfo{
		FileID:  fileID,
		SHA256:  testSHA,
		AbsPath: "/tmp/suspect.js",
	})

	select {
	case v := <-verdictCh:
		if v.Status != "suspicious" {
			t.Errorf("VT verdict status = %q, want \"suspicious\"", v.Status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for VirusTotal verdict")
	}

	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	events, _, err := db.Events(store.EventFilter{
		Types: []model.EventType{model.EvFileCarved},
		Flat:  true,
	})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 || events[0].Severity != model.SevWarning {
		t.Errorf("FILE_CARVED severity = %v, want warning", events)
	}
}

// TestServiceOfflineModeZeroHTTPCalls verifies:
// offline mode makes zero HTTP calls (assert with a transport that fails the test on use).
func TestServiceOfflineModeZeroHTTPCalls(t *testing.T) {
	// The transport will call t.Fatalf if any HTTP request is attempted.
	failingHTTP := &http.Client{
		Transport: &failingTransport{t: t},
	}

	vtClient := &Client{
		HTTP:    failingHTTP,
		BaseURL: "http://example.com/api/v3",
		APIKey:  "real-or-fake-key-does-not-matter",
	}

	db := openTestDB(t)
	const fileID int64 = 505
	testSHA := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	_, err := db.InsertEvents([]model.Event{
		{
			ID:       1,
			TS:       time.Now().UnixNano(),
			Type:     model.EvFileCarved,
			Severity: model.SevInfo,
			FileID:   fileID,
			Title:    "File carved: offline.bin",
		},
	})
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	svc := NewService(context.Background(), ServiceConfig{
		Store:    db,
		YARA:     NopEngine{},
		VTClient: vtClient,
		Offline:  true, // OFFLINE MODE ACTIVATED
	})
	defer svc.Close()

	// Calling ProcessFile in offline mode must NOT contact the VTClient.
	svc.ProcessFile(FileInfo{
		FileID:  fileID,
		SHA256:  testSHA,
		AbsPath: "/tmp/offline.bin",
	})

	// Wait briefly to ensure no asynchronous requests slip through.
	time.Sleep(50 * time.Millisecond)

	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Verify a "not_checked" verdict is stored for source "virustotal".
	verdicts, err := db.Verdicts(testSHA)
	if err != nil {
		t.Fatalf("query verdicts: %v", err)
	}
	var foundVTNotChecked bool
	for _, v := range verdicts {
		if v.Source == "virustotal" && v.Status == "not_checked" {
			foundVTNotChecked = true
		}
	}
	if !foundVTNotChecked {
		t.Errorf("expected not_checked virustotal verdict in store, got: %v", verdicts)
	}

	// Verify FILE_CARVED event was not escalated (remains SevInfo).
	events, _, err := db.Events(store.EventFilter{
		Types: []model.EventType{model.EvFileCarved},
		Flat:  true,
	})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 || events[0].Severity != model.SevInfo {
		t.Errorf("FILE_CARVED severity should remain info, got %v", events)
	}
}
