package server

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
)

const (
	testToken = "test-token-0123456789abcdef"
	testID    = "20260101-120000-abcdef"
)

var fixtureCreated = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func ts(ms int64) int64 { return fixtureCreated.Add(time.Duration(ms) * time.Millisecond).UnixNano() }

// seedCase writes one finished case: 3 streams, 7 events (2 grouped
// children), 3 carved files (one with two competing verdicts).
func seedCase(t *testing.T, dataDir string) {
	t.Helper()
	c, err := casedir.Create(dataDir, casedir.Options{
		ID:      testID,
		PCAP:    "capture.pcap",
		Created: fixtureCreated,
	})
	if err != nil {
		t.Fatalf("casedir.Create: %v", err)
	}
	db, err := store.Open(c.DB())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	setMeta := func(k, v string) {
		if err := db.SetMeta(k, v); err != nil {
			t.Fatalf("SetMeta(%s): %v", k, err)
		}
	}
	setMeta("pcap_name", "capture.pcap")
	setMeta("pcap_size", "48213")
	setMeta("pcap_sha256", "9f2ce1")
	setMeta("packets", "42")
	setMeta("streams", "3")
	setMeta("duration_ns", "2450000000")
	setMeta("tool_version", "devel")

	streams := []model.Stream{
		{ID: 1, Proto: "ftp", SrcIP: "10.0.0.1", SrcPort: 50000, DstIP: "10.0.0.2", DstPort: 21,
			StartTS: ts(100), EndTS: ts(2400), BytesC2S: 134, BytesS2C: 402, Packets: 14,
			FirstPacket: 1, LastPacket: 14},
		{ID: 2, Proto: "http", SrcIP: "10.0.0.3", SrcPort: 4444, DstIP: "10.0.0.4", DstPort: 80,
			StartTS: ts(300), EndTS: ts(900), BytesC2S: 200, BytesS2C: 800, Packets: 8,
			FirstPacket: 15, LastPacket: 22},
		{ID: 3, Proto: "dns", SrcIP: "10.0.0.5", SrcPort: 53000, DstIP: "10.0.0.6", DstPort: 53,
			StartTS: ts(500), EndTS: ts(600), BytesC2S: 48, BytesS2C: 96, Packets: 4,
			FirstPacket: 23, LastPacket: 26, UDP: true},
	}
	if _, err := db.InsertStreams(streams); err != nil {
		t.Fatalf("InsertStreams: %v", err)
	}

	events := []model.Event{
		{ID: 1, TS: ts(100), PacketNo: 1, PacketEnd: 1, Type: model.EvStreamOpened,
			Severity: model.SevInfo, Phase: "recon", StreamID: 1,
			Src: "10.0.0.1:50000", Dst: "10.0.0.2:21", Proto: "ftp",
			Title:   "TCP stream opened",
			Details: map[string]any{"midstream": false}, FindingIDs: []int64{1, 2}},
		{ID: 2, TS: ts(200), PacketNo: 5, Type: model.EvFTPLoginTry,
			Severity: model.SevWarning, Phase: "access", StreamID: 1,
			Src: "10.0.0.1:50000", Dst: "10.0.0.2:21", Proto: "ftp",
			Title: "FTP login attempt user=admin"},
		{ID: 3, TS: ts(300), PacketNo: 7, Type: model.EvFTPLoginFail,
			Severity: model.SevCritical, Phase: "access", StreamID: 1, ParentID: 2,
			Src: "10.0.0.1:50000", Dst: "10.0.0.2:21", Proto: "ftp",
			Title: "FTP login failed"},
		{ID: 4, TS: ts(400), PacketNo: 15, Type: model.EvHTTPTx,
			Severity: model.SevInfo, Phase: "action", StreamID: 2,
			Src: "10.0.0.3:4444", Dst: "10.0.0.4:80", Proto: "http",
			Title: "HTTP transaction GET /x"},
		{ID: 5, TS: ts(500), PacketNo: 23, Type: model.EvDNSQuery,
			Severity: model.SevInfo, Phase: "action", StreamID: 3,
			Src: "10.0.0.5:53000", Dst: "10.0.0.6:53", Proto: "dns",
			Title: "DNS query for example.com"},
		{ID: 6, TS: ts(600), PacketNo: 30, Type: model.EvGroup,
			Severity: model.SevInfo, Phase: "c2", StreamID: 1,
			Src: "10.0.0.1:50000", Dst: "10.0.0.2:21", Proto: "ftp",
			Title: "Burst of 12 similar events"},
		{ID: 7, TS: ts(700), PacketNo: 40, Type: model.EvFileCarved,
			Severity: model.SevWarning, Phase: "exfil", StreamID: 1, ParentID: 6, FileID: 1,
			Src: "10.0.0.1:50000", Dst: "10.0.0.2:21", Proto: "ftp-data",
			Title: "File carved from stream"},
	}
	if _, err := db.InsertEvents(events); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	files := []model.CarvedFile{
		{ID: 1, StreamID: 1, Dir: model.C2S, StartOff: 0, EndOff: 4321,
			Format: "PNG", Ext: "png", Status: "complete", Confidence: "high",
			Size: 4321, MD5: "d41d8cd9", SHA256: "sha-high",
			DisplayName: "secret.png", Path: "carved/sha-high.png", MagicHex: "89504e47"},
		{ID: 2, StreamID: 2, Dir: model.S2C, StartOff: 0, EndOff: 100,
			Format: "GZIP", Ext: "gz", Status: "truncated", Confidence: "medium",
			Size: 100, MD5: "abcd", SHA256: "sha-medium",
			DisplayName: "x.gz", Path: "carved/sha-medium.gz", MagicHex: "1f8b"},
		{ID: 3, StreamID: 3, Dir: model.C2S, StartOff: 0, EndOff: 10,
			Format: "UNKNOWN", Ext: "bin", Status: "corrupt", Confidence: "low",
			Size: 10, MD5: "beef", SHA256: "sha-low",
			DisplayName: "x.bin", Path: "carved/sha-low.bin", MagicHex: "0000"},
	}
	if _, err := db.InsertFiles(files); err != nil {
		t.Fatalf("InsertFiles: %v", err)
	}

	// The high-confidence file has two verdicts: the more severe one wins
	// even though it is older.
	for _, v := range []model.Verdict{
		{SHA256: "sha-high", Source: "malwarebazaar", Status: "malicious",
			Score: 10, Total: 10, CheckedAt: ts(60000)},
		{SHA256: "sha-high", Source: "virustotal", Status: "no_detections",
			Score: 0, Total: 70, CheckedAt: ts(300000)},
	} {
		if err := db.UpsertVerdict(v); err != nil {
			t.Fatalf("UpsertVerdict: %v", err)
		}
	}
}

type fixture struct {
	srv  *Server
	base string
}

func startFixture(t *testing.T, dist fs.FS) *fixture {
	t.Helper()
	dataDir := t.TempDir()
	seedCase(t, dataDir)
	srv, err := New(Config{Token: testToken, DataDir: dataDir, Dist: dist})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return &fixture{srv: srv, base: "http://" + srv.Addr().String()}
}

// get performs a request with the valid token and Host by default.
func (f *fixture) get(t *testing.T, path string, mutate func(*http.Request)) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.base+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Raccoon-Token", testToken)
	if mutate != nil {
		mutate(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return resp, body
}

// getErr expects a JSON error envelope and returns its code.
func (f *fixture) getErr(t *testing.T, path string, wantStatus int) (string, string) {
	t.Helper()
	resp, body := f.get(t, path, nil)
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s: status %d, want %d (body %s)", path, resp.StatusCode, wantStatus, body)
	}
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("GET %s: bad envelope %v: %s", path, err, body)
	}
	return env.Error.Code, env.Error.Message
}

func decodeInto[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	return v
}

// ---------------------------------------------------------------------------
// 10.1: listener, token, host/origin, security headers
// ---------------------------------------------------------------------------

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(Config{DataDir: t.TempDir()}); err == nil {
		t.Fatal("New without token: want error")
	}
	if _, err := New(Config{Token: "x"}); err == nil {
		t.Fatal("New without data dir: want error")
	}
}

func TestTokenRequired(t *testing.T) {
	f := startFixture(t, nil)
	caseURL := "/api/case/" + testID

	t.Run("missing", func(t *testing.T) {
		resp, body := f.get(t, caseURL, func(r *http.Request) { r.Header.Del("X-Raccoon-Token") })
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401 (body %s)", resp.StatusCode, body)
		}
		var env errorEnvelope
		json.Unmarshal(body, &env)
		if env.Error.Code != codeUnauthorized {
			t.Fatalf("code %q, want %q", env.Error.Code, codeUnauthorized)
		}
	})
	t.Run("wrong", func(t *testing.T) {
		resp, _ := f.get(t, caseURL, func(r *http.Request) { r.Header.Set("X-Raccoon-Token", "wrong") })
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", resp.StatusCode)
		}
	})
	t.Run("query parameter", func(t *testing.T) {
		resp, body := f.get(t, caseURL+"?t="+testToken,
			func(r *http.Request) { r.Header.Del("X-Raccoon-Token") })
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200 (body %s)", resp.StatusCode, body)
		}
	})
	t.Run("ui shell needs no token", func(t *testing.T) {
		f := startFixture(t, fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>RACCOON</title>")},
		})
		resp, body := f.get(t, "/", func(r *http.Request) { r.Header.Del("X-Raccoon-Token") })
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200 (body %s)", resp.StatusCode, body)
		}
	})
}

func TestHostAndOriginChecks(t *testing.T) {
	f := startFixture(t, nil)
	caseURL := "/api/case/" + testID

	t.Run("bad host", func(t *testing.T) {
		resp, body := f.get(t, caseURL, func(r *http.Request) { r.Host = "evil.example" })
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403 (body %s)", resp.StatusCode, body)
		}
		var env errorEnvelope
		json.Unmarshal(body, &env)
		if env.Error.Code != codeForbidden {
			t.Fatalf("code %q, want %q", env.Error.Code, codeForbidden)
		}
	})
	t.Run("host with wrong port", func(t *testing.T) {
		resp, _ := f.get(t, caseURL, func(r *http.Request) { r.Host = "127.0.0.1:1" })
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", resp.StatusCode)
		}
	})
	t.Run("cross origin", func(t *testing.T) {
		resp, _ := f.get(t, caseURL, func(r *http.Request) {
			r.Header.Set("Origin", "http://evil.example")
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", resp.StatusCode)
		}
	})
	t.Run("matching origin", func(t *testing.T) {
		resp, _ := f.get(t, caseURL, func(r *http.Request) {
			r.Header.Set("Origin", "http://"+r.Host)
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
	})
	t.Run("localhost host accepted", func(t *testing.T) {
		resp, _ := f.get(t, caseURL, func(r *http.Request) {
			r.Host = "localhost:" + f.srv.port
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	f := startFixture(t, fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")},
	})
	for _, path := range []string{"/", "/api/case/" + testID, "/api/nope"} {
		resp, _ := f.get(t, path, nil)
		h := resp.Header
		if got := h.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
			t.Errorf("%s: CSP %q", path, got)
		}
		if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options %q", path, got)
		}
		if got := h.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy %q", path, got)
		}
		resp.Body.Close()
	}
}

func TestUnknownAPIRouteIsJSON404(t *testing.T) {
	f := startFixture(t, nil)
	for _, path := range []string{"/api/nope", "/api/case/" + testID + "/bogus", "/api/case/x/y/z"} {
		code, _ := f.getErr(t, path, http.StatusNotFound)
		if code != codeNotFound {
			t.Errorf("%s: code %q, want %q", path, code, codeNotFound)
		}
	}
}

func TestStaticSPA(t *testing.T) {
	dist := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("<!doctype html><title>RACCOON</title>")},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('app')")},
	}
	f := startFixture(t, dist)

	t.Run("root serves index", func(t *testing.T) {
		resp, body := f.get(t, "/", nil)
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "RACCOON") {
			t.Fatalf("GET /: %d %s", resp.StatusCode, body)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("Content-Type %q", ct)
		}
	})
	t.Run("asset served verbatim", func(t *testing.T) {
		resp, body := f.get(t, "/assets/app.js", nil)
		if resp.StatusCode != http.StatusOK || string(body) != "console.log('app')" {
			t.Fatalf("GET /assets/app.js: %d %s", resp.StatusCode, body)
		}
	})
	t.Run("extensionless path falls back to index", func(t *testing.T) {
		resp, body := f.get(t, "/timeline", nil)
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "RACCOON") {
			t.Fatalf("GET /timeline: %d %s", resp.StatusCode, body)
		}
	})
	t.Run("missing asset is 404", func(t *testing.T) {
		resp, _ := f.get(t, "/missing.js", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status %d, want 404", resp.StatusCode)
		}
	})
	t.Run("no dist configured", func(t *testing.T) {
		f := startFixture(t, nil)
		resp, _ := f.get(t, "/", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status %d, want 404", resp.StatusCode)
		}
	})
}

// ---------------------------------------------------------------------------
// 10.2: case metadata
// ---------------------------------------------------------------------------

func TestCaseMetadata(t *testing.T) {
	f := startFixture(t, nil)
	resp, body := f.get(t, "/api/case/"+testID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	c := decodeInto[caseResponse](t, body)
	if c.ID != testID || c.FileName != "capture.pcap" || c.Size != 48213 ||
		c.PCAPSHA256 != "9f2ce1" || c.ToolVersion != "devel" {
		t.Fatalf("identity fields wrong: %+v", c)
	}
	if c.Status != "ready" || c.Stage != "done" || c.Progress != 100 {
		t.Fatalf("status fields: %s/%s/%d, want ready/done/100", c.Status, c.Stage, c.Progress)
	}
	if c.Packets != 42 || c.Streams != 3 || c.Files != 3 || c.Events != 7 {
		t.Fatalf("counts: packets=%d streams=%d files=%d events=%d", c.Packets, c.Streams, c.Files, c.Events)
	}
	if c.DurationNs != 2450000000 {
		t.Fatalf("durationNs %d", c.DurationNs)
	}
	if c.StartedAt != "2026-01-01T12:00:00Z" {
		t.Fatalf("startedAt %q", c.StartedAt)
	}
	if c.FinishedAt != "2026-01-01T12:00:02.45Z" {
		t.Fatalf("finishedAt %q", c.FinishedAt)
	}
	if c.Error != "" {
		t.Fatalf("error %q", c.Error)
	}
}

func TestCaseMetadataUnknownOrMalformed(t *testing.T) {
	f := startFixture(t, nil)
	for _, id := range []string{
		"20260101-120000-aaaaaa", // well formed but no directory
		"not-a-case",
		"20260101-120000-ABCDEF", // upper-case hex is not canonical
		"",                       // /api/case/ has no id segment
	} {
		code, _ := f.getErr(t, "/api/case/"+id, http.StatusNotFound)
		if code != codeNotFound {
			t.Errorf("%s: code %q, want %q", id, code, codeNotFound)
		}
	}
}

func TestCaseMetadataRunning(t *testing.T) {
	f := startFixture(t, nil)
	run := NewRunState(testID, "upload.pcap", 1234, fixtureCreated)
	f.srv.Track(run)
	run.SetProgress("read", 40)

	resp, body := f.get(t, "/api/case/"+testID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	c := decodeInto[caseResponse](t, body)
	if c.Status != "running" || c.Stage != "read" || c.Progress != 40 {
		t.Fatalf("run fields: %s/%s/%d, want running/read/40", c.Status, c.Stage, c.Progress)
	}
	if c.FileName != "upload.pcap" || c.Size != 1234 {
		t.Fatalf("run identity: %q/%d", c.FileName, c.Size)
	}

	run.Finish("")
	resp, body = f.get(t, "/api/case/"+testID, nil)
	c = decodeInto[caseResponse](t, body)
	if c.Status != "ready" || c.Stage != "done" || c.Progress != 100 || c.FinishedAt == "" {
		t.Fatalf("after Finish: %+v", c)
	}

	// A failed run reports the error message.
	run2 := NewRunState("20260102-120000-bbbbbb", "bad.pcap", 1, fixtureCreated)
	f.srv.Track(run2)
	run2.Finish("the file does not look like a PCAP")
	resp, body = f.get(t, "/api/case/20260102-120000-bbbbbb", nil)
	c = decodeInto[caseResponse](t, body)
	if c.Status != "failed" || c.Error != "the file does not look like a PCAP" {
		t.Fatalf("failed run: %+v", c)
	}
}

// ---------------------------------------------------------------------------
// 10.2: events
// ---------------------------------------------------------------------------

func idsOf(items []jsonEvent) []int64 {
	out := make([]int64, len(items))
	for i, e := range items {
		out[i] = e.ID
	}
	return out
}

func eqInt64s(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEventsDefaultExcludesChildren(t *testing.T) {
	f := startFixture(t, nil)
	resp, body := f.get(t, "/api/case/"+testID+"/events", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	page := decodeInto[eventsPage](t, body)
	if !eqInt64s(idsOf(page.Items), []int64{1, 2, 4, 5, 6}) {
		t.Fatalf("ids %v, want [1 2 4 5 6]", idsOf(page.Items))
	}
	if page.NextCursor != "" {
		t.Fatalf("nextCursor %q, want empty", page.NextCursor)
	}
	// Serialization checks on the first item.
	e := page.Items[0]
	if e.TS != "2026-01-01T12:00:00.1Z" || e.Type != "STREAM_OPENED" ||
		e.Severity != "info" || e.Phase != "recon" || e.Proto != "ftp" ||
		e.Src != "10.0.0.1:50000" || e.Dst != "10.0.0.2:21" || e.StreamID != 1 {
		t.Fatalf("event 1: %+v", e)
	}
	if e.Details == nil || e.FindingIDs == nil || len(e.FindingIDs) != 2 {
		t.Fatalf("event 1 details/findingIds: %+v", e)
	}
}

func TestEventsFilters(t *testing.T) {
	f := startFixture(t, nil)
	cases := []struct {
		name  string
		query string
		want  []int64
	}{
		{"flat includes children", "flat=1", []int64{1, 2, 3, 4, 5, 6, 7}},
		{"parent", "parent=2", []int64{3}},
		{"parent group", "parent=6", []int64{7}},
		{"severity set", "severity=info,warning", []int64{1, 2, 4, 5, 6}},
		{"severity critical with flat", "severity=critical&flat=1", []int64{3}},
		{"type set", "type=FTP_LOGIN_FAILED,HTTP_TRANSACTION&flat=1", []int64{3, 4}},
		{"phase", "phase=c2", []int64{6}},
		{"proto", "proto=dns", []int64{5}},
		{"search", "q=dns", []int64{5}},
		{"from inclusive", "from=2026-01-01T12:00:00.4Z", []int64{4, 5, 6}},
		{"to exclusive", "to=2026-01-01T12:00:00.4Z", []int64{1, 2}},
		{"combined", "severity=warning&phase=exfil&flat=1", []int64{7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := f.get(t, "/api/case/"+testID+"/events?"+tc.query, nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			page := decodeInto[eventsPage](t, body)
			if !eqInt64s(idsOf(page.Items), tc.want) {
				t.Fatalf("ids %v, want %v", idsOf(page.Items), tc.want)
			}
		})
	}
}

func TestEventsInvalidQuery(t *testing.T) {
	f := startFixture(t, nil)
	bad := []string{
		"severity=bogus",
		"phase=bogus",
		"proto=bogus",
		"limit=0",
		"limit=1001",
		"limit=abc",
		"cursor=not-a-cursor",
		"from=not-a-time",
		"to=2026-13-45T99:00:00Z",
		"parent=-1",
		"parent=abc",
	}
	for _, q := range bad {
		code, msg := f.getErr(t, "/api/case/"+testID+"/events?"+q, http.StatusBadRequest)
		if code != codeInvalidQuery {
			t.Errorf("%s: code %q, want %q (%s)", q, code, codeInvalidQuery, msg)
		}
	}
	if _, msg := f.getErr(t, "/api/case/"+testID+"/events?limit=1001", http.StatusBadRequest); !strings.Contains(msg, "limit") {
		t.Errorf("limit message %q should mention limit", msg)
	}
}

func TestEventsPagination(t *testing.T) {
	f := startFixture(t, nil)
	resp, body := f.get(t, "/api/case/"+testID+"/events?limit=2", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	p1 := decodeInto[eventsPage](t, body)
	if !eqInt64s(idsOf(p1.Items), []int64{1, 2}) || p1.NextCursor == "" {
		t.Fatalf("page1: ids=%v cursor=%q", idsOf(p1.Items), p1.NextCursor)
	}
	resp, body = f.get(t, "/api/case/"+testID+"/events?limit=2&cursor="+p1.NextCursor, nil)
	p2 := decodeInto[eventsPage](t, body)
	if !eqInt64s(idsOf(p2.Items), []int64{4, 5}) || p2.NextCursor == "" {
		t.Fatalf("page2: ids=%v cursor=%q", idsOf(p2.Items), p2.NextCursor)
	}
	resp, body = f.get(t, "/api/case/"+testID+"/events?limit=2&cursor="+p2.NextCursor, nil)
	p3 := decodeInto[eventsPage](t, body)
	if !eqInt64s(idsOf(p3.Items), []int64{6}) || p3.NextCursor != "" {
		t.Fatalf("page3: ids=%v cursor=%q", idsOf(p3.Items), p3.NextCursor)
	}
}

func TestEventsUnknownCase(t *testing.T) {
	f := startFixture(t, nil)
	code, _ := f.getErr(t, "/api/case/20260101-120000-aaaaaa/events", http.StatusNotFound)
	if code != codeNotFound {
		t.Fatalf("code %q", code)
	}
}

// ---------------------------------------------------------------------------
// 10.2: files
// ---------------------------------------------------------------------------

func TestFilesConfidenceFilter(t *testing.T) {
	f := startFixture(t, nil)
	cases := []struct {
		query string
		want  []int64
	}{
		{"", []int64{1, 2}}, // low hidden by default
		{"confidence=all", []int64{1, 2, 3}},
		{"confidence=high", []int64{1}},
		{"confidence=medium", []int64{2}},
	}
	for _, tc := range cases {
		resp, body := f.get(t, "/api/case/"+testID+"/files?"+tc.query, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d: %s", tc.query, resp.StatusCode, body)
		}
		page := decodeInto[filesPage](t, body)
		var got []int64
		for _, item := range page.Items {
			got = append(got, item.ID)
		}
		if !eqInt64s(got, tc.want) {
			t.Fatalf("%s: ids %v, want %v", tc.query, got, tc.want)
		}
	}
	code, _ := f.getErr(t, "/api/case/"+testID+"/files?confidence=bogus", http.StatusBadRequest)
	if code != codeInvalidQuery {
		t.Fatalf("bad confidence: code %q", code)
	}
}

func TestFilesVerdicts(t *testing.T) {
	f := startFixture(t, nil)
	resp, body := f.get(t, "/api/case/"+testID+"/files?confidence=all", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	page := decodeInto[filesPage](t, body)
	byID := map[int64]jsonFile{}
	for _, item := range page.Items {
		byID[item.ID] = item
	}
	// The most severe verdict wins over the most recent one.
	v := byID[1].Verdict
	if v == nil || v.Status != "malicious" || v.Source != "malwarebazaar" {
		t.Fatalf("file 1 verdict: %+v", v)
	}
	// A file without verdicts omits the field entirely.
	if byID[2].Verdict != nil {
		t.Fatalf("file 2 verdict: %+v", byID[2].Verdict)
	}
	// Serialization of the rest of the record.
	f1 := byID[1]
	if f1.Dir != "c2s" || f1.Format != "PNG" || f1.Confidence != "high" ||
		f1.Size != 4321 || f1.DisplayName != "secret.png" || f1.MagicHex != "89504e47" {
		t.Fatalf("file 1: %+v", f1)
	}
	if byID[3].Dir != "c2s" {
		t.Fatalf("file 3 dir: %q", byID[3].Dir)
	}
	if byID[2].Dir != "s2c" {
		t.Fatalf("file 2 dir: %q", byID[2].Dir)
	}
}

// ---------------------------------------------------------------------------
// 10.2: streams
// ---------------------------------------------------------------------------

func TestStreamsListAndFilters(t *testing.T) {
	f := startFixture(t, nil)
	cases := []struct {
		name  string
		query string
		want  []int64
	}{
		{"all", "", []int64{1, 2, 3}},
		{"proto", "proto=dns", []int64{3}},
		{"search ip", "q=10.0.0.2", []int64{1}},
		{"search port", "q=:53", []int64{3}},
		{"search proto", "q=http", []int64{2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := f.get(t, "/api/case/"+testID+"/streams?"+tc.query, nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			page := decodeInto[streamsPage](t, body)
			var got []int64
			for _, s := range page.Items {
				got = append(got, s.ID)
			}
			if !eqInt64s(got, tc.want) {
				t.Fatalf("%s: ids %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestStreamsSerialization(t *testing.T) {
	f := startFixture(t, nil)
	resp, body := f.get(t, "/api/case/"+testID+"/streams?proto=ftp", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	page := decodeInto[streamsPage](t, body)
	if len(page.Items) != 1 {
		t.Fatalf("items %d", len(page.Items))
	}
	s := page.Items[0]
	if s.ID != 1 || s.Proto != "ftp" || s.SrcIP != "10.0.0.1" || s.SrcPort != 50000 ||
		s.DstIP != "10.0.0.2" || s.DstPort != 21 || s.BytesC2S != 134 || s.BytesS2C != 402 ||
		s.Packets != 14 || s.FirstPacket != 1 || s.LastPacket != 14 ||
		s.Midstream || s.HasGaps || s.UDP {
		t.Fatalf("stream: %+v", s)
	}
	if s.StartTS != "2026-01-01T12:00:00.1Z" || s.EndTS != "2026-01-01T12:00:02.4Z" {
		t.Fatalf("timestamps: %q %q", s.StartTS, s.EndTS)
	}
}

func TestStreamsPaginationAndValidation(t *testing.T) {
	f := startFixture(t, nil)
	resp, body := f.get(t, "/api/case/"+testID+"/streams?limit=2", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page1: status %d: %s", resp.StatusCode, body)
	}
	p1 := decodeInto[streamsPage](t, body)
	var got []int64
	for _, s := range p1.Items {
		got = append(got, s.ID)
	}
	if !eqInt64s(got, []int64{1, 2}) || p1.NextCursor == "" {
		t.Fatalf("page1: ids=%v cursor=%q", got, p1.NextCursor)
	}
	resp, body = f.get(t, "/api/case/"+testID+"/streams?limit=2&cursor="+p1.NextCursor, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page2: status %d: %s", resp.StatusCode, body)
	}
	p2 := decodeInto[streamsPage](t, body)
	got = got[:0]
	for _, s := range p2.Items {
		got = append(got, s.ID)
	}
	if !eqInt64s(got, []int64{3}) || p2.NextCursor != "" {
		t.Fatalf("page2: ids=%v cursor=%q", got, p2.NextCursor)
	}
	for _, q := range []string{"proto=bogus", "limit=0", "limit=1001", "cursor=zzz"} {
		code, _ := f.getErr(t, "/api/case/"+testID+"/streams?"+q, http.StatusBadRequest)
		if code != codeInvalidQuery {
			t.Errorf("%s: code %q", q, code)
		}
	}
	code, _ := f.getErr(t, "/api/case/20260101-120000-aaaaaa/streams", http.StatusNotFound)
	if code != codeNotFound {
		t.Fatalf("unknown case: code %q", code)
	}
}
