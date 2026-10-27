package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/model"
)

// seedBasic inserts one row of every persistable type and returns the database.
func seedBasic(t *testing.T) *DB {
	t.Helper()
	db, _ := openTemp(t)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})

	if _, err := db.InsertStreams([]model.Stream{
		{ID: 1, Proto: "ftp", SrcIP: "10.0.0.1", SrcPort: 50000, DstIP: "10.0.0.2", DstPort: 21,
			StartTS: 100, EndTS: 900, BytesC2S: 134, BytesS2C: 402, Packets: 14,
			FirstPacket: 1, LastPacket: 14, HasGaps: true},
		{ID: 2, ParentID: 1, Proto: "ftp-data", SrcIP: "10.0.0.2", SrcPort: 20, DstIP: "10.0.0.1", DstPort: 40000,
			StartTS: 200, EndTS: 800, BytesC2S: 0, BytesS2C: 4321, Packets: 6,
			FirstPacket: 4, LastPacket: 9, UDP: true},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertEvents([]model.Event{
		{ID: 1, TS: 100, PacketNo: 1, PacketEnd: 3, Type: model.EvStreamOpened, Severity: model.SevInfo,
			Phase: "recon", StreamID: 1, Src: "10.0.0.1:50000", Dst: "10.0.0.2:21", Proto: "ftp",
			Title: "TCP stream opened", Details: map[string]any{"midstream": "false"}},
		{ID: 2, TS: 200, PacketNo: 4, PacketEnd: 4, Type: model.EvFTPLoginFail, Severity: model.SevWarning,
			StreamID: 1, Src: "10.0.0.1:50000", Dst: "10.0.0.2:21", Proto: "ftp",
			Title: "FTP login failed", FindingIDs: []int64{9}},
		{ID: 3, TS: 300, PacketNo: 5, PacketEnd: 5, Type: model.EvFTPLoginOK, Severity: model.SevInfo,
			ParentID: 2, StreamID: 1, Src: "10.0.0.1:50000", Dst: "10.0.0.2:21", Proto: "ftp",
			Title: "FTP login succeeded"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertFiles([]model.CarvedFile{
		{ID: 1, StreamID: 2, Dir: model.S2C, StartOff: 0, EndOff: 4321, Format: "PNG", Ext: "png",
			Status: "complete", Confidence: "high", Size: 4321, MD5: "md5a", SHA256: "sha-a",
			DisplayName: "secret.png", Path: "carved/sha-a.png", MagicHex: "89504e47"},
		{ID: 2, StreamID: 2, Dir: model.S2C, StartOff: 10, EndOff: 20, Format: "PDF", Ext: "pdf",
			Status: "truncated", Confidence: "medium", Size: 10, MD5: "md5b", SHA256: "sha-b",
			DisplayName: "a.pdf", Path: "carved/sha-b.pdf", MagicHex: "25504446"},
		{ID: 3, StreamID: 2, Dir: model.S2C, StartOff: 30, EndOff: 40, Format: "ZIP", Ext: "zip",
			Status: "corrupt", Confidence: "low", Size: 10, MD5: "md5c", SHA256: "sha-c",
			DisplayName: "c.zip", Path: "carved/sha-c.zip", MagicHex: "504b0304"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertSegments([]Segment{
		{StreamID: 1, Dir: model.C2S, Offset: 0, Length: 4, TS: 100, PacketNo: 1},
		{StreamID: 1, Dir: model.C2S, Offset: 4, Length: 6, TS: 101, PacketNo: 2},
		{StreamID: 1, Dir: model.S2C, Offset: 0, Length: 8, TS: 102, PacketNo: 3},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertFindings([]model.Finding{{
		ID: 9, Title: "brute force", Technique: "T1110", Severity: model.SevCritical,
		Explanation: "many failures", EvidenceEventIDs: []int64{2},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertVerdict(model.Verdict{SHA256: "sha-a", Source: "virustotal",
		Status: "no_detections", Score: 0, Total: 70, CheckedAt: 400}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertVerdict(model.Verdict{SHA256: "sha-a", Source: "yara",
		Status: "malicious", Score: 2, Total: 2, Detail: map[string]any{"rule": "EICAR"},
		CheckedAt: 401}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMeta("tool", "raccoon"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMeta("packets", "42"); err != nil {
		t.Fatal(err)
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestEventsQuery(t *testing.T) {
	db := seedBasic(t)

	all, next, err := db.Events(EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	// Event 3 has a parent, so it is excluded from the default top-level query.
	if len(all) != 2 || next != "" {
		t.Fatalf("all=%d next=%q, want 2 events and no cursor", len(all), next)
	}
	if all[0].ID != 1 || all[1].ID != 2 {
		t.Fatalf("order: %d,%d", all[0].ID, all[1].ID)
	}
	if all[1].Severity != model.SevWarning || all[1].Type != model.EvFTPLoginFail {
		t.Fatalf("event 2 = %+v", all[1])
	}
	if !reflect.DeepEqual(all[1].FindingIDs, []int64{9}) {
		t.Fatalf("finding ids = %v", all[1].FindingIDs)
	}

	// Detail values are decoded as JSON.
	if got := all[0].Details["midstream"]; got != "false" {
		t.Fatalf("details midstream = %#v", got)
	}

	// Numeric details decode as float64.
	if _, err := db.InsertEvents([]model.Event{{ID: 4, TS: 400, Type: model.EvTCPAnomaly,
		Severity: model.SevWarning, Details: map[string]any{"off": 3}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	got, _, err := db.Events(EventFilter{Types: []model.EventType{model.EvTCPAnomaly}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Details["off"] != float64(3) {
		t.Fatalf("numeric details = %#v", got)
	}

	findings, err := db.Findings()
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ID != 9 || findings[0].Technique != "T1110" {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestEventsFilters(t *testing.T) {
	db := seedBasic(t)

	// Severity set.
	sev, _, err := db.Events(EventFilter{Severities: []model.Severity{model.SevWarning, model.SevCritical}})
	if err != nil {
		t.Fatal(err)
	}
	if len(sev) != 1 || sev[0].ID != 2 {
		t.Fatalf("severity set = %v", sev)
	}

	// Type set.
	typ, _, err := db.Events(EventFilter{Types: []model.EventType{model.EvFTPLoginOK}})
	if err != nil {
		t.Fatal(err)
	}
	// The only login-success event is a child, so a top-level query hides it...
	if len(typ) != 0 {
		t.Fatalf("type set without flat = %v", typ)
	}
	// ...but Flat reveals it.
	typ, _, err = db.Events(EventFilter{Types: []model.EventType{model.EvFTPLoginOK}, Flat: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(typ) != 1 || typ[0].ID != 3 {
		t.Fatalf("type set with flat = %v", typ)
	}

	// Parent returns the children of one event.
	parentID := int64(2)
	kids, _, err := db.Events(EventFilter{Parent: &parentID})
	if err != nil {
		t.Fatal(err)
	}
	if len(kids) != 1 || kids[0].ID != 3 {
		t.Fatalf("parent = %v", kids)
	}

	// Parent takes precedence over Flat.
	kidsFlat, _, err := db.Events(EventFilter{Parent: &parentID, Flat: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(kidsFlat) != 1 || kidsFlat[0].ID != 3 {
		t.Fatalf("parent+flat = %v", kidsFlat)
	}

	// Phase and proto.
	phase, _, err := db.Events(EventFilter{Phase: "recon"})
	if err != nil {
		t.Fatal(err)
	}
	if len(phase) != 1 || phase[0].ID != 1 {
		t.Fatalf("phase = %v", phase)
	}
	proto, _, err := db.Events(EventFilter{Proto: "ftp", Flat: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(proto) != 3 {
		t.Fatalf("proto = %v", proto)
	}

	// Free-text search over title and details.
	q, _, err := db.Events(EventFilter{Query: "FAILED", Flat: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 1 || q[0].ID != 2 {
		t.Fatalf("query title = %v", q)
	}
	q, _, err = db.Events(EventFilter{Query: "midstream", Flat: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 1 || q[0].ID != 1 {
		t.Fatalf("query details = %v", q)
	}

	// Time bounds: from inclusive, to exclusive.
	bounded, _, err := db.Events(EventFilter{From: 200, To: 300, Flat: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(bounded) != 1 || bounded[0].ID != 2 {
		t.Fatalf("time bounds = %v", bounded)
	}
}

func TestEventsKeysetPagination(t *testing.T) {
	db, _ := openTemp(t)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})

	// Several events share a timestamp to exercise the (ts, id) tie-break.
	const total = 25
	rows := make([]model.Event, total)
	for i := range rows {
		rows[i] = model.Event{ID: int64(i + 1), TS: int64(i / 3), Type: model.EvDNSQuery, Severity: model.SevInfo}
	}
	if _, err := db.InsertEvents(rows); err != nil {
		t.Fatal(err)
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}

	for _, pageSize := range []int{1, 4, 7, 25, 100} {
		seen := make(map[int64]int)
		var (
			order  []model.Event
			cursor string
			pages  int
			lastTS int64
			lastID int64
		)
		for {
			page, next, err := db.Events(EventFilter{Limit: pageSize, Cursor: cursor})
			if err != nil {
				t.Fatalf("pageSize=%d: %v", pageSize, err)
			}
			if len(page) > pageSize {
				t.Fatalf("pageSize=%d: page has %d rows", pageSize, len(page))
			}
			for _, e := range page {
				seen[e.ID]++
				if lastID != 0 && (e.TS < lastTS || (e.TS == lastTS && e.ID <= lastID)) {
					t.Fatalf("pageSize=%d: order broke at ts=%d id=%d after %d/%d",
						pageSize, e.TS, e.ID, lastTS, lastID)
				}
				lastTS, lastID = e.TS, e.ID
				order = append(order, e)
			}
			pages++
			if next == "" {
				break
			}
			cursor = next
			if pages > total+2 {
				t.Fatalf("pageSize=%d: too many pages", pageSize)
			}
		}
		if len(order) != total {
			t.Fatalf("pageSize=%d: got %d rows, want %d", pageSize, len(order), total)
		}
		for id, n := range seen {
			if n != 1 {
				t.Fatalf("pageSize=%d: event %d returned %d times", pageSize, id, n)
			}
		}
	}
}

func TestEventsInvalidCursor(t *testing.T) {
	db := seedBasic(t)
	if _, _, err := db.Events(EventFilter{Cursor: "!!not-base64!!"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("err = %v, want ErrInvalidCursor", err)
	}
	// Valid base64 but not an event (ts,id) cursor.
	if _, _, err := db.Events(EventFilter{Cursor: encodeIDCursor(5)}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("err = %v, want ErrInvalidCursor", err)
	}
}

func TestFilesQuery(t *testing.T) {
	db := seedBasic(t)

	def, err := db.Files(FileFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(def) != 2 || def[0].ID != 1 || def[1].ID != 2 {
		t.Fatalf("default files = %v", def)
	}
	if def[0].Dir != model.S2C || def[0].SHA256 != "sha-a" || def[0].StreamID != 2 {
		t.Fatalf("file 1 = %+v", def[0])
	}

	all, err := db.Files(FileFilter{Confidence: ConfidenceAll})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("all files = %d, want 3", len(all))
	}

	high, err := db.Files(FileFilter{Confidence: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if len(high) != 1 || high[0].ID != 1 {
		t.Fatalf("high files = %v", high)
	}

	low, err := db.Files(FileFilter{Confidence: "low"})
	if err != nil {
		t.Fatal(err)
	}
	if len(low) != 1 || low[0].ID != 3 {
		t.Fatalf("low files = %v", low)
	}
}

func TestStreamsQuery(t *testing.T) {
	db := seedBasic(t)

	all, next, err := db.Streams(StreamFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || next != "" {
		t.Fatalf("streams = %d next=%q", len(all), next)
	}
	if all[1].ParentID != 1 || !all[1].UDP || all[0].BytesC2S != 134 || !all[0].HasGaps {
		t.Fatalf("stream payload = %+v / %+v", all[0], all[1])
	}

	ftp, _, err := db.Streams(StreamFilter{Proto: "ftp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ftp) != 1 || ftp[0].ID != 1 {
		t.Fatalf("proto filter = %v", ftp)
	}

	// Query matches source, destination and proto.
	byDst, _, err := db.Streams(StreamFilter{Query: "10.0.0.2:21"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byDst) != 1 || byDst[0].ID != 1 {
		t.Fatalf("dst query = %v", byDst)
	}
	byProto, _, err := db.Streams(StreamFilter{Query: "FTP-DATA"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byProto) != 1 || byProto[0].ID != 2 {
		t.Fatalf("proto query = %v", byProto)
	}

	// Keyset pagination over ids.
	page1, cursor, err := db.Streams(StreamFilter{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 1 || page1[0].ID != 1 || cursor == "" {
		t.Fatalf("page1 = %v cursor=%q", page1, cursor)
	}
	page2, cursor2, err := db.Streams(StreamFilter{Limit: 1, Cursor: cursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 1 || page2[0].ID != 2 || cursor2 != "" {
		t.Fatalf("page2 = %v cursor=%q", page2, cursor2)
	}

	if _, _, err := db.Streams(StreamFilter{Cursor: "%%"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("err = %v, want ErrInvalidCursor", err)
	}
}

func TestStreamByID(t *testing.T) {
	db := seedBasic(t)

	s, err := db.StreamByID(1)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != 1 || s.Proto != "ftp" || s.SrcPort != 50000 || s.DstPort != 21 {
		t.Fatalf("stream = %+v", s)
	}
	if _, err := db.StreamByID(99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestSegmentsFor(t *testing.T) {
	db := seedBasic(t)

	c2s, err := db.SegmentsFor(1, model.C2S)
	if err != nil {
		t.Fatal(err)
	}
	if len(c2s) != 2 || c2s[0].Offset != 0 || c2s[1].Offset != 4 {
		t.Fatalf("c2s segments = %+v", c2s)
	}
	if c2s[1].Length != 6 || c2s[1].PacketNo != 2 || c2s[1].Dir != model.C2S {
		t.Fatalf("c2s segment 2 = %+v", c2s[1])
	}
	s2c, err := db.SegmentsFor(1, model.S2C)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2c) != 1 || s2c[0].Length != 8 {
		t.Fatalf("s2c segments = %+v", s2c)
	}
	none, err := db.SegmentsFor(99, model.C2S)
	if err != nil || len(none) != 0 {
		t.Fatalf("unknown stream segments = %v err=%v", none, err)
	}
}

func TestVerdictsQuery(t *testing.T) {
	db := seedBasic(t)

	v, err := db.Verdicts("sha-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 2 {
		t.Fatalf("verdicts = %v", v)
	}
	// Ordered by source: virustotal before yara.
	if v[0].Source != "virustotal" || v[1].Source != "yara" {
		t.Fatalf("verdict order = %s,%s", v[0].Source, v[1].Source)
	}
	if v[1].Status != "malicious" || v[1].Score != 2 || v[1].Detail["rule"] != "EICAR" {
		t.Fatalf("yara verdict = %+v", v[1])
	}
	none, err := db.Verdicts("nope")
	if err != nil || len(none) != 0 {
		t.Fatalf("unknown sha = %v err=%v", none, err)
	}
}

func TestMetaQuery(t *testing.T) {
	db := seedBasic(t)

	m, err := db.Meta()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"tool": "raccoon", "packets": "42"}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("meta = %v, want %v", m, want)
	}
}

// seedManyEvents inserts n events in one batch with a realistic mix of types and
// severities. Timestamps are unique and ascending so the (ts, id) order is well
// defined. It is used to size the first-page query benchmark.
func seedManyEvents(tb testing.TB, n int) *DB {
	tb.Helper()
	db, _ := openTempTB(tb)
	types := []model.EventType{model.EvDNSQuery, model.EvHTTPTx, model.EvFTPLoginFail, model.EvStreamOpened}
	sevs := []model.Severity{model.SevInfo, model.SevWarning, model.SevCritical}
	rows := make([]model.Event, n)
	for i := range rows {
		rows[i] = model.Event{
			ID:       int64(i + 1),
			TS:       int64(i + 1),
			Type:     types[i%len(types)],
			Severity: sevs[i%len(sevs)],
			Proto:    "tcp",
			Title:    fmt.Sprintf("event %d", i),
		}
	}
	if _, err := db.InsertEvents(rows); err != nil {
		tb.Fatal(err)
	}
	if err := db.Flush(); err != nil {
		tb.Fatal(err)
	}
	return db
}

// openTempTB is the testing.TB variant of openTemp.
func openTempTB(tb testing.TB) (*DB, string) {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "case.db")
	db, err := Open(path)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		if err := db.Close(); err != nil {
			tb.Fatal(err)
		}
	})
	return db, path
}

// BenchmarkEventsFirstPage measures the first page of a severity+type filtered
// query over 200 000 events. Target: under 50 ms per page.
func BenchmarkEventsFirstPage(b *testing.B) {
	db := seedManyEvents(b, 200_000)
	filter := EventFilter{
		Severities: []model.Severity{model.SevWarning},
		Types:      []model.EventType{model.EvFTPLoginFail},
		Limit:      200,
	}

	// Warm up and time a single page explicitly so the target is visible even
	// if the benchmark loop changes.
	start := time.Now()
	page, next, err := db.Events(filter)
	if err != nil {
		b.Fatal(err)
	}
	single := time.Since(start)
	if len(page) != 200 || next == "" {
		b.Fatalf("first page: %d rows, next=%q", len(page), next)
	}
	b.ReportMetric(float64(single.Microseconds())/1000, "ms/page")
	if single > 50*time.Millisecond {
		b.Errorf("first page took %v, want < 50ms", single)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := db.Events(filter); err != nil {
			b.Fatal(err)
		}
	}
}

// TestEventsFirstPageUnder50ms verifies the non-functional query target on a
// 200 000 event database. It is skipped in short mode because seeding the rows
// dominates the runtime.
func TestEventsFirstPageUnder50ms(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200k-event seed in short mode")
	}
	db := seedManyEvents(t, 200_000)
	filter := EventFilter{
		Severities: []model.Severity{model.SevWarning},
		Types:      []model.EventType{model.EvFTPLoginFail},
		Limit:      200,
	}
	page, next, err := db.Events(filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 200 || next == "" {
		t.Fatalf("first page: %d rows, next=%q", len(page), next)
	}
	start := time.Now()
	if _, _, err := db.Events(filter); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Fatalf("first page took %v, want < 50ms", elapsed)
	}
	if testing.Verbose() {
		t.Logf("first page over 200k events: %v", elapsed)
	}
}
