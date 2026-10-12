package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
)

func openTemp(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "case.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return db, path
}

func TestOpenSchema(t *testing.T) {
	db, path := openTemp(t)

	var uv int
	if err := db.Conn().QueryRow("PRAGMA user_version").Scan(&uv); err != nil || uv != schemaVersion {
		t.Fatalf("user_version=%d err=%v", uv, err)
	}
	for _, tbl := range []string{"streams", "events", "files", "verdicts", "findings", "segments", "meta"} {
		var name string
		if err := db.Conn().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl).Scan(&name); err != nil {
			t.Errorf("table %s missing: %v", tbl, err)
		}
	}
	var jm string
	if err := db.Conn().QueryRow("PRAGMA journal_mode").Scan(&jm); err != nil || jm != "wal" {
		t.Errorf("journal_mode=%q err=%v", jm, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening an existing database must succeed.
	if _, err := Open(path); err != nil {
		t.Fatalf("reopen: %v", err)
	}
}

func TestRefuseNewer(t *testing.T) {
	_, path := openTemp(t)
	conn, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec("PRAGMA user_version = 2"); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	if _, err := Open(path); !errors.Is(err, ErrNewerVersion) {
		t.Fatalf("Open: %v, want ErrNewerVersion", err)
	}
}

func TestRoundTrip(t *testing.T) {
	db, path := openTemp(t)
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if _, err := db.InsertStreams([]model.Stream{{
		ID: 1, Proto: "tcp", SrcIP: "1.2.3.4", SrcPort: 1234, DstIP: "5.6.7.8", DstPort: 80,
		StartTS: 1, EndTS: 2, BytesC2S: 10, BytesS2C: 0, Packets: 1, FirstPacket: 1, LastPacket: 1,
		Midstream: true, HasGaps: false,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertEvents([]model.Event{{
		ID: 1, TS: 5, PacketNo: 1, PacketEnd: 1,
		Type: model.EvTCPAnomaly, Severity: model.SevWarning, Phase: "recon",
		StreamID: 1, Src: "1.2.3.4:1234", Dst: "5.6.7.8:80", Proto: "tcp",
		Title: "gap", Details: map[string]any{"off": 3},
	}, {
		ID: 2, TS: 6, Type: model.EvStreamOpened, Severity: model.SevInfo,
		FindingIDs: []int64{9},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertFiles([]model.CarvedFile{{
		ID: 3, StreamID: 1, Dir: model.C2S, StartOff: 0, EndOff: 4, Format: "png",
		Ext: "png", Status: "complete", Confidence: "high", Size: 4, SHA256: "abc", Path: "carved/x.png",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertSegments([]Segment{
		{StreamID: 1, Dir: model.C2S, Offset: 0, Length: 4, TS: 1, PacketNo: 1},
		{StreamID: 1, Dir: model.S2C, Offset: 0, Length: 6, TS: 2, PacketNo: 2},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertFindings([]model.Finding{{
		ID: 9, Title: "brute", Technique: "T1110", Severity: model.SevCritical,
		EvidenceEventIDs: []int64{2},
	}}); err != nil {
		t.Fatal(err)
	}
	v := model.Verdict{SHA256: "abc", Source: "yara", Status: "malicious", Score: 1, Total: 2,
		Detail: map[string]any{"rule": "Win32_Agent"}, CheckedAt: 7}
	if err := db.UpsertVerdict(v); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertVerdict(v); err != nil {
		t.Fatal(err)
	}
	v.Score = 2
	if err := db.UpsertVerdict(v); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMeta("tool", "raccoon"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMeta("tool", "raccoon2"); err != nil {
		t.Fatal(err)
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}

	ro, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	c := ro.Conn()

	var n int
	if err := c.QueryRow("SELECT count(*) FROM streams").Scan(&n); err != nil || n != 1 {
		t.Errorf("streams=%d err=%v", n, err)
	}
	var midstream int64
	if err := c.QueryRow("SELECT midstream FROM streams WHERE id=1").Scan(&midstream); err != nil || midstream != 1 {
		t.Errorf("midstream=%d err=%v", midstream, err)
	}
	if err := c.QueryRow("SELECT count(*) FROM events").Scan(&n); err != nil || n != 2 {
		t.Errorf("events=%d err=%v", n, err)
	}
	var details string
	if err := c.QueryRow("SELECT details_json FROM events WHERE id=1").Scan(&details); err != nil ||
		details != `{"off":3}` {
		t.Errorf("details=%q err=%v", details, err)
	}
	var fid string
	if err := c.QueryRow("SELECT finding_ids FROM events WHERE id=2").Scan(&fid); err != nil || fid != `[9]` {
		t.Errorf("finding_ids=%q err=%v", fid, err)
	}
	if err := c.QueryRow("SELECT count(*) FROM files WHERE sha256='abc'").Scan(&n); err != nil || n != 1 {
		t.Errorf("files=%d err=%v", n, err)
	}
	if err := c.QueryRow("SELECT count(*) FROM segments").Scan(&n); err != nil || n != 2 {
		t.Errorf("segments=%d err=%v", n, err)
	}
	var dir, off int64
	if err := c.QueryRow("SELECT dir, stream_off FROM segments WHERE stream_id=1 AND dir=0").Scan(&dir, &off); err != nil ||
		dir != 0 || off != 0 {
		t.Errorf("segment dir=%d off=%d err=%v", dir, off, err)
	}
	var score int64
	if err := c.QueryRow("SELECT count(*) FROM verdicts").Scan(&n); err != nil || n != 1 {
		t.Errorf("verdicts=%d err=%v", n, err)
	} else if err := c.QueryRow("SELECT score FROM verdicts").Scan(&score); err != nil || score != 2 {
		t.Errorf("verdict score=%d err=%v (want upserted 2)", score, err)
	}
	if err := c.QueryRow("SELECT count(*) FROM findings").Scan(&n); err != nil || n != 1 {
		t.Errorf("findings=%d err=%v", n, err)
	}
	var tool string
	if err := c.QueryRow("SELECT value FROM meta WHERE key='tool'").Scan(&tool); err != nil || tool != "raccoon2" {
		t.Errorf("meta tool=%q err=%v", tool, err)
	}
}

func TestBatchInsert(t *testing.T) {
	db, _ := openTemp(t)
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// 5 chunks of 500 = 2500 rows, forcing multiple insertBatch flushes.
	for j := 0; j < 5; j++ {
		rows := make([]model.Event, 500)
		for i := range rows {
			rows[i].ID = int64(j*500 + i + 1)
			rows[i].TS = int64(i)
			rows[i].Type = model.EvDNSQuery
		}
		if _, err := db.InsertEvents(rows); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.Conn().QueryRow("SELECT count(*) FROM events").Scan(&n); err != nil || n != 2500 {
		t.Fatalf("events=%d err=%v, want 2500 (batched)", n, err)
	}
}

func TestWriteAfterClose(t *testing.T) {
	db, _ := openTemp(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMeta("k", "v"); !errors.Is(err, ErrClosed) {
		t.Fatalf("SetMeta after Close: %v, want ErrClosed", err)
	}
	if _, err := db.InsertEvents([]model.Event{{Type: model.EvDNSQuery}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("InsertEvents after Close: %v, want ErrClosed", err)
	}
}
