package timeline

import (
	"context"
	"testing"

	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/pipeline"
	"github.com/tokio-drift/raccoon/internal/resource"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

func TestIsSynthetic(t *testing.T) {
	cases := []struct {
		typ  model.EventType
		want bool
	}{
		{model.EvFinding, true},
		{model.EvGroup, true},
		{model.EvStreamOpened, false},
		{model.EvTCPAnomaly, false},
		{model.EvFTPLoginTry, false},
		{model.EvFTPLoginOK, false},
		{model.EvFTPLoginFail, false},
		{model.EvFTPCommand, false},
		{model.EvFTPTransfer, false},
		{model.EvHTTPTx, false},
		{model.EvDNSQuery, false},
		{model.EvFileCarved, false},
		{model.EvOpaqueRegion, false},
		{model.EvVerdict, false},
	}
	for _, c := range cases {
		if got := IsSynthetic(model.Event{Type: c.typ}); got != c.want {
			t.Errorf("IsSynthetic(%s) = %v, want %v", c.typ, got, c.want)
		}
	}
}

func TestHasEvidence(t *testing.T) {
	cases := []struct {
		name string
		ev   model.Event
		want bool
	}{
		{"full range", model.Event{StreamID: 1, PacketNo: 3, PacketEnd: 5}, true},
		{"single packet", model.Event{StreamID: 1, PacketNo: 3, PacketEnd: 3}, true},
		{"no stream", model.Event{PacketNo: 3, PacketEnd: 5}, false},
		{"no packets", model.Event{StreamID: 1}, false},
		{"empty range", model.Event{StreamID: 1, PacketNo: 0, PacketEnd: 0}, false},
		{"inverted range", model.Event{StreamID: 1, PacketNo: 5, PacketEnd: 3}, false},
	}
	for _, c := range cases {
		if got := HasEvidence(c.ev); got != c.want {
			t.Errorf("%s: HasEvidence = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestLinkEvidencePacketRangeNormalisation covers the range rules of
// linkEvidence: defaults, degenerate starts, inversion clamping and the
// stream-row fallback, including its precedence over a known range end.
func TestLinkEvidencePacketRangeNormalisation(t *testing.T) {
	streams := []model.Stream{{ID: 4, FirstPacket: 10, LastPacket: 25}}
	cases := []struct {
		name    string
		ev      model.Event
		wantNo  uint64
		wantEnd uint64
	}{
		{"end defaults to start", model.Event{StreamID: 4, PacketNo: 5}, 5, 5},
		{"start defaults to end", model.Event{StreamID: 4, PacketEnd: 7}, 7, 7},
		{"intact range untouched", model.Event{StreamID: 4, PacketNo: 3, PacketEnd: 9}, 3, 9},
		{"inverted range clamped", model.Event{StreamID: 4, PacketNo: 9, PacketEnd: 3}, 9, 9},
		{"unknown without sources stays unknown", model.Event{}, 0, 0},
		{"stream row fills full range", model.Event{StreamID: 4}, 10, 25},
		{"known end beats stream row", model.Event{StreamID: 4, PacketEnd: 7}, 7, 7},
		{"known start keeps its own end", model.Event{StreamID: 4, PacketNo: 12}, 12, 12},
	}
	for _, c := range cases {
		events := []model.Event{c.ev}
		linkEvidence(events, nil, streams)
		if events[0].PacketNo != c.wantNo || events[0].PacketEnd != c.wantEnd {
			t.Errorf("%s: range = [%d,%d], want [%d,%d]",
				c.name, events[0].PacketNo, events[0].PacketEnd, c.wantNo, c.wantEnd)
		}
	}
}

// TestLinkEvidenceFromCarvedFile covers file-derived events (THREAT_VERDICT)
// acquiring their file id, stream id and packet range from the FILE_CARVED
// anchor, from the CarvedFile row, or from the stream row.
func TestLinkEvidenceFromCarvedFile(t *testing.T) {
	const sha = "abc123"
	carved := model.Event{
		TS:        100,
		PacketNo:  40,
		PacketEnd: 41,
		Type:      model.EvFileCarved,
		StreamID:  3,
		FileID:    9,
		Details:   map[string]any{"sha256": sha},
	}
	files := []model.CarvedFile{{ID: 9, StreamID: 3, SHA256: sha}}
	streams := []model.Stream{{ID: 3, FirstPacket: 38, LastPacket: 50}}

	t.Run("from carve anchor", func(t *testing.T) {
		events := []model.Event{
			carved,
			{TS: 101, Type: model.EvVerdict, FileID: 9, Title: "verdict"},
		}
		linkEvidence(events, files, streams)
		got := events[1]
		if got.StreamID != 3 || got.PacketNo != 40 || got.PacketEnd != 41 {
			t.Errorf("verdict evidence = stream %d [%d,%d], want stream 3 [40,41]",
				got.StreamID, got.PacketNo, got.PacketEnd)
		}
		if !HasEvidence(got) {
			t.Error("verdict lacks evidence after linking")
		}
	})

	t.Run("file id resolved from sha", func(t *testing.T) {
		events := []model.Event{
			carved,
			{TS: 101, Type: model.EvVerdict, Details: map[string]any{"sha256": sha}},
		}
		linkEvidence(events, files, streams)
		got := events[1]
		if got.FileID != 9 {
			t.Errorf("FileID = %d, want 9", got.FileID)
		}
		if got.StreamID != 3 || got.PacketNo != 40 || got.PacketEnd != 41 {
			t.Errorf("verdict evidence = stream %d [%d,%d], want stream 3 [40,41]",
				got.StreamID, got.PacketNo, got.PacketEnd)
		}
	})

	t.Run("carve row and stream row without carve event", func(t *testing.T) {
		events := []model.Event{
			{TS: 101, Type: model.EvVerdict, FileID: 9, Title: "verdict"},
		}
		linkEvidence(events, files, streams)
		got := events[0]
		if got.StreamID != 3 || got.PacketNo != 38 || got.PacketEnd != 50 {
			t.Errorf("verdict evidence = stream %d [%d,%d], want stream 3 [38,50]",
				got.StreamID, got.PacketNo, got.PacketEnd)
		}
	})

	t.Run("no sources leaves event unanchored", func(t *testing.T) {
		events := []model.Event{{TS: 101, Type: model.EvVerdict, Title: "verdict"}}
		linkEvidence(events, nil, nil)
		if HasEvidence(events[0]) {
			t.Errorf("evidence = [%d,%d] stream %d, want unanchored",
				events[0].PacketNo, events[0].PacketEnd, events[0].StreamID)
		}
	})

	t.Run("carve event keeps its own evidence", func(t *testing.T) {
		events := []model.Event{carved}
		linkEvidence(events, files, streams)
		got := events[0]
		if got.StreamID != 3 || got.PacketNo != 40 || got.PacketEnd != 41 || got.FileID != 9 {
			t.Errorf("FILE_CARVED changed: stream %d [%d,%d] file %d",
				got.StreamID, got.PacketNo, got.PacketEnd, got.FileID)
		}
	})
}

// TestBuildLinksEvidence checks the full Build path: evidence is backfilled
// and normalised before ordering, synthetic events stay exempt, and events
// that already carry evidence keep it.
func TestBuildLinksEvidence(t *testing.T) {
	const sha = "abc123"
	events := []model.Event{
		// Intact event: untouched.
		{TS: 10, PacketNo: 5, PacketEnd: 6, Type: model.EvTCPAnomaly, StreamID: 2},
		// Verdict without a carve event in the batch: stream from the carved
		// row, packets from the stream row.
		{TS: 20, Type: model.EvVerdict, FileID: 9, Details: map[string]any{"sha256": sha}},
		// Event that knows its stream but not its packets.
		{TS: 30, Type: model.EvOpaqueRegion, StreamID: 2},
		// Event missing its range end.
		{TS: 40, PacketNo: 7, Type: model.EvDNSQuery, StreamID: 2},
		// Synthetic event: exempt from evidence.
		{TS: 50, Type: model.EvFinding, Title: "synthetic finding"},
	}
	opts := Options{
		Files:   []model.CarvedFile{{ID: 9, StreamID: 2, SHA256: sha}},
		Streams: []model.Stream{{ID: 2, FirstPacket: 10, LastPacket: 25}},
	}
	built := Build(events, opts)
	if len(built) != 5 {
		t.Fatalf("len = %d, want 5", len(built))
	}

	byType := make(map[model.EventType]model.Event, len(built))
	for _, e := range built {
		byType[e.Type] = e
	}

	if e := byType[model.EvTCPAnomaly]; !HasEvidence(e) || e.PacketNo != 5 || e.PacketEnd != 6 {
		t.Errorf("TCP_ANOMALY evidence = stream %d [%d,%d], want intact [5,6]",
			e.StreamID, e.PacketNo, e.PacketEnd)
	}
	if e := byType[model.EvVerdict]; !HasEvidence(e) || e.StreamID != 2 || e.PacketNo != 10 || e.PacketEnd != 25 {
		t.Errorf("THREAT_VERDICT evidence = stream %d [%d,%d], want stream 2 [10,25]",
			e.StreamID, e.PacketNo, e.PacketEnd)
	}
	if e := byType[model.EvOpaqueRegion]; !HasEvidence(e) || e.PacketNo != 10 || e.PacketEnd != 25 {
		t.Errorf("OPAQUE_REGION evidence = [%d,%d], want stream range [10,25]", e.PacketNo, e.PacketEnd)
	}
	if e := byType[model.EvDNSQuery]; e.PacketNo != 7 || e.PacketEnd != 7 {
		t.Errorf("DNS_QUERY range = [%d,%d], want [7,7]", e.PacketNo, e.PacketEnd)
	}
	if e := byType[model.EvFinding]; HasEvidence(e) {
		t.Errorf("synthetic finding acquired evidence [%d,%d] stream %d",
			e.PacketNo, e.PacketEnd, e.StreamID)
	}

	for _, e := range built {
		if IsSynthetic(e) {
			continue
		}
		if !HasEvidence(e) {
			t.Errorf("event %s id %d lacks evidence: stream %d [%d,%d]",
				e.Type, e.ID, e.StreamID, e.PacketNo, e.PacketEnd)
		}
	}
}

// evidenceFixtures are the fixtures whose produced events are checked for
// evidence links: protocols, carving, entropy, anomalies and UDP analysis.
var evidenceFixtures = []string{
	"tcp_gap.pcap",
	"ftp_upload_png.pcap",
	"ftp_bruteforce.pcap",
	"http_get_jpeg_chunked.pcap",
	"dns_queries.pcap",
	"carve_nonstandard_port.pcap",
	"random_data.pcap",
}

// TestEveryNonSyntheticEventHasEvidence runs each fixture through the
// pipeline, builds the timeline from the stored rows and asserts that every
// non-synthetic event carries a stream id referencing a stored stream and a
// non-empty packet range (task 9.4).
func TestEveryNonSyntheticEventHasEvidence(t *testing.T) {
	for _, name := range evidenceFixtures {
		name := name
		t.Run(name, func(t *testing.T) {
			db := runEvidenceFixture(t, name)

			events := loadAllEvents(t, db)
			if len(events) == 0 {
				t.Fatalf("fixture produced no events")
			}
			streams := loadAllStreams(t, db)
			files, err := db.Files(store.FileFilter{Confidence: store.ConfidenceAll})
			if err != nil {
				t.Fatalf("Files: %v", err)
			}

			built := Build(events, Options{Files: files, Streams: streams})
			if len(built) != len(events) {
				t.Fatalf("Build kept %d of %d events", len(built), len(events))
			}

			streamIDs := make(map[int64]bool, len(streams))
			for _, s := range streams {
				streamIDs[s.ID] = true
			}

			checked := 0
			for _, e := range built {
				if IsSynthetic(e) {
					continue
				}
				checked++
				if e.StreamID == 0 {
					t.Errorf("event %s (ts %d) has no stream id", e.Type, e.TS)
					continue
				}
				if !streamIDs[e.StreamID] {
					t.Errorf("event %s (ts %d) references missing stream %d",
						e.Type, e.TS, e.StreamID)
				}
				if e.PacketNo == 0 || e.PacketEnd < e.PacketNo {
					t.Errorf("event %s (ts %d, stream %d) has packet range [%d,%d]",
						e.Type, e.TS, e.StreamID, e.PacketNo, e.PacketEnd)
				}
			}
			if checked != len(built) && checked == 0 {
				t.Errorf("all %d events were synthetic", len(built))
			}
		})
	}
}

// runEvidenceFixture runs the pipeline over a fixture and returns its open
// event store.
func runEvidenceFixture(t *testing.T, name string) *store.DB {
	t.Helper()
	budget, err := resource.NewBudget(256*1024*1024, 0, 2)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	res, err := pipeline.Run(context.Background(), pipeline.Options{
		PCAPPath: testutil.Pcap(t, name),
		BaseDir:  t.TempDir(),
		Budget:   budget,
	})
	if err != nil {
		t.Fatalf("%s: pipeline.Run: %v", name, err)
	}
	db, err := store.Open(res.Case.DB())
	if err != nil {
		t.Fatalf("%s: open DB: %v", name, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// loadAllEvents reads every stored event, including grouped children.
func loadAllEvents(t *testing.T, db *store.DB) []model.Event {
	t.Helper()
	var (
		out    []model.Event
		cursor string
	)
	for {
		page, next, err := db.Events(store.EventFilter{
			Flat:   true,
			Limit:  limits.EventsPageSizeMax,
			Cursor: cursor,
		})
		if err != nil {
			t.Fatalf("Events: %v", err)
		}
		out = append(out, page...)
		if next == "" || len(page) == 0 {
			return out
		}
		cursor = next
	}
}

// loadAllStreams reads every stored stream row.
func loadAllStreams(t *testing.T, db *store.DB) []model.Stream {
	t.Helper()
	var (
		out    []model.Stream
		cursor string
	)
	for {
		page, next, err := db.Streams(store.StreamFilter{
			Limit:  limits.EventsPageSizeMax,
			Cursor: cursor,
		})
		if err != nil {
			t.Fatalf("Streams: %v", err)
		}
		out = append(out, page...)
		if next == "" || len(page) == 0 {
			return out
		}
		cursor = next
	}
}
