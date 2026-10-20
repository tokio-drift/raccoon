package timeline

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

// timelineFixtures are the fixtures whose finished timelines are pinned by a
// golden file in testdata/expected/timeline/ (task 9.5).
var timelineFixtures = []string{
	"ftp_upload_png.pcap",
	"ftp_bruteforce.pcap",
}

// timelineEntry is the deterministic projection of one built timeline event.
// Stream ids are omitted for the same reason as in the protocol goldens (6.7):
// flow ids depend on worker interleaving. Evidence linking itself is covered
// by TestEveryNonSyntheticEventHasEvidence.
type timelineEntry struct {
	ID        int64           `json:"id"`
	Type      model.EventType `json:"type"`
	Severity  model.Severity  `json:"severity"`
	TS        int64           `json:"ts"`
	PacketNo  uint64          `json:"packetNo"`
	PacketEnd uint64          `json:"packetEnd"`
	Src       string          `json:"src"`
	Dst       string          `json:"dst"`
	Proto     string          `json:"proto"`
	Title     string          `json:"title"`
	FileID    int64           `json:"fileId,omitempty"`
	Details   map[string]any  `json:"details,omitempty"`
}

// timelineDoc is the golden file shape for testdata/expected/timeline/*.json.
type timelineDoc struct {
	Name   string          `json:"name"`
	Events []timelineEntry `json:"events"`
}

// TestGoldenTimeline pins the finished timeline — order, final ids, severities
// and human titles after Build — for the two FTP fixtures (task 9.5).
// Regenerate with: go test ./internal/timeline/ -run TestGoldenTimeline -update
func TestGoldenTimeline(t *testing.T) {
	for _, name := range timelineFixtures {
		name := name
		base := strings.TrimSuffix(name, filepath.Ext(name))
		t.Run(base, func(t *testing.T) {
			db := runEvidenceFixture(t, name)
			built := buildFixtureTimeline(t, db)
			got := projectTimeline(built)
			if len(got) == 0 {
				t.Fatalf("fixture produced no timeline events")
			}

			// Content guards: a golden regenerated from a broken build must
			// still fail here instead of silently blessing the regression.
			switch base {
			case "ftp_upload_png":
				assertUploadPNGTimeline(t, got)
			case "ftp_bruteforce":
				assertBruteForceTimeline(t, got)
			}

			// want must start empty when comparing (see 6.7): json.Unmarshal
			// merges into existing maps/slices, so seeding outside -update
			// would leak current values into the decoded golden.
			want := timelineDoc{Name: name}
			if testutil.Updating() {
				want.Events = got
			}
			testutil.LoadExpected(t, filepath.Join("timeline", base+".json"), &want)
			if want.Name != name {
				t.Errorf("golden name = %q, want %q", want.Name, name)
			}
			if !reflect.DeepEqual(got, want.Events) {
				t.Errorf("timeline differs from golden %s\n got: %s\nwant: %s",
					base+".json", timelineJSON(t, got), timelineJSON(t, want.Events))
			}
		})
	}
}

// TestTimelineOrdering checks the finished fixture timelines are ordered by
// (ts, packetNo) with contiguous ids 1..N, that the order does not depend on
// the input order of the events, and that a second Build over an already
// built timeline is a no-op (task 9.5).
func TestTimelineOrdering(t *testing.T) {
	for _, name := range timelineFixtures {
		name := name
		base := strings.TrimSuffix(name, filepath.Ext(name))
		t.Run(base, func(t *testing.T) {
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
			opts := Options{Files: files, Streams: streams}

			built := Build(events, opts)
			assertTimelineOrder(t, built)

			// Determinism: the same events fed in reverse must produce the
			// identical timeline (content-only tiebreakers).
			reversed := make([]model.Event, len(events))
			for i := range events {
				reversed[i] = events[len(events)-1-i]
			}
			again := Build(reversed, opts)
			if !reflect.DeepEqual(projectTimeline(built), projectTimeline(again)) {
				t.Errorf("order depends on input order\n first: %s\n second: %s",
					timelineJSON(t, projectTimeline(built)), timelineJSON(t, projectTimeline(again)))
			}

			// Idempotence: rebuilding an already built timeline changes nothing.
			redone := Build(built, opts)
			if !reflect.DeepEqual(projectTimeline(built), projectTimeline(redone)) {
				t.Errorf("second Build changed the timeline\n first: %s\nsecond: %s",
					timelineJSON(t, projectTimeline(built)), timelineJSON(t, projectTimeline(redone)))
			}
		})
	}
}

// TestSeverityOnlyEscalates verifies the timeline never lowers a severity
// (task 9.5). Build rates each event with Rate, so every event a fixture
// producer stored — including ones already escalated by the carver or the
// intel stage — must come out at least at its stored rank. The synthetic
// subtest pins the guarantee at the Build level for pre-escalated events.
func TestSeverityOnlyEscalates(t *testing.T) {
	for _, name := range evidenceFixtures {
		name := name
		t.Run(name, func(t *testing.T) {
			db := runEvidenceFixture(t, name)
			events := loadAllEvents(t, db)
			if len(events) == 0 {
				t.Fatalf("fixture produced no events")
			}
			for _, e := range events {
				if got := Rate(e); Rank(got) < Rank(e.Severity) {
					t.Errorf("%s: Rate lowered %s (ts %d) severity %q -> %q",
						name, e.Type, e.TS, e.Severity, got)
				}
			}
		})
	}

	t.Run("pre-escalated survives Build", func(t *testing.T) {
		events := []model.Event{
			// Benign types carrying an already escalated severity must keep it:
			// Rate computes info for them but Escalate preserves the higher rank.
			{TS: 100, PacketNo: 1, PacketEnd: 1, Type: model.EvDNSQuery,
				Severity: model.SevCritical, Src: "10.0.0.1:50000", Dst: "10.0.0.2:53",
				Proto: "dns", Details: map[string]any{"qname": "example.com", "qtype": "A"}},
			{TS: 200, PacketNo: 2, PacketEnd: 2, Type: model.EvFTPCommand,
				Severity: model.SevWarning, Src: "10.0.0.1:50000", Dst: "10.0.0.2:21",
				Proto: "ftp", Details: map[string]any{"command": "LIST"}},
			{TS: 300, PacketNo: 3, PacketEnd: 3, Type: model.EvFileCarved,
				Severity: model.SevCritical, Src: "10.0.0.1:50001", Dst: "10.0.0.2:30000",
				Proto: "tcp", Details: map[string]any{"format": "png", "size": 89,
					"sha256": "6c0328165683e4450da3aea197fe7edb89fe3d858473df79d896f75a975be172"}},
			{TS: 400, PacketNo: 4, PacketEnd: 4, Type: model.EvStreamOpened,
				Severity: model.SevWarning, Src: "10.0.0.1:50000", Dst: "10.0.0.2:21",
				Proto: "ftp"},
		}
		want := []model.Severity{model.SevCritical, model.SevWarning, model.SevCritical, model.SevWarning}

		built := Build(events)
		if len(built) != len(want) {
			t.Fatalf("built %d events, want %d", len(built), len(want))
		}
		for i, e := range built {
			if e.Severity != want[i] {
				t.Errorf("event %s severity = %q, want %q (escalation only)",
					e.Type, e.Severity, want[i])
			}
		}
	})
}

// buildFixtureTimeline loads every stored event, file and stream of a fixture
// case and runs the full timeline Build over them.
func buildFixtureTimeline(t *testing.T, db *store.DB) []model.Event {
	t.Helper()
	events := loadAllEvents(t, db)
	streams := loadAllStreams(t, db)
	files, err := db.Files(store.FileFilter{Confidence: store.ConfidenceAll})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	return Build(events, Options{Files: files, Streams: streams})
}

// projectTimeline maps built events onto the golden projection.
func projectTimeline(events []model.Event) []timelineEntry {
	out := make([]timelineEntry, len(events))
	for i, e := range events {
		out[i] = timelineEntry{
			ID:        e.ID,
			Type:      e.Type,
			Severity:  e.Severity,
			TS:        e.TS,
			PacketNo:  e.PacketNo,
			PacketEnd: e.PacketEnd,
			Src:       e.Src,
			Dst:       e.Dst,
			Proto:     e.Proto,
			Title:     e.Title,
			FileID:    e.FileID,
			Details:   e.Details,
		}
	}
	return out
}

// assertTimelineOrder checks ids are contiguous from 1 and (ts, packetNo) is
// non-decreasing across the built timeline.
func assertTimelineOrder(t *testing.T, built []model.Event) {
	t.Helper()
	for i, e := range built {
		if e.ID != int64(i+1) {
			t.Fatalf("built[%d].ID = %d, want %d", i, e.ID, i+1)
		}
		if i == 0 {
			continue
		}
		prev := built[i-1]
		if e.TS < prev.TS || (e.TS == prev.TS && e.PacketNo < prev.PacketNo) {
			t.Errorf("built[%d] (id %d) out of order: (ts %d, packet %d) follows (ts %d, packet %d)",
				i, e.ID, e.TS, e.PacketNo, prev.TS, prev.PacketNo)
		}
	}
}

// assertUploadPNGTimeline pins the semantic content of the ftp_upload_png
// timeline: one login, three FTP commands, one carved PNG.
func assertUploadPNGTimeline(t *testing.T, got []timelineEntry) {
	t.Helper()
	counts := map[model.EventType]int{}
	for _, e := range got {
		counts[e.Type]++
	}
	wantCounts := map[model.EventType]int{
		model.EvFTPLoginTry: 1,
		model.EvFTPLoginOK:  1,
		model.EvFTPCommand:  3,
		model.EvFileCarved:  1,
	}
	if len(got) != 6 {
		t.Errorf("timeline has %d events, want 6", len(got))
	}
	for typ, want := range wantCounts {
		if counts[typ] != want {
			t.Errorf("%s count = %d, want %d", typ, counts[typ], want)
		}
	}

	for _, e := range got {
		switch e.Type {
		case model.EvFTPLoginOK:
			if e.Title != "FTP login successful as bob" {
				t.Errorf("login title = %q, want %q", e.Title, "FTP login successful as bob")
			}
			// Cleartext credential in Details escalates the login to warning.
			if e.Severity != model.SevWarning {
				t.Errorf("login severity = %q, want %q", e.Severity, model.SevWarning)
			}
		case model.EvFTPCommand:
			if e.Severity != model.SevInfo {
				t.Errorf("FTP command %q severity = %q, want info", e.Title, e.Severity)
			}
		case model.EvFileCarved:
			if e.FileID == 0 {
				t.Error("FILE_CARVED event has no file id")
			}
			if e.Title != "File carved: 6c0328165683.png (PNG, 89 B)" {
				t.Errorf("carve title = %q, want %q", e.Title, "File carved: 6c0328165683.png (PNG, 89 B)")
			}
			if e.Severity != model.SevInfo {
				t.Errorf("carve severity = %q, want info (PNG is not executable)", e.Severity)
			}
		}
	}
}

// assertBruteForceTimeline pins the semantic content of the ftp_bruteforce
// timeline: 40 failed logins after 40 attempts, then bob's success last.
func assertBruteForceTimeline(t *testing.T, got []timelineEntry) {
	t.Helper()
	counts := map[model.EventType]int{}
	for _, e := range got {
		counts[e.Type]++
	}
	wantCounts := map[model.EventType]int{
		model.EvFTPLoginTry:  41,
		model.EvFTPLoginFail: 40,
		model.EvFTPLoginOK:   1,
	}
	if len(got) != 82 {
		t.Errorf("timeline has %d events, want 82", len(got))
	}
	for typ, want := range wantCounts {
		if counts[typ] != want {
			t.Errorf("%s count = %d, want %d", typ, counts[typ], want)
		}
	}

	if first := got[0]; first.Type != model.EvFTPLoginTry || first.Title != "FTP login attempt for user00" {
		t.Errorf("first event = %s %q, want FTP login attempt for user00", first.Type, first.Title)
	}
	last := got[len(got)-1]
	if last.Type != model.EvFTPLoginOK || last.Title != "FTP login successful as bob" {
		t.Errorf("last event = %s %q, want FTP login successful as bob", last.Type, last.Title)
	}
	for _, e := range got {
		switch e.Type {
		case model.EvFTPLoginFail:
			// Cleartext password in Details escalates every failure to warning.
			if e.Severity != model.SevWarning {
				t.Errorf("failure %q severity = %q, want warning", e.Title, e.Severity)
			}
		case model.EvFTPLoginTry:
			if e.Severity != model.SevInfo {
				t.Errorf("attempt %q severity = %q, want info", e.Title, e.Severity)
			}
		}
	}
}

// timelineJSON renders v for failure messages.
func timelineJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
