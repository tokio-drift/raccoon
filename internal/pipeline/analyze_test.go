package pipeline

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/resource"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

// expProtocolEvent is the deterministic, id-free projection of a protocol
// event stored in a golden file. Stream ids are intentionally omitted because
// flow ids depend on worker interleaving; the test asserts separately that
// every event references an existing, correctly classified stream.
type expProtocolEvent struct {
	Type      model.EventType `json:"type"`
	Severity  model.Severity  `json:"severity"`
	TS        int64           `json:"ts"`
	PacketNo  uint64          `json:"packetNo"`
	PacketEnd uint64          `json:"packetEnd"`
	Src       string          `json:"src"`
	Dst       string          `json:"dst"`
	Proto     string          `json:"proto"`
	Title     string          `json:"title"`
	Details   map[string]any  `json:"details,omitempty"`
}

type expProtocolDoc struct {
	Name   string             `json:"name"`
	Events []expProtocolEvent `json:"events"`
}

func TestEndToEndProtocolFixtures(t *testing.T) {
	fixtures := []string{
		"ftp_bruteforce.pcap",
		"ftp_upload_png.pcap",
		"ftp_download_pdf_port31337.pcap",
		"http_get_jpeg_chunked.pcap",
		"dns_queries.pcap",
	}
	for _, name := range fixtures {
		name := name
		base := strings.TrimSuffix(name, filepath.Ext(name))
		t.Run(base, func(t *testing.T) {
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

			events := protocolEvents(t, db)
			assertProtocolEventMetadata(t, db, events)

			got := make([]expProtocolEvent, len(events))
			for i, e := range events {
				got[i] = expProtocolEvent{
					Type:      e.Type,
					Severity:  e.Severity,
					TS:        e.TS,
					PacketNo:  e.PacketNo,
					PacketEnd: e.PacketEnd,
					Src:       e.Src,
					Dst:       e.Dst,
					Proto:     e.Proto,
					Title:     e.Title,
					Details:   e.Details,
				}
			}

			// want must start empty when comparing: json.Unmarshal reuses an
			// existing slice and merges into existing maps, so aliasing got
			// here would leak current values into the decoded golden. The seed
			// is only needed so -update writes the freshly produced events.
			want := expProtocolDoc{Name: name}
			if testutil.Updating() {
				want.Events = got
			}
			testutil.LoadExpected(t, filepath.Join("events", base+".json"), &want)
			if !reflect.DeepEqual(got, want.Events) {
				t.Errorf("events differ from golden %s\n got: %s\nwant: %s",
					base+".json", mustJSON(t, got), mustJSON(t, want.Events))
			}
		})
	}
}

func protocolEvents(t *testing.T, db *store.DB) []model.Event {
	t.Helper()
	rows, err := db.Conn().Query(`SELECT ts,packet_no,packet_end,type,severity,stream_id,` +
		`src,dst,proto,title,details_json FROM events ORDER BY id ASC`)
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	defer rows.Close()

	var out []model.Event
	for rows.Next() {
		var (
			ev         model.Event
			ts, pkt    int64
			end        int64
			typ, sev   string
			streamID   sql.NullInt64
			title      string
			details    sql.NullString
			src, dst   string
			protoValue string
		)
		if err := rows.Scan(&ts, &pkt, &end, &typ, &sev, &streamID,
			&src, &dst, &protoValue, &title, &details); err != nil {
			t.Fatalf("scan event: %v", err)
		}
		ev.TS = ts
		ev.PacketNo = uint64(pkt)
		ev.PacketEnd = uint64(end)
		ev.Type = model.EventType(typ)
		ev.Severity = model.Severity(sev)
		ev.StreamID = streamID.Int64
		ev.Src = src
		ev.Dst = dst
		ev.Proto = protoValue
		ev.Title = title
		if details.Valid && details.String != "" {
			if err := json.Unmarshal([]byte(details.String), &ev.Details); err != nil {
				t.Fatalf("decode details for %s: %v", typ, err)
			}
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate events: %v", err)
	}
	return out
}

func assertProtocolEventMetadata(t *testing.T, db *store.DB, events []model.Event) {
	t.Helper()
	rows, err := db.Conn().Query(`SELECT id,proto FROM streams`)
	if err != nil {
		t.Fatalf("query streams: %v", err)
	}
	streamProto := make(map[int64]string)
	for rows.Next() {
		var id int64
		var proto string
		if err := rows.Scan(&id, &proto); err != nil {
			rows.Close()
			t.Fatalf("scan stream: %v", err)
		}
		streamProto[id] = proto
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate streams: %v", err)
	}

	allowed := map[string]bool{"ftp": true, "http": true, "dns": true}
	if len(events) == 0 {
		t.Fatal("expected protocol events, got none")
	}
	for _, e := range events {
		// Protocol events must carry an application proto. FILE_CARVED events
		// are emitted for every stream, including ones with no matched
		// analyzer, so they may carry the transport proto ("tcp") instead.
		if e.Type != model.EvFileCarved && !allowed[e.Proto] {
			t.Errorf("event proto = %q, want ftp/http/dns", e.Proto)
		}
		if e.StreamID == 0 {
			t.Errorf("event %s has no stream id", e.Type)
			continue
		}
		proto, ok := streamProto[e.StreamID]
		if !ok {
			t.Errorf("event %s references missing stream %d", e.Type, e.StreamID)
			continue
		}
		if e.Type != model.EvFileCarved && proto != e.Proto {
			t.Errorf("event %s proto = %q, stream %d proto = %q", e.Type, e.Proto, e.StreamID, proto)
		}
		if e.Src == "" || e.Dst == "" {
			t.Errorf("event %s missing endpoints: src=%q dst=%q", e.Type, e.Src, e.Dst)
		}
		if e.PacketNo == 0 || e.PacketEnd < e.PacketNo {
			t.Errorf("event %s packet range = [%d,%d]", e.Type, e.PacketNo, e.PacketEnd)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
