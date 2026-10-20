package timeline

import (
	"path/filepath"
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
)

func TestBuildEmpty(t *testing.T) {
	if got := Build(nil); got != nil {
		t.Errorf("Build(nil) = %v, want nil", got)
	}
	if got := Build([]model.Event{}); got != nil {
		t.Errorf("Build([]) = %v, want nil", got)
	}
}

func TestBuildOrdering(t *testing.T) {
	events := []model.Event{
		{TS: 300, PacketNo: 3, Title: "Three"},
		{TS: 100, PacketNo: 1, Title: "One"},
		{TS: 200, PacketNo: 2, Title: "Two"},
		{TS: 100, PacketNo: 2, Title: "One-B"},
	}

	built := Build(events)
	if len(built) != 4 {
		t.Fatalf("len = %d, want 4", len(built))
	}

	// Expected order:
	// 1: TS=100, PacketNo=1
	// 2: TS=100, PacketNo=2
	// 3: TS=200, PacketNo=2
	// 4: TS=300, PacketNo=3
	wantTitles := []string{"One", "One-B", "Two", "Three"}
	for i, want := range wantTitles {
		if built[i].Title != want {
			t.Errorf("built[%d].Title = %q, want %q", i, built[i].Title, want)
		}
		if built[i].ID != int64(i+1) {
			t.Errorf("built[%d].ID = %d, want %d", i, built[i].ID, i+1)
		}
	}
}

func TestBuildTiebreakers(t *testing.T) {
	// Identical TS and PacketNo, differing by Type/Title/Details.
	events := []model.Event{
		{TS: 100, PacketNo: 1, Type: model.EvHTTPTx, Title: "Zebra"},
		{TS: 100, PacketNo: 1, Type: model.EvDNSQuery, Title: "Alpha"},
		{TS: 100, PacketNo: 1, Type: model.EvDNSQuery, Title: "Beta"},
	}

	built1 := Build(events)
	// Run again with reverse input order to ensure determinism.
	eventsRev := []model.Event{events[2], events[1], events[0]}
	built2 := Build(eventsRev)

	for i := range built1 {
		if built1[i].Title != built2[i].Title {
			t.Errorf("non-deterministic order at index %d: %q vs %q", i, built1[i].Title, built2[i].Title)
		}
	}

	// EvDNSQuery < EvHTTPTransaction; Alpha < Beta
	if built1[0].Title != "Alpha" || built1[1].Title != "Beta" || built1[2].Title != "Zebra" {
		t.Errorf("unexpected tiebreaker ordering: %+v", built1)
	}
}

func TestBuildIDAssignmentAndParentRemap(t *testing.T) {
	// Event 2 is a child of Event 1 with old IDs 50 and 99.
	events := []model.Event{
		{ID: 99, TS: 200, PacketNo: 2, ParentID: 50, Title: "Child"},
		{ID: 50, TS: 100, PacketNo: 1, Title: "Parent"},
	}

	built := Build(events)
	if len(built) != 2 {
		t.Fatalf("len = %d, want 2", len(built))
	}

	// After sorting: Parent comes first (ID=1), Child second (ID=2).
	if built[0].Title != "Parent" || built[0].ID != 1 {
		t.Errorf("Parent ID = %d, want 1", built[0].ID)
	}
	if built[1].Title != "Child" || built[1].ID != 2 {
		t.Errorf("Child ID = %d, want 2", built[1].ID)
	}
	// Child's ParentID should now point to new ID 1.
	if built[1].ParentID != 1 {
		t.Errorf("Child ParentID = %d, want 1", built[1].ParentID)
	}
}

func TestBuildLinkFileIDAndVerdicts(t *testing.T) {
	const testHash = "6c0328165683e4450da3aea197fe7edb89fe3d858473df79d896f75a975be172"
	const fileID int64 = 42

	events := []model.Event{
		{
			TS:        1000,
			PacketNo:  10,
			PacketEnd: 15,
			Type:      model.EvFileCarved,
			Severity:  model.SevInfo,
			StreamID:  5,
			Src:       "10.0.0.1:50000",
			Dst:       "10.0.0.2:21",
			Proto:     "ftp-data",
			FileID:    fileID,
			Title:     "File carved: secret.png",
			Details: map[string]any{
				"sha256": testHash,
				"size":   1234,
			},
		},
		{
			TS:       1050,
			PacketNo: 0, // async verdict event may not have packet bounds
			Type:     model.EvVerdict,
			Severity: model.SevCritical,
			FileID:   0, // unlinked initial FileID
			Title:    "Threat verdict: malicious (yara)",
			Details: map[string]any{
				"sha256": testHash,
				"source": "yara",
				"status": "malicious",
			},
		},
	}

	built := Build(events)
	if len(built) != 2 {
		t.Fatalf("len = %d, want 2", len(built))
	}

	verdictEv := built[1]
	if verdictEv.Type != model.EvVerdict {
		t.Fatalf("expected verdict event at index 1, got %v", verdictEv.Type)
	}

	// 1. FileID must be linked.
	if verdictEv.FileID != fileID {
		t.Errorf("verdict FileID = %d, want %d", verdictEv.FileID, fileID)
	}
	if verdictEv.Details["file_id"] != fileID {
		t.Errorf("verdict Details[file_id] = %v, want %d", verdictEv.Details["file_id"], fileID)
	}

	// 2. Stream context must be inherited.
	if verdictEv.StreamID != 5 {
		t.Errorf("verdict StreamID = %d, want 5", verdictEv.StreamID)
	}
	if verdictEv.Src != "10.0.0.1:50000" || verdictEv.Dst != "10.0.0.2:21" {
		t.Errorf("verdict endpoints = %s -> %s, want 10.0.0.1:50000 -> 10.0.0.2:21", verdictEv.Src, verdictEv.Dst)
	}
	if verdictEv.Proto != "ftp-data" {
		t.Errorf("verdict Proto = %q, want \"ftp-data\"", verdictEv.Proto)
	}
	if verdictEv.PacketNo != 10 || verdictEv.PacketEnd != 15 {
		t.Errorf("verdict packet bounds = [%d, %d], want [10, 15]", verdictEv.PacketNo, verdictEv.PacketEnd)
	}
}

func TestBuildAndStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "timeline_case.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	events := []model.Event{
		{TS: 500, PacketNo: 5, Type: model.EvHTTPTx, Severity: model.SevInfo, Title: "HTTP 2"},
		{TS: 100, PacketNo: 1, Type: model.EvDNSQuery, Severity: model.SevInfo, Title: "DNS 1"},
		{TS: 300, PacketNo: 3, Type: model.EvHTTPTx, Severity: model.SevInfo, Title: "HTTP 1"},
	}

	built, err := BuildAndStore(db, events)
	if err != nil {
		t.Fatalf("BuildAndStore: %v", err)
	}
	if len(built) != 3 {
		t.Fatalf("built count = %d, want 3", len(built))
	}

	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	stored, _, err := db.Events(store.EventFilter{Flat: true})
	if err != nil {
		t.Fatalf("query stored events: %v", err)
	}
	if len(stored) != 3 {
		t.Fatalf("stored count = %d, want 3", len(stored))
	}

	wantTitles := []string{"DNS 1", "HTTP 1", "HTTP 2"}
	for i, want := range wantTitles {
		if stored[i].Title != want {
			t.Errorf("stored[%d].Title = %q, want %q", i, stored[i].Title, want)
		}
		if stored[i].ID != int64(i+1) {
			t.Errorf("stored[%d].ID = %d, want %d", i, stored[i].ID, i+1)
		}
	}
}
