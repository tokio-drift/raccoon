package timeline

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/tokio-drift/raccoon/internal/model"
)

// Store is the persistence interface required to save timeline events.
// *store.DB satisfies this interface.
type Store interface {
	InsertEvents(rows []model.Event) (int64, error)
}

// Options configures timeline construction.
type Options struct {
	// Files, if provided, supplies carved files used to link FileID onto events
	// (such as THREAT_VERDICT events) matching by SHA-256.
	Files []model.CarvedFile
}

// Build merges and sorts events in (ts, packetNo) order with deterministic
// content-only tiebreakers, links FileID and verdict events, and assigns final
// sequential IDs starting from 1.
func Build(events []model.Event, opts ...Options) []model.Event {
	if len(events) == 0 {
		return nil
	}

	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	// 1. Copy events to avoid mutating the caller's slice header.
	out := make([]model.Event, len(events))
	copy(out, events)

	// 2. Link FileID and verdict events.
	linkFilesAndVerdicts(out, opt.Files)

	// 3. Apply core severity rating rules (escalation only).
	for i := range out {
		out[i].Severity = Rate(out[i])
	}

	// 4. Sort events in (ts, packetNo) order with deterministic tiebreakers.
	sortEvents(out)

	// 4. Assign final sequential IDs (1, 2, ..., N), updating ParentID references
	// if any child events were linked to parent events before renumbering.
	oldToNew := make(map[int64]int64, len(out))
	for i := range out {
		newID := int64(i + 1)
		if out[i].ID != 0 {
			oldToNew[out[i].ID] = newID
		}
		out[i].ID = newID
	}

	// Remap ParentID if old IDs were referenced.
	for i := range out {
		if out[i].ParentID != 0 {
			if remapped, ok := oldToNew[out[i].ParentID]; ok {
				out[i].ParentID = remapped
			}
		}
	}

	return out
}

// Save persists the events to the store in batches.
func Save(s Store, events []model.Event) error {
	if s == nil || len(events) == 0 {
		return nil
	}
	const batchSize = 1000
	for start := 0; start < len(events); start += batchSize {
		end := start + batchSize
		if end > len(events) {
			end = len(events)
		}
		if _, err := s.InsertEvents(events[start:end]); err != nil {
			return fmt.Errorf("timeline: save events [%d:%d]: %w", start, end, err)
		}
	}
	return nil
}

// BuildAndStore merges, links, orders, renumbers, and persists events to s.
func BuildAndStore(s Store, events []model.Event, opts ...Options) ([]model.Event, error) {
	built := Build(events, opts...)
	if err := Save(s, built); err != nil {
		return nil, err
	}
	return built, nil
}

// linkFilesAndVerdicts discovers file IDs from FILE_CARVED events and CarvedFile
// records, links missing FileID values on THREAT_VERDICT events matching by SHA-256,
// and ensures stream context (StreamID, endpoints, packet range) is shared.
func linkFilesAndVerdicts(events []model.Event, files []model.CarvedFile) {
	// shaToFileID maps lower-case hex SHA-256 to a carved file ID.
	shaToFileID := make(map[string]int64, len(files))
	for _, f := range files {
		if f.ID != 0 && f.SHA256 != "" {
			shaToFileID[f.SHA256] = f.ID
		}
	}

	// Index existing FILE_CARVED events by fileID and by SHA-256.
	fileCarvedByID := make(map[int64]*model.Event)
	shaToCarvedEvent := make(map[string]*model.Event)

	for i := range events {
		e := &events[i]
		if e.Type == model.EvFileCarved {
			sha := extractSHA256(e)
			if e.FileID != 0 {
				fileCarvedByID[e.FileID] = e
				if sha != "" {
					shaToFileID[sha] = e.FileID
					shaToCarvedEvent[sha] = e
				}
			} else if sha != "" {
				// If FILE_CARVED event itself lacks FileID, resolve from files slice.
				if fid, ok := shaToFileID[sha]; ok {
					e.FileID = fid
					fileCarvedByID[fid] = e
					shaToCarvedEvent[sha] = e
				}
			}
		}
	}

	// Link verdict events (EvVerdict / "THREAT_VERDICT").
	for i := range events {
		e := &events[i]
		if e.Type != model.EvVerdict {
			continue
		}

		sha := extractSHA256(e)

		// 1. Resolve missing FileID on verdict event.
		if e.FileID == 0 && sha != "" {
			if fid, ok := shaToFileID[sha]; ok {
				e.FileID = fid
			}
		}

		// Ensure FileID is recorded in Details map as well.
		if e.FileID != 0 {
			if e.Details == nil {
				e.Details = make(map[string]any)
			}
			if _, ok := e.Details["file_id"]; !ok {
				e.Details["file_id"] = e.FileID
			}
		}

		// 2. Inherit stream metadata from the corresponding FILE_CARVED event if missing.
		var fc *model.Event
		if e.FileID != 0 {
			fc = fileCarvedByID[e.FileID]
		}
		if fc == nil && sha != "" {
			fc = shaToCarvedEvent[sha]
		}

		if fc != nil {
			if e.StreamID == 0 {
				e.StreamID = fc.StreamID
			}
			if e.Src == "" {
				e.Src = fc.Src
			}
			if e.Dst == "" {
				e.Dst = fc.Dst
			}
			if e.Proto == "" {
				e.Proto = fc.Proto
			}
			if e.PacketNo == 0 {
				e.PacketNo = fc.PacketNo
			}
			if e.PacketEnd == 0 {
				e.PacketEnd = fc.PacketEnd
			}
		}
	}
}

// extractSHA256 extracts the lower-case sha256 hash from event Details.
func extractSHA256(e *model.Event) string {
	if e.Details == nil {
		return ""
	}
	if v, ok := e.Details["sha256"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	if v, ok := e.Details["sha"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// sortEvents orders events by (ts, packetNo) and then by content-only fields.
// Content-only tiebreakers (no IDs) keep the order identical across runs even
// when flows are spread over different workers.
func sortEvents(events []model.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		a, b := &events[i], &events[j]
		if a.TS != b.TS {
			return a.TS < b.TS
		}
		if a.PacketNo != b.PacketNo {
			return a.PacketNo < b.PacketNo
		}
		if a.PacketEnd != b.PacketEnd {
			return a.PacketEnd < b.PacketEnd
		}
		if a.Src != b.Src {
			return a.Src < b.Src
		}
		if a.Dst != b.Dst {
			return a.Dst < b.Dst
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		if a.Explain != b.Explain {
			return a.Explain < b.Explain
		}
		return detailsKey(a) < detailsKey(b)
	})
}

// detailsKey returns a deterministic representation of an event's details.
// encoding/json sorts object keys, so equal maps always encode identically.
func detailsKey(e *model.Event) string {
	if e.Details == nil {
		return ""
	}
	b, err := json.Marshal(e.Details)
	if err != nil {
		return ""
	}
	return string(b)
}
