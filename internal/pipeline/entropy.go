package pipeline

import (
	"fmt"
	"sort"

	"github.com/tokio-drift/raccoon/internal/entropy"
	"github.com/tokio-drift/raccoon/internal/model"
)

// span is a half-open [start,end) byte range of a stream direction.
type span struct{ start, end int64 }

// subtractRanges returns the parts of [0,length) that no span in covers
// covers. The spans are sorted by start in place; they may overlap.
func subtractRanges(length int64, covers []span) []entropy.Range {
	if length <= 0 {
		return nil
	}
	if len(covers) == 0 {
		return []entropy.Range{{Start: 0, End: length}}
	}
	sort.Slice(covers, func(i, j int) bool { return covers[i].start < covers[j].start })
	var out []entropy.Range
	cursor := int64(0)
	for _, c := range covers {
		if c.start > cursor {
			out = append(out, entropy.Range{Start: cursor, End: c.start})
		}
		if c.end > cursor {
			cursor = c.end
		}
	}
	if cursor < length {
		out = append(out, entropy.Range{Start: cursor, End: length})
	}
	return out
}

// opaqueEvent builds the OPAQUE_REGION event for one merged region.
func opaqueEvent(cs *ClosedStream, appProto string, dir model.Direction, loc *streamLocator, reg entropy.OpaqueRegion) model.Event {
	f := cs.Flow
	streamProto := f.Proto
	if appProto != "" {
		streamProto = appProto
	}
	responder := responderEndpoint(f)
	ts, pktNo, pktEnd := loc.at(dir, reg.Start)
	return model.Event{
		TS:        ts,
		PacketNo:  pktNo,
		PacketEnd: pktEnd,
		Type:      model.EvOpaqueRegion,
		Severity:  model.SevWarning,
		StreamID:  f.ID,
		Src:       joinHostPort(f.Initiator.IP.String(), f.Initiator.Port),
		Dst:       joinHostPort(responder.IP.String(), responder.Port),
		Proto:     streamProto,
		Title:     fmt.Sprintf("Opaque region: %s [%d,%d)", dirName(dir), reg.Start, reg.End),
		Details: map[string]any{
			"dir":      dirName(dir),
			"startOff": reg.Start,
			"endOff":   reg.End,
			"meanH":    reg.MeanH,
		},
	}
}

// entropyInto scans both directions of a closed stream for high-entropy
// regions that no carved file covers, emitting an OPAQUE_REGION event for each.
// carved maps a direction to the extents already carved from it (so carved
// bytes are not flagged again).
func entropyInto(cs *ClosedStream, appProto string, carved map[model.Direction][]span, emit func(model.Event)) error {
	if cs == nil || cs.Flow == nil || cs.Stream == nil {
		return nil
	}
	loc := newStreamLocator(cs, appProto)
	for _, dir := range []model.Direction{model.C2S, model.S2C} {
		length := cs.Stream.Len(dir)
		if length <= 0 {
			continue
		}
		regions := subtractRanges(length, carved[dir])
		if len(regions) == 0 {
			continue
		}
		found, err := entropy.Scan(cs.Stream.ReaderAt(dir), regions)
		if err != nil {
			return fmt.Errorf("pipeline: entropy stream %d %s: %w", cs.Flow.ID, dirName(dir), err)
		}
		for _, reg := range found {
			emit(opaqueEvent(cs, appProto, dir, loc, reg))
		}
	}
	return nil
}
