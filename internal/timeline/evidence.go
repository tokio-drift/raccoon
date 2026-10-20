package timeline

import "github.com/tokio-drift/raccoon/internal/model"

// fileAnchor is the packet-level evidence a FILE_CARVED event records for one
// carved file: the stream it was carved from and the packet range covering
// the carve offset.
type fileAnchor struct {
	streamID  int64
	packetNo  uint64
	packetEnd uint64
}

// IsSynthetic reports whether an event is synthetic: produced by an analysis
// stage from other events rather than anchored to capture packets. Synthetic
// events carry their evidence through ParentID or FindingIDs instead of a
// direct stream id and packet range, so they are exempt from HasEvidence.
// No core event type is synthetic; the FINDING and GROUP events of the PLUS
// phases are.
func IsSynthetic(e model.Event) bool {
	switch e.Type {
	case model.EvFinding, model.EvGroup:
		return true
	default:
		return false
	}
}

// HasEvidence reports whether an event carries the evidence links required of
// every non-synthetic event: a stream id and a non-empty packet range
// [PacketNo, PacketEnd]. linkEvidence guarantees the range is never empty or
// inverted; a non-synthetic event still fails this check when no evidence
// source (carve anchor, carved-file row or stream row) was available.
func HasEvidence(e model.Event) bool {
	return e.StreamID != 0 && e.PacketNo != 0 && e.PacketEnd >= e.PacketNo
}

// linkEvidence gives every event its evidence links: the packet range it
// describes, the stream it belongs to and, where one exists, the carved file
// it refers to. Missing pieces are backfilled, in order, from the FILE_CARVED
// event of the same file, from the CarvedFile row, and from the stream row;
// the result is then normalised to a non-empty, non-inverted packet range.
//
// The sources consulted for an event are:
//   - file id:       Details["sha256"] ("sha" accepted) against carved rows
//   - stream id:     the FILE_CARVED anchor for its file, else the CarvedFile row
//   - packet range:  the FILE_CARVED anchor for its file, else its stream row's
//     first/last packet
//
// Events that already know part of their range never have it widened: a known
// PacketEnd with a missing PacketNo degenerates to a single packet, and a
// known PacketNo with a missing PacketEnd ends at that packet.
func linkEvidence(events []model.Event, files []model.CarvedFile, streams []model.Stream) {
	streamByID := make(map[int64]model.Stream, len(streams))
	for _, s := range streams {
		if s.ID != 0 {
			streamByID[s.ID] = s
		}
	}

	shaToFileID := make(map[string]int64, len(files))
	fileToStreamID := make(map[int64]int64, len(files))
	for _, f := range files {
		if f.ID == 0 {
			continue
		}
		if f.SHA256 != "" {
			shaToFileID[f.SHA256] = f.ID
		}
		if f.StreamID != 0 {
			fileToStreamID[f.ID] = f.StreamID
		}
	}

	// FILE_CARVED events are the packet-level anchor for their file.
	byFileID := make(map[int64]fileAnchor)
	bySHA := make(map[string]fileAnchor)
	for i := range events {
		e := &events[i]
		if e.Type != model.EvFileCarved {
			continue
		}
		a := fileAnchor{streamID: e.StreamID, packetNo: e.PacketNo, packetEnd: e.PacketEnd}
		sha := extractSHA256(e)
		if e.FileID != 0 {
			byFileID[e.FileID] = a
		}
		if sha != "" {
			bySHA[sha] = a
			if e.FileID != 0 {
				shaToFileID[sha] = e.FileID
			}
		}
	}

	for i := range events {
		e := &events[i]

		if e.Type != model.EvFileCarved {
			sha := extractSHA256(e)

			// File id: an event carrying a file hash links to the carved
			// file row (a THREAT_VERDICT inserted before the timeline saw
			// its FILE_CARVED event arrives here with only its hash).
			if e.FileID == 0 && sha != "" {
				if fid, ok := shaToFileID[sha]; ok {
					e.FileID = fid
				}
			}

			// Stream id and packet range from the file's carve anchor.
			if e.FileID != 0 && (e.StreamID == 0 || e.PacketNo == 0) {
				a, ok := byFileID[e.FileID]
				if !ok && sha != "" {
					a, ok = bySHA[sha]
				}
				if ok {
					if e.StreamID == 0 {
						e.StreamID = a.streamID
					}
					if e.PacketNo == 0 && a.packetNo != 0 {
						e.PacketNo = a.packetNo
						if e.PacketEnd == 0 {
							e.PacketEnd = a.packetEnd
						}
					}
				}
				// The CarvedFile row still knows the stream when the carve
				// event is not part of this batch.
				if e.StreamID == 0 {
					if sid := fileToStreamID[e.FileID]; sid != 0 {
						e.StreamID = sid
					}
				}
			}
		}

		// A range whose start is unknown but whose end is known degenerates
		// to a single packet at the end; this must happen before the stream
		// fallback so the known end is preserved.
		if e.PacketNo == 0 && e.PacketEnd != 0 {
			e.PacketNo = e.PacketEnd
		}

		// The event knows its stream but not its packets: take the stream's
		// full range.
		if e.PacketNo == 0 && e.StreamID != 0 {
			if s, ok := streamByID[e.StreamID]; ok && s.FirstPacket != 0 {
				e.PacketNo = s.FirstPacket
				if e.PacketEnd == 0 {
					e.PacketEnd = s.LastPacket
				}
			}
		}

		// Normalise: a known range is never empty or inverted.
		if e.PacketEnd == 0 {
			e.PacketEnd = e.PacketNo
		}
		if e.PacketEnd < e.PacketNo {
			e.PacketEnd = e.PacketNo
		}
	}
}
