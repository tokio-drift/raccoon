package pipeline

import (
	"fmt"

	"github.com/tokio-drift/raccoon/internal/carve"
	"github.com/tokio-drift/raccoon/internal/carve/formats"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
)

// newFormatRegistry returns the carvable formats used by the pipeline.
// Registration order is match priority for equally long headers.
func newFormatRegistry() *carve.Registry {
	reg := carve.NewRegistry()
	for _, f := range []carve.Format{
		formats.JPEG{},
		formats.PNG{},
		formats.PDF{},
		formats.ZIP{},
	} {
		_ = reg.Register(f)
	}
	return reg
}

// carveResult pairs a carved file with the stream location it came from so the
// pipeline can build its row and FILE_CARVED event.
type carveResult struct {
	carved carve.Carved
	proto  string
	src    string
	dst    string
	ts     int64
	pktNo  uint64
	pktEnd uint64
}

// carver scans one closed stream for embedded files: both reassembled
// directions plus every decoded FileSource an analyzer produced (e.g. an HTTP
// body after dechunking and gunzip). Results are emitted in a deterministic
// order (c2s, s2c, then the file sources in analyzer emission order).
type carver struct {
	scanner *carve.Scanner
}

// newCarverStage builds the scanner used during post-processing. A nil disk
// counter means unlimited carved-file storage; cfg.carvedDir receives the
// files.
func newCarverStage(cfg postConfig) (*carver, error) {
	s, err := carve.NewScanner(carve.Config{
		Registry:  newFormatRegistry(),
		CarvedDir: cfg.carvedDir,
		Disk:      cfg.disk,
	})
	if err != nil {
		return nil, err
	}
	return &carver{scanner: s}, nil
}

// run scans cs and calls emit for every carved file. protoName is the identified
// application protocol (used as the event/file Proto, falling back to the
// transport protocol when empty).
func (c *carver) run(cs *ClosedStream, protoName string, files []proto.FileSource, emit func(carveResult)) error {
	if cs == nil || cs.Flow == nil {
		return nil
	}
	f := cs.Flow
	streamProto := f.Proto
	if protoName != "" {
		streamProto = protoName
	}
	src := joinHostPort(f.Initiator.IP.String(), f.Initiator.Port)
	responder := responderEndpoint(f)
	dst := joinHostPort(responder.IP.String(), responder.Port)

	loc := newStreamLocator(cs, streamProto)

	makeResult := func(cd carve.Carved, dir model.Direction) carveResult {
		r := carveResult{carved: cd, proto: streamProto, src: src, dst: dst}
		r.ts, r.pktNo, r.pktEnd = loc.at(dir, cd.Start)
		return r
	}

	// Both directions of a reassembled TCP stream.
	if cs.Stream != nil {
		for _, dir := range []model.Direction{model.C2S, model.S2C} {
			length := cs.Stream.Len(dir)
			if length <= 0 {
				continue
			}
			err := c.scanner.ScanStream(cs.Stream.ReaderAt(dir), length, dir, "", func(cd carve.Carved) {
				emit(makeResult(cd, dir))
			})
			if err != nil {
				return fmt.Errorf("pipeline: carve stream %d %s: %w", f.ID, dirName(dir), err)
			}
		}
	}

	// Decoded file bodies handed over by analyzers.
	for _, fs := range files {
		if fs.Reader == nil || fs.Len <= 0 {
			continue
		}
		src := fs
		err := c.scanner.ScanStream(src.Reader, src.Len, src.Dir, src.Name, func(cd carve.Carved) {
			emit(makeResult(cd, src.Dir))
		})
		if err != nil {
			return fmt.Errorf("pipeline: carve file source %q: %w", src.Name, err)
		}
	}
	return nil
}

// streamLocator maps a (dir, offset) inside a closed stream to the capture
// timestamp and packet number of the bytes there.
type streamLocator struct {
	ctx *proto.StreamContext
}

func newStreamLocator(cs *ClosedStream, protoName string) *streamLocator {
	if cs == nil || cs.Flow == nil || cs.Stream == nil {
		return &streamLocator{}
	}
	f := cs.Flow
	responder := responderEndpoint(f)
	name := f.Proto
	if protoName != "" {
		name = protoName
	}
	meta := proto.StreamMeta{
		ID:          f.ID,
		Proto:       name,
		SrcIP:       f.Initiator.IP.String(),
		DstIP:       responder.IP.String(),
		SrcPort:     f.Initiator.Port,
		DstPort:     responder.Port,
		StartTS:     f.StartTS,
		EndTS:       f.EndTS,
		FirstPacket: f.FirstPacket,
		LastPacket:  f.LastPacket,
	}
	return &streamLocator{ctx: proto.NewStreamContext(meta, cs.Stream)}
}

// at returns the timestamp and the [packetNo, packetEnd] range for offset off.
func (l *streamLocator) at(dir model.Direction, off int64) (ts int64, pktNo, pktEnd uint64) {
	if l.ctx == nil {
		return 0, 0, 0
	}
	ts = l.ctx.TimeAtOffset(dir, off)
	pktNo = l.ctx.PacketAtOffset(dir, off)
	pktEnd = pktNo
	return ts, pktNo, pktEnd
}

// carvedFileRow builds the CarvedFile row for one result.
func carvedFileRow(r carveResult, streamID int64) model.CarvedFile {
	cd := r.carved
	name := cd.DisplayName
	if name == "" {
		sha12 := cd.SHA256
		if len(sha12) > 12 {
			sha12 = sha12[:12]
		}
		name = sha12 + "." + cd.Ext
	}
	confidence := "high"
	if cd.Status == carve.StatusTruncated {
		confidence = "medium"
	}
	return model.CarvedFile{
		StreamID:    streamID,
		Dir:         cd.Dir,
		StartOff:    cd.Start,
		EndOff:      cd.End,
		Format:      cd.Format.Name(),
		Ext:         cd.Ext,
		Status:      cd.Status,
		Confidence:  confidence,
		Size:        cd.Size,
		MD5:         cd.MD5,
		SHA256:      cd.SHA256,
		DisplayName: name,
		Path:        cd.RelPath,
		MagicHex:    cd.MagicHex,
	}
}

// carvedEvent builds the FILE_CARVED event for a carved file row with id.
func carvedEvent(r carveResult, streamID, fileID int64, displayName string) model.Event {
	cd := r.carved
	return model.Event{
		TS:        r.ts,
		PacketNo:  r.pktNo,
		PacketEnd: r.pktEnd,
		Type:      model.EvFileCarved,
		Severity:  model.SevInfo,
		StreamID:  streamID,
		Src:       r.src,
		Dst:       r.dst,
		Proto:     r.proto,
		Title:     fmt.Sprintf("File carved: %s", displayName),
		FileID:    fileID,
		Details: map[string]any{
			"sha256":   cd.SHA256,
			"md5":      cd.MD5,
			"size":     cd.Size,
			"format":   cd.Format.Name(),
			"magicHex": cd.MagicHex,
			"status":   cd.Status,
			"dir":      dirName(cd.Dir),
			"startOff": cd.Start,
			"endOff":   cd.End,
		},
	}
}

func dirName(dir model.Direction) string {
	if dir == model.S2C {
		return "s2c"
	}
	return "c2s"
}
