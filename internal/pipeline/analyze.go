package pipeline

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/tokio-drift/raccoon/internal/capture"
	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/flow"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
	dnsp "github.com/tokio-drift/raccoon/internal/proto/dns"
	ftpp "github.com/tokio-drift/raccoon/internal/proto/ftp"
	httpp "github.com/tokio-drift/raccoon/internal/proto/http"
)

// sniffBytes is how many bytes from the start of each direction are inspected
// during protocol identification.
const sniffBytes = 4 << 10

// newAnalyzerRegistry returns the registry used by the pipeline. Registration
// order is matching priority.
func newAnalyzerRegistry() *proto.Registry {
	reg := proto.NewRegistry()
	reg.Register(ftpp.New())
	reg.Register(httpp.New())
	reg.Register(dnsp.New())
	return reg
}

// postConfig carries the capture metadata needed to re-read UDP datagrams
// after their flows close.
type postConfig struct {
	pcapPath     string
	pktIndexPath string
	linkTypes    []uint16
}

// datagramSource re-reads UDP payloads from the capture using the packet index.
// It opens the capture and index lazily and is only used by the single
// post-processing goroutine.
type datagramSource struct {
	cfg postConfig

	file    *os.File
	idxFile *os.File
	format  capture.Format
	index   *capture.IndexReader
	dec     *decode.Decoder
}

func newDatagramSource(cfg postConfig) *datagramSource {
	return &datagramSource{cfg: cfg}
}

func (d *datagramSource) open() error {
	if d.file != nil {
		return nil
	}
	f, err := os.Open(d.cfg.pcapPath)
	if err != nil {
		return fmt.Errorf("open capture %s: %w", d.cfg.pcapPath, err)
	}
	format, err := capture.Detect(f)
	if err != nil {
		f.Close()
		return err
	}
	idxFile, err := os.Open(d.cfg.pktIndexPath)
	if err != nil {
		f.Close()
		return fmt.Errorf("open packet index: %w", err)
	}
	st, err := idxFile.Stat()
	if err != nil {
		f.Close()
		idxFile.Close()
		return fmt.Errorf("stat packet index: %w", err)
	}
	d.file = f
	d.idxFile = idxFile
	d.format = format
	d.index = capture.NewIndexReader(idxFile, st.Size())
	d.dec = decode.NewDecoder()
	return nil
}

func (d *datagramSource) close() {
	if d.idxFile != nil {
		_ = d.idxFile.Close()
		d.idxFile = nil
	}
	if d.file != nil {
		_ = d.file.Close()
		d.file = nil
	}
	d.index = nil
	d.dec = nil
}

func (d *datagramSource) linkType(rec capture.IndexRecord) (uint16, error) {
	if len(d.cfg.linkTypes) == 0 {
		return 0, errors.New("capture has no link types")
	}
	if len(d.cfg.linkTypes) == 1 {
		return d.cfg.linkTypes[0], nil
	}
	if int(rec.Iface) < len(d.cfg.linkTypes) {
		return d.cfg.linkTypes[rec.Iface], nil
	}
	return d.cfg.linkTypes[0], nil
}

// payload re-reads one datagram's UDP payload. It returns ok=false when the
// packet cannot be decoded as UDP rather than failing the whole analysis.
func (d *datagramSource) payload(ref flow.DatagramRef) ([]byte, bool, error) {
	if err := d.open(); err != nil {
		return nil, false, err
	}
	rec, err := d.index.At(ref.PacketNo)
	if err != nil {
		return nil, false, fmt.Errorf("read packet index %d: %w", ref.PacketNo, err)
	}
	data, err := capture.ReadPacketAtFile(d.file, d.format, rec)
	if err != nil {
		return nil, false, fmt.Errorf("read packet %d: %w", ref.PacketNo, err)
	}
	linkType, err := d.linkType(rec)
	if err != nil {
		return nil, false, err
	}
	pkt, err := d.dec.Decode(capture.RawPacket{
		No:       ref.PacketNo,
		TS:       ref.TS,
		Offset:   rec.Offset,
		CapLen:   rec.CapLen,
		OrigLen:  rec.CapLen,
		LinkType: linkType,
		Data:     data,
	})
	if err != nil || pkt.Proto != decode.ProtoUDP {
		return nil, false, nil
	}
	return append([]byte(nil), pkt.Payload...), true, nil
}

func (d *datagramSource) firstPayload(refs []flow.DatagramRef, dir model.Direction) ([]byte, error) {
	for _, ref := range refs {
		if ref.Dir != dir {
			continue
		}
		p, ok, err := d.payload(ref)
		if err != nil {
			return nil, err
		}
		if ok {
			return p, nil
		}
	}
	return nil, nil
}

func (d *datagramSource) datagrams(refs []flow.DatagramRef) ([]proto.Datagram, error) {
	out := make([]proto.Datagram, 0, len(refs))
	for _, ref := range refs {
		p, ok, err := d.payload(ref)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, proto.Datagram{
			TS:       ref.TS,
			PacketNo: ref.PacketNo,
			Dir:      ref.Dir,
			Payload:  p,
		})
	}
	return out, nil
}

// analyzeClosed identifies and runs the analyzer for one closed flow. Events
// are passed to emit with all stream metadata filled in. It returns the
// identified application protocol, or "" when no analyzer matched.
func analyzeClosed(cs *ClosedStream, reg *proto.Registry, uds *datagramSource, emit func(model.Event)) (string, error) {
	if cs == nil || cs.Flow == nil || reg == nil {
		return "", nil
	}
	f := cs.Flow
	responder := responderEndpoint(f)
	ports := proto.PortPair{Client: f.Initiator.Port, Server: responder.Port}
	meta := proto.StreamMeta{
		ID:          f.ID,
		Proto:       f.Proto,
		SrcIP:       f.Initiator.IP.String(),
		DstIP:       responder.IP.String(),
		SrcPort:     f.Initiator.Port,
		DstPort:     responder.Port,
		StartTS:     f.StartTS,
		EndTS:       f.EndTS,
		FirstPacket: f.FirstPacket,
		LastPacket:  f.LastPacket,
	}

	fill := func(e model.Event) {
		if e.TS == 0 {
			e.TS = meta.StartTS
		}
		if e.PacketNo == 0 {
			e.PacketNo = meta.FirstPacket
		}
		if e.PacketEnd == 0 {
			e.PacketEnd = e.PacketNo
		}
		if e.StreamID == 0 {
			e.StreamID = meta.ID
		}
		if e.Src == "" {
			e.Src = joinHostPort(meta.SrcIP, meta.SrcPort)
		}
		if e.Dst == "" {
			e.Dst = joinHostPort(meta.DstIP, meta.DstPort)
		}
		if e.Proto == "" {
			e.Proto = meta.Proto
		}
		emit(e)
	}

	var (
		firstC2S []byte
		firstS2C []byte
	)
	if f.IsUDP() {
		if uds == nil || len(f.Datagrams) == 0 {
			return "", nil
		}
		var err error
		firstC2S, err = uds.firstPayload(f.Datagrams, model.C2S)
		if err != nil {
			return "", err
		}
		firstS2C, err = uds.firstPayload(f.Datagrams, model.S2C)
		if err != nil {
			return "", err
		}
	} else {
		if cs.Stream == nil {
			return "", nil
		}
		firstC2S = readPrefix(cs.Stream, model.C2S)
		firstS2C = readPrefix(cs.Stream, model.S2C)
	}

	a := reg.Find(firstC2S, firstS2C, ports)
	if a == nil {
		return "", nil
	}
	meta.Proto = a.Name()

	if f.IsUDP() {
		dgs, err := uds.datagrams(f.Datagrams)
		if err != nil {
			return "", err
		}
		return a.Name(), a.Analyze(proto.NewDatagramContext(meta, dgs), fill)
	}
	return a.Name(), a.Analyze(proto.NewStreamContext(meta, cs.Stream), fill)
}

// readPrefix returns up to sniffBytes from the start of a stream direction.
func readPrefix(src proto.StreamSource, dir model.Direction) []byte {
	n := src.Len(dir)
	if n <= 0 {
		return nil
	}
	if n > sniffBytes {
		n = sniffBytes
	}
	buf := make([]byte, int(n))
	nRead, err := src.ReaderAt(dir).ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return buf[:nRead]
	}
	return buf[:nRead]
}

func joinHostPort(ip string, port uint16) string {
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}
