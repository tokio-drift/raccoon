package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/tokio-drift/raccoon/internal/capture"
	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/flow"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/reassembly"
)

func newDebugCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Debug utilities",
	}
	cmd.AddCommand(newDumpStreamCommand(stdout))
	return cmd
}

func newDumpStreamCommand(stdout io.Writer) *cobra.Command {
	var (
		pcapFlag   string
		streamFlag int64
		dirFlag    string
	)
	cmd := &cobra.Command{
		Use:   "dump-stream <pcap> <n> [c2s|s2c]",
		Short: "Dump one reassembled TCP stream as hex",
		Args:  cobra.RangeArgs(0, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			pcap := pcapFlag
			if pcap == "" && len(args) > 0 {
				pcap = args[0]
			}
			var index int64
			if cmd.Flags().Changed("stream") {
				index = streamFlag
			} else if len(args) > 1 {
				n, err := strconv.ParseInt(args[1], 10, 64)
				if err != nil {
					return badInput(fmt.Errorf("invalid stream index %q", args[1]))
				}
				index = n
			} else {
				return badInput(errors.New("missing stream index"))
			}
			dir := dirFlag
			if len(args) > 2 {
				dir = args[2]
			}
			if pcap == "" {
				return badInput(errors.New("missing capture path"))
			}
			return dumpStream(pcap, index, dir, stdout)
		},
	}
	cmd.Flags().StringVar(&pcapFlag, "pcap", "", "capture file")
	cmd.Flags().Int64Var(&streamFlag, "stream", 0, "zero-based TCP stream index")
	cmd.Flags().StringVar(&dirFlag, "dir", "", "direction: c2s, s2c or both")
	return cmd
}

type dumpChunk struct {
	dir model.Direction
	seg reassembly.Segment
}

func dumpStream(path string, index int64, dirArg string, out io.Writer) error {
	if index < 0 {
		return badInput(fmt.Errorf("invalid stream index %d", index))
	}
	mode := "both"
	switch dirArg {
	case "", "both":
	case "c2s":
		mode = "c2s"
	case "s2c":
		mode = "s2c"
	default:
		return badInput(fmt.Errorf("invalid direction %q (want c2s, s2c or both)", dirArg))
	}
	if _, err := capture.Validate(path); err != nil {
		return badInput(fmt.Errorf("invalid capture %q: %w", path, err))
	}

	rd, _, err := capture.Open(path)
	if err != nil {
		return internal(fmt.Errorf("open capture: %w", err))
	}
	defer rd.Close()

	tmp, err := os.MkdirTemp("", "raccoon-dump-*")
	if err != nil {
		return internal(fmt.Errorf("create temporary directory: %w", err))
	}
	defer os.RemoveAll(tmp)
	spoolDir := filepath.Join(tmp, "streams")

	dec := decode.NewDecoder()
	tbl := flow.NewTable(nil)
	streams := make(map[int64]*reassembly.Stream)
	var order []int64

	for {
		raw, err := rd.Next()
		if errors.Is(err, io.EOF) || errors.Is(err, capture.ErrTruncatedTail) {
			break
		}
		if err != nil {
			return internal(fmt.Errorf("read capture: %w", err))
		}
		pkt, err := dec.Decode(raw)
		if err != nil {
			if errors.Is(err, decode.ErrSkip) {
				continue
			}
			return internal(fmt.Errorf("decode packet: %w", err))
		}
		if pkt.Proto != decode.ProtoTCP {
			continue
		}
		f, dir, created := tbl.Lookup(pkt)
		if f == nil {
			continue
		}
		if created {
			spool, err := reassembly.NewSpool(spoolDir, f.ID)
			if err != nil {
				return internal(fmt.Errorf("create stream spool: %w", err))
			}
			st := reassembly.NewStream(reassembly.StreamConfig{
				ID:         f.ID,
				Proto:      f.Proto,
				Spool:      spool,
				Accountant: reassembly.NoopAccountant{},
				Midstream:  f.Midstream,
			})
			streams[f.ID] = st
			order = append(order, f.ID)
			defer spool.Close()
		}
		if st := streams[f.ID]; st != nil {
			st.AddPacket(dir, pkt.Seq, pkt.TCPFlags, pkt.Payload, pkt.TS, pkt.No)
		}
	}

	for _, st := range streams {
		if err := st.Close(); err != nil {
			return internal(fmt.Errorf("close stream: %w", err))
		}
	}
	if index >= int64(len(order)) {
		return badInput(fmt.Errorf("stream %d not found", index))
	}
	st := streams[order[index]]
	if st == nil {
		return badInput(fmt.Errorf("stream %d not found", index))
	}

	hw := newHexWriter(out)
	if mode == "c2s" || mode == "s2c" {
		dir := model.C2S
		if mode == "s2c" {
			dir = model.S2C
		}
		if err := copyStream(hw, st, dir); err != nil {
			return err
		}
	} else {
		var chunks []dumpChunk
		for _, dir := range []model.Direction{model.C2S, model.S2C} {
			for _, seg := range st.Segments(dir) {
				chunks = append(chunks, dumpChunk{dir: dir, seg: seg})
			}
		}
		sort.SliceStable(chunks, func(i, j int) bool {
			a, b := &chunks[i], &chunks[j]
			if a.seg.PacketNo != b.seg.PacketNo {
				return a.seg.PacketNo < b.seg.PacketNo
			}
			if a.seg.TS != b.seg.TS {
				return a.seg.TS < b.seg.TS
			}
			if a.seg.Dir != b.seg.Dir {
				return a.seg.Dir < b.seg.Dir
			}
			return a.seg.StreamOff < b.seg.StreamOff
		})
		for _, ch := range chunks {
			if err := copySegment(hw, st, ch.dir, ch.seg); err != nil {
				return err
			}
		}
	}
	return hw.Close()
}

func copyStream(w io.Writer, st *reassembly.Stream, dir model.Direction) error {
	n := st.Len(dir)
	if n == 0 {
		return nil
	}
	_, err := io.Copy(w, io.NewSectionReader(st.ReaderAt(dir), 0, n))
	if err != nil {
		return internal(fmt.Errorf("read stream bytes: %w", err))
	}
	return nil
}

func copySegment(w io.Writer, st *reassembly.Stream, dir model.Direction, seg reassembly.Segment) error {
	n := int64(seg.Length)
	if n == 0 {
		return nil
	}
	_, err := io.Copy(w, io.NewSectionReader(st.ReaderAt(dir), seg.StreamOff, n))
	if err != nil {
		return internal(fmt.Errorf("read stream segment: %w", err))
	}
	return nil
}

type hexWriter struct {
	w   io.Writer
	off int64
	buf []byte
}

func newHexWriter(w io.Writer) *hexWriter { return &hexWriter{w: w} }

func (h *hexWriter) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	for len(h.buf) >= 16 {
		if err := h.line(h.buf[:16]); err != nil {
			return 0, err
		}
		h.buf = h.buf[16:]
	}
	return len(p), nil
}

func (h *hexWriter) Close() error {
	if len(h.buf) == 0 {
		return nil
	}
	return h.line(h.buf)
}

func (h *hexWriter) line(p []byte) error {
	if _, err := fmt.Fprintf(h.w, "%08x  % x\n", h.off, p); err != nil {
		return err
	}
	h.off += int64(len(p))
	return nil
}
