package pipeline

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tokio-drift/raccoon/internal/capture"
	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/flow"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
	"github.com/tokio-drift/raccoon/internal/reassembly"
	"github.com/tokio-drift/raccoon/internal/resource"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/version"
)

// Progress tracks atomic pipeline progress counters for SSE and status monitoring.
// Files remains 0 until Phase 7 (file carving).
type Progress struct {
	stage       atomic.Pointer[string]
	packetsRead atomic.Int64
	bytesRead   atomic.Int64
	streams     atomic.Int64
	files       atomic.Int64 // remains 0 until Phase 7 (file carving)
	notifyCh    atomic.Pointer[chan struct{}]
}

// NewProgress returns a new initialized Progress tracker.
func NewProgress() *Progress {
	p := &Progress{}
	initStage := "init"
	p.stage.Store(&initStage)
	return p
}

// SetStage updates the current stage name and triggers notification if a notifier is registered.
func (p *Progress) SetStage(stage string) {
	p.stage.Store(&stage)
	if chPtr := p.notifyCh.Load(); chPtr != nil {
		select {
		case *chPtr <- struct{}{}:
		default:
		}
	}
}

// Stage returns the current pipeline stage name.
func (p *Progress) Stage() string {
	s := p.stage.Load()
	if s == nil {
		return ""
	}
	return *s
}

// ProgressSnapshot is a point-in-time snapshot of the pipeline progress.
type ProgressSnapshot struct {
	Stage       string `json:"stage"`
	PacketsRead int64  `json:"packets"`
	BytesRead   int64  `json:"bytes"`
	Streams     int64  `json:"streams"`
	Files       int64  `json:"files"`
}

// Snapshot returns a copy of current progress counter values.
func (p *Progress) Snapshot() ProgressSnapshot {
	return ProgressSnapshot{
		Stage:       p.Stage(),
		PacketsRead: p.packetsRead.Load(),
		BytesRead:   p.bytesRead.Load(),
		Streams:     p.streams.Load(),
		Files:       p.files.Load(),
	}
}

// ClosedStream packages a closed flow, its optional reassembled TCP stream,
// and any detected anomalies for post-processing and store writing.
type ClosedStream struct {
	Flow      *flow.Flow
	Stream    *reassembly.Stream
	Anomalies []reassembly.Anomaly
}

// Hooks provides extension points for subsequent analysis phases.
type Hooks struct {
	// AnalyzeStream is called for protocol analyzers (Phase 6).
	AnalyzeStream func(ctx context.Context, cs *ClosedStream) error
	// CarveStream is called for file carving (Phase 7).
	CarveStream func(ctx context.Context, cs *ClosedStream) error
	// EntropyStream is called for entropy scanning (Phase 7).
	EntropyStream func(ctx context.Context, cs *ClosedStream) error
	// IntelEnqueue is called for threat intelligence lookup (Phase 8).
	IntelEnqueue func(ctx context.Context, file *model.CarvedFile) error
}

// Options configures a pipeline analysis run.
type Options struct {
	// PCAPPath is the path to the capture file.
	PCAPPath string

	// Case is the target case directory. If nil, one will be created under BaseDir.
	Case *casedir.Case

	// BaseDir is the base directory under which a case is created if Case is nil.
	BaseDir string

	// Budget specifies memory and concurrency limits. If nil, defaults are applied.
	Budget *resource.Budget

	// Store is the case database. If nil, Case.DB() will be opened.
	Store *store.DB

	// Hooks provides extension hooks for post-processing stages.
	Hooks Hooks

	// MaxFileSize, when > 0, caps a single carved file. Zero uses each format's
	// built-in limit.
	MaxFileSize int64

	// Progress, if provided, receives atomic progress updates.
	Progress *Progress

	// OnProgress is an optional callback called whenever progress changes.
	OnProgress func(ProgressSnapshot)
}

// Result summarizes a completed pipeline analysis run.
type Result struct {
	Case    *casedir.Case
	Packets int64
	Bytes   int64
	Streams int64
	// Files is the count of carved files extracted. It remains 0 until Phase 7 (file carving).
	Files      int64
	Events     int64
	Duration   time.Duration
	PcapSHA256 string
	PcapSize   int64
}

// packetMsg carries a decoded packet across goroutines with pooled buffers.
type packetMsg struct {
	pkt     decode.Packet
	srcBuf  [16]byte
	dstBuf  [16]byte
	payload []byte
}

var packetPool = sync.Pool{
	New: func() any {
		return &packetMsg{
			payload: make([]byte, 0, 2048),
		}
	},
}

var (
	testWorkerPanicMu   sync.RWMutex
	testWorkerPanicHook func(pkt decode.Packet)
)

// SetTestWorkerPanicHook sets a hook for testing worker panic recovery.
// When non-nil, workers invoke this hook during packet handling.
func SetTestWorkerPanicHook(fn func(pkt decode.Packet)) {
	testWorkerPanicMu.Lock()
	testWorkerPanicHook = fn
	testWorkerPanicMu.Unlock()
}

func getTestWorkerPanicHook() func(pkt decode.Packet) {
	testWorkerPanicMu.RLock()
	fn := testWorkerPanicHook
	testWorkerPanicMu.RUnlock()
	return fn
}

// channelCapacity calculates the bounded channel capacity per worker derived from the budget.
func channelCapacity(b *resource.Budget) int {
	if b == nil || b.Workers <= 0 {
		return 256
	}
	// Derive capacity from the decode buffers pool share.
	cap := int(b.DecodeBuffersCap / (64 * 1024 * int64(b.Workers)))
	if cap < 64 {
		return 64
	}
	if cap > 2048 {
		return 2048
	}
	return cap
}

// Run executes the complete analysis pipeline over a capture file.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.PCAPPath == "" {
		return nil, errors.New("pipeline: missing PCAPPath")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startTime := time.Now()

	// 1. Budget setup.
	budget := opts.Budget
	if budget == nil {
		workers := runtime.NumCPU()
		if workers > 8 {
			workers = 8
		}
		if workers < 1 {
			workers = 1
		}
		var err error
		budget, err = resource.NewBudget(2*1024*1024*1024, 0, workers)
		if err != nil {
			return nil, fmt.Errorf("pipeline: budget: %w", err)
		}
	}
	resource.Apply(budget)
	accs := budget.NewAccountants()
	streamAcc := accs[resource.CatStreamBuffers]

	// 2. Case directory setup.
	c := opts.Case
	if c == nil {
		base := opts.BaseDir
		if base == "" {
			base = filepath.Join(os.TempDir(), "raccoon_cases")
		}
		var err error
		c, err = casedir.Create(base, casedir.Options{
			PCAP: opts.PCAPPath,
		})
		if err != nil {
			return nil, fmt.Errorf("pipeline: create case: %w", err)
		}
	}

	// 3. Store setup.
	db := opts.Store
	closeDB := false
	if db == nil {
		var err error
		db, err = store.Open(c.DB())
		if err != nil {
			return nil, fmt.Errorf("pipeline: open store: %w", err)
		}
		closeDB = true
	}
	if closeDB {
		defer db.Close()
	}

	// 4. Progress tracker and single notifier goroutine.
	progress := opts.Progress
	if progress == nil {
		progress = NewProgress()
	}

	var stopNotifier func(sendDone bool)
	if opts.OnProgress != nil {
		notifyCh := make(chan struct{}, 1)
		progress.notifyCh.Store(&notifyCh)
		stopCh := make(chan struct{})
		notifierDone := make(chan struct{})
		var shouldSendDone atomic.Bool
		var once sync.Once

		go func() {
			defer close(notifierDone)
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-stopCh:
					if shouldSendDone.Load() {
						opts.OnProgress(progress.Snapshot())
					}
					return
				case <-ticker.C:
					opts.OnProgress(progress.Snapshot())
				case <-notifyCh:
					opts.OnProgress(progress.Snapshot())
				}
			}
		}()

		stopNotifier = func(sendDone bool) {
			once.Do(func() {
				if sendDone {
					shouldSendDone.Store(true)
				}
				close(stopCh)
				<-notifierDone
			})
		}
	} else {
		stopNotifier = func(bool) {}
	}
	defer func() {
		stopNotifier(false)
	}()

	progress.SetStage("read")

	// 5. Open capture and packet index writer.
	rd, info, err := capture.Open(opts.PCAPPath)
	if err != nil {
		return nil, fmt.Errorf("pipeline: open capture %s: %w", opts.PCAPPath, err)
	}
	defer rd.Close()

	idxFile, err := os.OpenFile(c.PktIndex(), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("pipeline: open packet index: %w", err)
	}
	defer idxFile.Close()
	idxBuf := bufio.NewWriterSize(idxFile, 64*1024)
	idxWriter := capture.NewIndexWriter(idxBuf)

	// Compute file SHA256 in background concurrently.
	type shaRes struct {
		sha256 string
		size   int64
		err    error
	}
	shaCh := make(chan shaRes, 1)
	go func() {
		f, err := os.Open(opts.PCAPPath)
		if err != nil {
			shaCh <- shaRes{err: err}
			return
		}
		defer f.Close()
		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			shaCh <- shaRes{err: err}
			return
		}
		shaCh <- shaRes{sha256: hex.EncodeToString(h.Sum(nil)), size: n}
	}()

	// 6. Bounded worker channels and closed-stream channel.
	numWorkers := budget.Workers
	chanCap := channelCapacity(budget)
	workerChans := make([]chan *packetMsg, numWorkers)
	for i := 0; i < numWorkers; i++ {
		workerChans[i] = make(chan *packetMsg, chanCap)
	}

	closedStreamCap := numWorkers * 32
	if closedStreamCap < 64 {
		closedStreamCap = 64
	}
	closedStreamChan := make(chan *ClosedStream, closedStreamCap)
	workerErrCh := make(chan error, numWorkers)

	// Shared flow ID counter across all workers.
	sharedCounter := flow.NewCounter(1)

	// 7. Launch worker goroutines.
	var workerWg sync.WaitGroup
	workerWg.Add(numWorkers)
	for w := 0; w < numWorkers; w++ {
		go func(workerID int, in <-chan *packetMsg) {
			defer workerWg.Done()
			runWorker(ctx, cancel, in, closedStreamChan, workerErrCh, sharedCounter, c, streamAcc, progress)
		}(w, workerChans[w])
	}

	// 8. Launch post-processing & store writer stage concurrently.
	var postWg sync.WaitGroup
	postWg.Add(1)
	var totalEvents atomic.Int64
	var postErr error
	postCfg := postConfig{
		pcapPath:     opts.PCAPPath,
		pktIndexPath: c.PktIndex(),
		linkTypes:    info.LinkTypes,
		carvedDir:    c.CarvedDir(),
		disk:         budget.NewDiskCounter(),
		maxFileSize:  opts.MaxFileSize,
	}

	go func() {
		defer postWg.Done()
		postErr = runPostProcessing(ctx, closedStreamChan, db, opts.Hooks, progress, &totalEvents, postCfg)
		if postErr != nil {
			cancel()
		}
	}()

	// 9. Single goroutine capture reader and decoder.
	dec := decode.NewDecoder()
	var readErr error

readLoop:
	for {
		if ctx.Err() != nil {
			readErr = ctx.Err()
			break
		}

		raw, err := rd.Next()
		if err == io.EOF || errors.Is(err, capture.ErrTruncatedTail) {
			break
		}
		if err != nil {
			readErr = fmt.Errorf("pipeline: read packet: %w", err)
			cancel()
			break
		}

		// Record packet index.
		idxRec := capture.IndexRecord{
			Offset: raw.Offset,
			TS:     raw.TS,
			CapLen: raw.CapLen,
			Iface:  0,
		}
		if err := idxWriter.Add(idxRec); err != nil {
			readErr = fmt.Errorf("pipeline: write index: %w", err)
			cancel()
			break
		}

		progress.packetsRead.Add(1)
		progress.bytesRead.Add(int64(raw.CapLen))

		// Decode.
		pkt, err := dec.Decode(raw)
		if err != nil {
			// Skip unsupported link types or malformed packets.
			continue
		}

		if pkt.Proto != decode.ProtoTCP && pkt.Proto != decode.ProtoUDP {
			continue
		}

		// Dispatch by flow.Key.Hash() % numWorkers.
		k := flow.MakeKey(pkt)
		workerIdx := k.Hash() % uint64(numWorkers)

		// Borrow pooled message.
		msg := packetPool.Get().(*packetMsg)
		msg.pkt = pkt
		if len(pkt.SrcIP) <= 16 {
			copy(msg.srcBuf[:], pkt.SrcIP)
			msg.pkt.SrcIP = msg.srcBuf[:len(pkt.SrcIP)]
		} else {
			msg.pkt.SrcIP = append([]byte(nil), pkt.SrcIP...)
		}
		if len(pkt.DstIP) <= 16 {
			copy(msg.dstBuf[:], pkt.DstIP)
			msg.pkt.DstIP = msg.dstBuf[:len(pkt.DstIP)]
		} else {
			msg.pkt.DstIP = append([]byte(nil), pkt.DstIP...)
		}
		if len(pkt.Payload) > 0 {
			msg.payload = append(msg.payload[:0], pkt.Payload...)
			msg.pkt.Payload = msg.payload
		} else {
			msg.pkt.Payload = nil
		}

		select {
		case workerChans[workerIdx] <- msg:
		case <-ctx.Done():
			packetPool.Put(msg)
			readErr = ctx.Err()
			break readLoop
		}
	}

	// Close worker channels to signal EOF.
	for _, ch := range workerChans {
		close(ch)
	}

	// Flush packet index buffer.
	if err := idxBuf.Flush(); err != nil && readErr == nil {
		readErr = fmt.Errorf("pipeline: flush packet index: %w", err)
	}

	// Close the closed-stream channel only after the packet index is durable:
	// UDP flow analysis re-reads datagrams through the index when the channel
	// drains. Workers may still be finishing, so the close waits for them too.
	go func() {
		workerWg.Wait()
		close(closedStreamChan)
	}()

	// Wait for workers and post-processing to complete.
	workerWg.Wait()
	postWg.Wait()

	var workerErr error
	select {
	case workerErr = <-workerErrCh:
	default:
	}

	if postErr != nil {
		return nil, postErr
	}
	if workerErr != nil {
		return nil, workerErr
	}
	if readErr != nil {
		return nil, readErr
	}

	// Retrieve file SHA256 and size.
	sRes := <-shaCh
	if sRes.err != nil {
		return nil, fmt.Errorf("pipeline: sha256 calculation: %w", sRes.err)
	}
	pcapSize := sRes.size
	if pcapSize == 0 && info.Size > 0 {
		pcapSize = info.Size
	}

	// Flush store.
	if err := db.Flush(); err != nil {
		return nil, fmt.Errorf("pipeline: flush store: %w", err)
	}

	duration := time.Since(startTime)
	packetsCount := progress.packetsRead.Load()
	bytesCount := progress.bytesRead.Load()
	streamsCount := progress.streams.Load()
	filesCount := progress.files.Load()

	// Write metadata to store. Prefer the original capture name recorded in
	// case.json (uploads are stored as input.pcap but keep the client name).
	pcapName := filepath.Base(opts.PCAPPath)
	if opts.Case != nil && opts.Case.Meta.PCAP != "" {
		pcapName = filepath.Base(opts.Case.Meta.PCAP)
	}
	metaPairs := [][2]string{
		{"pcap_name", pcapName},
		{"pcap_size", strconv.FormatInt(pcapSize, 10)},
		{"pcap_sha256", sRes.sha256},
		{"packets", strconv.FormatInt(packetsCount, 10)},
		{"streams", strconv.FormatInt(streamsCount, 10)},
		{"duration_ns", strconv.FormatInt(duration.Nanoseconds(), 10)},
		{"tool_version", version.String()},
		{"max_mem", strconv.FormatInt(budget.MaxMem, 10)},
		{"max_disk", strconv.FormatInt(budget.MaxDisk, 10)},
		{"workers", strconv.Itoa(budget.Workers)},
	}
	for _, pair := range metaPairs {
		if err := db.SetMeta(pair[0], pair[1]); err != nil {
			return nil, fmt.Errorf("pipeline: set meta %q: %w", pair[0], err)
		}
	}

	progress.SetStage("done")
	stopNotifier(true)

	return &Result{
		Case:       c,
		Packets:    packetsCount,
		Bytes:      bytesCount,
		Streams:    streamsCount,
		Files:      filesCount,
		Events:     totalEvents.Load(),
		Duration:   duration,
		PcapSHA256: sRes.sha256,
		PcapSize:   pcapSize,
	}, nil
}

// runWorker consumes decoded packets assigned to this worker, manages flow tables,
// reassembles TCP streams, and emits closed streams to closedChan.
func runWorker(
	ctx context.Context,
	cancel context.CancelFunc,
	in <-chan *packetMsg,
	closedChan chan<- *ClosedStream,
	errCh chan<- error,
	counter func() int64,
	c *casedir.Case,
	accountant reassembly.Accountant,
	progress *Progress,
) {
	tbl := flow.NewTable(counter)
	streams := make(map[int64]*reassembly.Stream)
	anomalies := make(map[int64][]reassembly.Anomaly)
	sent := make(map[int64]bool)
	active := make(map[int64]*flow.Flow)
	panicked := make(map[int64]bool)
	var lastExpire int64
	var expireInit bool

	reportErr := func(err error) {
		if err == nil {
			return
		}
		select {
		case errCh <- err:
		default:
		}
		cancel()
	}

	emitClosed := func(f *flow.Flow, s *reassembly.Stream, anoms []reassembly.Anomaly) {
		if f == nil || sent[f.ID] {
			return
		}
		sent[f.ID] = true
		delete(active, f.ID)
		fc := *f
		cs := &ClosedStream{
			Flow:      &fc,
			Stream:    s,
			Anomalies: anoms,
		}
		select {
		case closedChan <- cs:
		case <-ctx.Done():
		}
	}

	for msg := range in {
		if ctx.Err() != nil {
			packetPool.Put(msg)
			continue
		}

		func() {
			var currentFlow *flow.Flow
			var currentDir model.Direction

			defer func() {
				if r := recover(); r != nil {
					if currentFlow != nil {
						streamID := currentFlow.ID
						if !panicked[streamID] {
							panicked[streamID] = true
							anomalies[streamID] = append(anomalies[streamID], reassembly.Anomaly{
								Kind:   reassembly.AnomalyParseError,
								Dir:    currentDir,
								Offset: 0,
								Length: 0,
							})
							if s := streams[streamID]; s != nil {
								_ = s.Close()
							}
						}
					}
				}
			}()

			f, dir, isNew := tbl.Lookup(msg.pkt)
			if f == nil {
				return
			}
			currentFlow = f
			currentDir = dir

			if isNew {
				progress.streams.Add(1)
				if !f.IsUDP() {
					streamID := f.ID
					spool, err := reassembly.NewSpool(c.StreamsDir(), streamID)
					if err != nil {
						reportErr(fmt.Errorf("pipeline: worker spool %d: %w", streamID, err))
						return
					}
					stream := reassembly.NewStream(reassembly.StreamConfig{
						ID:         streamID,
						Proto:      f.Proto,
						Spool:      spool,
						Accountant: accountant,
						Midstream:  f.Midstream,
						OnAnomaly: func(a reassembly.Anomaly) {
							anomalies[streamID] = append(anomalies[streamID], a)
						},
					})
					streams[streamID] = stream
					active[streamID] = f
				}
			}

			// Invoke test hook for injected panics during packet handling.
			if hook := getTestWorkerPanicHook(); hook != nil {
				hook(msg.pkt)
			}

			if panicked[f.ID] {
				if f.State == flow.StateClosed {
					emitClosed(f, streams[f.ID], anomalies[f.ID])
					delete(streams, f.ID)
					delete(anomalies, f.ID)
				}
				return
			}

			if !f.IsUDP() {
				if stream := streams[f.ID]; stream != nil {
					stream.AddPacket(dir, msg.pkt.Seq, msg.pkt.TCPFlags, msg.pkt.Payload, msg.pkt.TS, msg.pkt.No)
					if f.State == flow.StateClosed {
						if err := stream.Close(); err != nil {
							reportErr(fmt.Errorf("pipeline: worker close stream %d: %w", f.ID, err))
						}
						emitClosed(f, stream, anomalies[f.ID])
						delete(streams, f.ID)
						delete(anomalies, f.ID)
					}
				}
			}

			// Periodically reap expired flows on capture clock (at most once per 1s of capture time).
			if !expireInit {
				lastExpire = msg.pkt.TS
				expireInit = true
			} else if msg.pkt.TS-lastExpire >= int64(time.Second) {
				lastExpire = msg.pkt.TS
				if expired := tbl.Expire(msg.pkt.TS); len(expired) > 0 {
					for _, exp := range expired {
						if !exp.IsUDP() {
							stream := streams[exp.ID]
							if stream != nil {
								if err := stream.Close(); err != nil {
									reportErr(fmt.Errorf("pipeline: worker close stream %d: %w", exp.ID, err))
								}
							}
							emitClosed(exp, stream, anomalies[exp.ID])
							delete(streams, exp.ID)
							delete(anomalies, exp.ID)
						} else {
							emitClosed(exp, nil, anomalies[exp.ID])
							delete(anomalies, exp.ID)
						}
					}
				}
			}
		}()

		packetPool.Put(msg)
	}

	// Flush all remaining active flows when input is exhausted.
	for id, stream := range streams {
		if err := stream.Close(); err != nil {
			reportErr(fmt.Errorf("pipeline: worker close stream %d: %w", id, err))
		}
	}

	for id, f := range active {
		emitClosed(f, streams[id], anomalies[id])
	}

	// Drain any flows remaining in table.
	allExpired := tbl.Expire(1<<63 - 1)
	for _, exp := range allExpired {
		var s *reassembly.Stream
		if !exp.IsUDP() {
			s = streams[exp.ID]
		}
		emitClosed(exp, s, anomalies[exp.ID])
	}
}

// runPostProcessing consumes closed streams, runs hook callbacks, and writes
// streams, segments, and anomaly events to the store.
func runPostProcessing(
	ctx context.Context,
	closedChan <-chan *ClosedStream,
	db *store.DB,
	hooks Hooks,
	progress *Progress,
	totalEvents *atomic.Int64,
	cfg postConfig,
) error {
	progress.SetStage("process")

	const maxBatch = 1000
	streamBuf := make([]model.Stream, 0, maxBatch)
	segmentBuf := make([]store.Segment, 0, maxBatch)
	eventBuf := make([]model.Event, 0, maxBatch)

	flush := func() error {
		if len(streamBuf) > 0 {
			if _, err := db.InsertStreams(streamBuf); err != nil {
				return fmt.Errorf("pipeline: flush streams: %w", err)
			}
			streamBuf = streamBuf[:0]
		}
		if len(segmentBuf) > 0 {
			if err := db.InsertSegments(segmentBuf); err != nil {
				return fmt.Errorf("pipeline: flush segments: %w", err)
			}
			segmentBuf = segmentBuf[:0]
		}
		return nil
	}

	flushEvents := func() error {
		if len(eventBuf) == 0 {
			return nil
		}
		// Events were sorted before this call, so SQLite assigns ascending ids
		// in (ts, packetNo) order and the table stays ordered by (ts, packetNo, id).
		for start := 0; start < len(eventBuf); start += maxBatch {
			end := start + maxBatch
			if end > len(eventBuf) {
				end = len(eventBuf)
			}
			if _, err := db.InsertEvents(eventBuf[start:end]); err != nil {
				return fmt.Errorf("pipeline: flush events: %w", err)
			}
			totalEvents.Add(int64(end - start))
		}
		eventBuf = eventBuf[:0]
		return nil
	}

	reg := newAnalyzerRegistry()
	uds := newDatagramSource(cfg)
	defer uds.close()

	carverStage, err := newCarverStage(cfg)
	if err != nil {
		return fmt.Errorf("pipeline: init carver: %w", err)
	}

	// pendingFile pairs a carved file with its stream id. Rows and FILE_CARVED
	// events are written after the drain in a content order so file ids (and
	// therefore event file_id links) are reproducible across runs.
	type pendingFile struct {
		res      carveResult
		streamID int64
		row      model.CarvedFile
	}
	var pendingFiles []pendingFile

	carveInto := func(cs *ClosedStream, appProto string, fileSources []proto.FileSource, carvedExtents map[model.Direction][]span) error {
		return carverStage.run(cs, appProto, fileSources, func(r carveResult) {
			pendingFiles = append(pendingFiles, pendingFile{res: r, streamID: cs.Flow.ID})
			carvedExtents[r.carved.Dir] = append(carvedExtents[r.carved.Dir], span{start: r.carved.Start, end: r.carved.End})
		})
	}

	handle := func(cs *ClosedStream) error {
		if cs == nil || cs.Flow == nil {
			return nil
		}

		// Built-in protocol analyzers run when a stream closes.
		appProto, fileSources, err := analyzeClosed(cs, reg, uds, func(e model.Event) {
			eventBuf = append(eventBuf, e)
		})
		if err != nil {
			return fmt.Errorf("pipeline: analyze stream: %w", err)
		}

		// Extension hooks for analyzers and carver.
		if hooks.AnalyzeStream != nil {
			if err := hooks.AnalyzeStream(ctx, cs); err != nil {
				return fmt.Errorf("pipeline: analyze stream: %w", err)
			}
		}
		if hooks.CarveStream != nil {
			if err := hooks.CarveStream(ctx, cs); err != nil {
				return fmt.Errorf("pipeline: carve stream: %w", err)
			}
		}
		if hooks.EntropyStream != nil {
			if err := hooks.EntropyStream(ctx, cs); err != nil {
				return fmt.Errorf("pipeline: entropy stream: %w", err)
			}
		}

		// Insert model.Stream row.
		f := cs.Flow
		responder := responderEndpoint(f)

		// For TCP, report the bytes actually delivered to the stream rather than
		// raw payload totals: retransmissions and trimmed overlaps must not
		// inflate the counts. UDP has no reassembly, so flow totals are exact.
		bytesC2S, bytesS2C := f.BytesC2S, f.BytesS2C
		if cs.Stream != nil {
			bytesC2S = cs.Stream.Len(model.C2S)
			bytesS2C = cs.Stream.Len(model.S2C)
		}

		stRow := model.Stream{
			ID:          f.ID,
			Proto:       f.Proto,
			SrcIP:       f.Initiator.IP.String(),
			SrcPort:     f.Initiator.Port,
			DstIP:       responder.IP.String(),
			DstPort:     responder.Port,
			StartTS:     f.StartTS,
			EndTS:       f.EndTS,
			BytesC2S:    bytesC2S,
			BytesS2C:    bytesS2C,
			Packets:     f.Packets,
			FirstPacket: f.FirstPacket,
			LastPacket:  f.LastPacket,
			Midstream:   f.Midstream,
			UDP:         f.IsUDP(),
		}
		if appProto != "" {
			stRow.Proto = appProto
		}

		if cs.Stream != nil {
			stRow.HasGaps = len(cs.Stream.Gaps(model.C2S)) > 0 || len(cs.Stream.Gaps(model.S2C)) > 0
		}
		streamBuf = append(streamBuf, stRow)

		// Insert segments if TCP stream reassembled.
		if cs.Stream != nil {
			for _, seg := range cs.Stream.Segments(model.C2S) {
				segmentBuf = append(segmentBuf, store.Segment{
					StreamID: f.ID,
					Dir:      model.C2S,
					Offset:   seg.StreamOff,
					Length:   seg.Length,
					TS:       seg.TS,
					PacketNo: seg.PacketNo,
				})
			}
			for _, seg := range cs.Stream.Segments(model.S2C) {
				segmentBuf = append(segmentBuf, store.Segment{
					StreamID: f.ID,
					Dir:      model.S2C,
					Offset:   seg.StreamOff,
					Length:   seg.Length,
					TS:       seg.TS,
					PacketNo: seg.PacketNo,
				})
			}
		}

		// Insert TCP anomaly events if any.
		if len(cs.Anomalies) > 0 {
			srcStr := netip.AddrPortFrom(f.Initiator.IP, f.Initiator.Port).String()
			dstStr := netip.AddrPortFrom(responder.IP, responder.Port).String()

			for _, anom := range cs.Anomalies {
				ev := model.Event{
					TS:        f.StartTS,
					PacketNo:  f.FirstPacket,
					PacketEnd: f.LastPacket,
					Type:      model.EvTCPAnomaly,
					Severity:  model.SevWarning,
					StreamID:  f.ID,
					Src:       srcStr,
					Dst:       dstStr,
					Proto:     f.Proto,
					Title:     fmt.Sprintf("TCP anomaly: %s", anom.Kind),
					Details: map[string]any{
						"kind":   string(anom.Kind),
						"dir":    dirString(anom.Dir),
						"offset": anom.Offset,
						"length": anom.Length,
					},
				}
				eventBuf = append(eventBuf, ev)
			}
		}

		// Carve embedded files from both stream directions and any decoded
		// file bodies the analyzer produced, then flag any high-entropy bytes
		// the carving did not account for.
		carvedExtents := make(map[model.Direction][]span)
		if err := carveInto(cs, appProto, fileSources, carvedExtents); err != nil {
			return err
		}
		if err := entropyInto(cs, appProto, carvedExtents, func(e model.Event) {
			eventBuf = append(eventBuf, e)
		}); err != nil {
			return err
		}

		if len(streamBuf) >= maxBatch || len(segmentBuf) >= maxBatch {
			if err := flush(); err != nil {
				return err
			}
		}
		return nil
	}

	// UDP flows are analyzed after the closed-stream channel drains: by then
	// the reader has flushed the packet index that datagram re-reads rely on.
	var pendingUDP []*ClosedStream
	for cs := range closedChan {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if cs != nil && cs.Flow != nil && cs.Flow.IsUDP() {
			pendingUDP = append(pendingUDP, cs)
			continue
		}
		if err := handle(cs); err != nil {
			return err
		}
	}
	for _, cs := range pendingUDP {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := handle(cs); err != nil {
			return err
		}
	}

	if err := flush(); err != nil {
		return err
	}

	// Insert carved-file rows in a content order (independent of worker
	// interleaving) so ids are reproducible, then attach the FILE_CARVED event
	// with the assigned id.
	sort.SliceStable(pendingFiles, func(i, j int) bool {
		return carveSortKey(&pendingFiles[i].res) < carveSortKey(&pendingFiles[j].res)
	})
	for i := range pendingFiles {
		pf := &pendingFiles[i]
		row := carvedFileRow(pf.res, pf.streamID)
		id, err := db.InsertFiles([]model.CarvedFile{row})
		if err != nil {
			return fmt.Errorf("pipeline: insert carved file: %w", err)
		}
		eventBuf = append(eventBuf, carvedEvent(pf.res, pf.streamID, id, row.DisplayName))
		row.ID = id
		pf.row = row
		progress.files.Add(1)
	}

	// Events are inserted only after every stage has completed so their ids are
	// deterministic regardless of worker completion order.
	sortEvents(eventBuf)
	if err := flushEvents(); err != nil {
		return err
	}

	if hooks.IntelEnqueue != nil {
		for i := range pendingFiles {
			file := pendingFiles[i].row
			if err := hooks.IntelEnqueue(ctx, &file); err != nil {
				return fmt.Errorf("pipeline: intel enqueue: %w", err)
			}
		}
	}

	return nil
}

// carveSortKey returns a content-only key for a carved file. It excludes ids
// and the stream id (worker-assigned) so the insertion order is identical
// across runs.
func carveSortKey(r *carveResult) string {
	cd := r.carved
	return fmt.Sprintf("%s|%d|%d|%d|%d|%s", cd.SHA256, cd.Dir, cd.Start, cd.End, cd.Size, cd.Format.Name())
}

// sortEvents orders events by (ts, packetNo) and then by content-only fields.
// Content-only tiebreakers (no ids) keep the order identical across runs even
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

func responderEndpoint(f *flow.Flow) flow.Endpoint {
	if f.Initiator == f.Key.A {
		return f.Key.B
	}
	return f.Key.A
}

func dirString(dir model.Direction) string {
	if dir == model.C2S {
		return "c2s"
	}
	return "s2c"
}
