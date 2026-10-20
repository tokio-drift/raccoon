package intel

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/tokio-drift/raccoon/internal/model"
)

// ServiceStore is the persistence interface required by Service.
// *store.DB satisfies this interface.
type ServiceStore interface {
	Store // UpsertVerdict + Verdicts (from cache.go)
	// InsertEvents appends verdict events and returns the last inserted id.
	InsertEvents(rows []model.Event) (int64, error)
	// UpdateEventSeverityByFileID escalates every FILE_CARVED event referencing
	// fileID to the given severity string.
	UpdateEventSeverityByFileID(fileID int64, severity string) error
}

// FileInfo carries the carved-file metadata that Service needs to perform
// threat intelligence checks and build verdict events.
type FileInfo struct {
	// FileID is the ID of the CarvedFile row in the store.
	FileID int64
	// SHA256 is the lower-case hex SHA-256 digest of the carved file.
	SHA256 string
	// AbsPath is the absolute on-disk path of the carved file (for YARA).
	AbsPath string
	// StreamID is the stream this file was carved from (0 if unknown).
	StreamID int64
	// Src is the source endpoint string "ip:port".
	Src string
	// Dst is the destination endpoint string "ip:port".
	Dst string
	// Proto is the stream protocol ("ftp", "http", "tcp", …).
	Proto string
	// TS is the Unix-nanosecond timestamp of the carve offset.
	TS int64
	// PacketNo is the first packet involved.
	PacketNo uint64
}

// ServiceConfig holds the parameters for constructing a Service.
type ServiceConfig struct {
	// Store is the persistence layer (required).
	Store ServiceStore
	// YARA is the rule engine. If nil or !Available(), YARA scanning is skipped.
	YARA RuleEngine
	// VTClient is the VirusTotal API client. May be nil.
	VTClient VTClient
	// Cache holds previously seen verdicts. If nil, no caching is done.
	Cache *Cache
	// Offline disables VT enqueuing even if VTClient is provided.
	Offline bool
	// VTRatePerMinute controls the token-bucket rate for VT lookups.
	// 0 uses limits.VTRatePerMinute (4).
	VTRatePerMinute int
	// OnVerdict is called after every verdict (YARA or VT) is processed.
	// It is intended for the SSE broadcast mechanism.
	OnVerdict func(v model.Verdict)
}

// Service orchestrates YARA scanning and VirusTotal lookups for carved files.
// Call ProcessFile after each carve; call Close when the analysis is complete.
type Service struct {
	store     ServiceStore
	yara      RuleEngine
	cache     *Cache
	offline   bool
	onVerdict func(v model.Verdict)
	queue     *Queue

	// mu protects pending, which maps sha256 → []FileInfo registered for VT.
	// When the VT worker delivers a verdict it needs the FileIDs to escalate
	// event severities; we can't pass them through the Queue API directly, so
	// we hold them here until the verdict arrives.
	mu      sync.RWMutex
	pending map[string][]FileInfo
}

// NewService constructs a Service from cfg and starts the background VT worker.
// ctx governs the VT queue goroutine lifetime.
func NewService(ctx context.Context, cfg ServiceConfig) *Service {
	svc := &Service{
		store:     cfg.Store,
		yara:      cfg.YARA,
		cache:     cfg.Cache,
		offline:   cfg.Offline,
		onVerdict: cfg.OnVerdict,
		pending:   make(map[string][]FileInfo),
	}

	vtEnabled := !cfg.Offline && cfg.VTClient != nil

	if vtEnabled {
		svc.queue = NewQueue(ctx, QueueConfig{
			Client:        cfg.VTClient,
			Cache:         cfg.Cache,
			RatePerMinute: cfg.VTRatePerMinute,
			OnVerdict: func(v model.Verdict) {
				svc.handleVTVerdict(v)
			},
			OnError: func(sha string, err error) {
				slog.Warn("intel: virustotal lookup error", "sha256", sha, "err", err)
			},
		})
	}

	return svc
}

// ProcessFile runs synchronous YARA scanning on the carved file and enqueues
// a VirusTotal lookup. It must be called from a single goroutine; it does not
// need to be safe for concurrent use (the VT queue worker is separate).
func (svc *Service) ProcessFile(info FileInfo) {
	svc.runYARA(info)
	svc.enqueueVT(info)
}

// Close waits for the VT queue to drain and stops the background worker.
// No new ProcessFile calls should be made after Close.
func (svc *Service) Close() {
	if svc.queue != nil {
		svc.queue.Close()
	}
}

// Stop immediately cancels the VT queue, discarding pending items.
func (svc *Service) Stop() {
	if svc.queue != nil {
		svc.queue.Stop()
	}
}

// runYARA performs synchronous YARA scanning. If the engine is unavailable or
// produces no matches the file receives a "not_checked" verdict (source "yara").
func (svc *Service) runYARA(info FileInfo) {
	if svc.yara == nil || !svc.yara.Available() {
		svc.storeNotChecked(info, "yara")
		return
	}

	matches, err := svc.yara.Scan(info.AbsPath)
	if err != nil {
		slog.Warn("intel: yara scan error", "path", info.AbsPath, "err", err)
		svc.storeNotChecked(info, "yara")
		return
	}

	var v model.Verdict
	if len(matches) == 0 {
		v = model.Verdict{
			SHA256:    info.SHA256,
			Source:    "yara",
			Status:    "no_detections",
			CheckedAt: time.Now().UnixNano(),
		}
	} else {
		rules := make([]string, 0, len(matches))
		for _, m := range matches {
			rules = append(rules, m.Rule)
		}
		v = model.Verdict{
			SHA256:    info.SHA256,
			Source:    "yara",
			Status:    "malicious",
			Score:     len(matches),
			Total:     len(matches),
			Detail:    map[string]any{"rules": rules},
			CheckedAt: time.Now().UnixNano(),
		}
	}

	// YARA is synchronous; we have info directly so we can escalate.
	svc.applyVerdict(v, info)
	// Store the verdict so the VT queue can find a YARA result in the cache.
	if svc.cache != nil {
		_ = svc.cache.Put(v)
	}
}

// storeNotChecked persists a "not_checked" verdict for source (used when the
// back-end is absent or produces an error).
func (svc *Service) storeNotChecked(info FileInfo, source string) {
	v := model.Verdict{
		SHA256:    info.SHA256,
		Source:    source,
		Status:    "not_checked",
		CheckedAt: time.Now().UnixNano(),
	}
	if err := svc.store.UpsertVerdict(v); err != nil {
		slog.Warn("intel: store not_checked verdict", "err", err)
	}
}

// enqueueVT adds the file's SHA-256 to the VT queue. If the service is offline,
// has no VT client, or the hash is already queued, it persists a "not_checked"
// verdict instead.
func (svc *Service) enqueueVT(info FileInfo) {
	if svc.offline || svc.queue == nil {
		svc.storeNotChecked(info, "virustotal")
		return
	}
	// Register info in the pending map so that handleVTVerdict can look up the
	// FileID when the VT worker delivers a verdict (which only carries sha256).
	svc.mu.Lock()
	svc.pending[info.SHA256] = append(svc.pending[info.SHA256], info)
	svc.mu.Unlock()

	svc.queue.Enqueue(info.SHA256)
}

// handleVTVerdict is the OnVerdict callback given to the Queue. It looks up all
// FileInfos registered for v.SHA256, applies the verdict for each, and then
// removes the pending entries.
func (svc *Service) handleVTVerdict(v model.Verdict) {
	svc.mu.Lock()
	infos := svc.pending[v.SHA256]
	delete(svc.pending, v.SHA256)
	svc.mu.Unlock()

	if len(infos) == 0 {
		// Verdict arrived for an unknown hash (e.g. from a cache hit path);
		// persist the verdict without file-level escalation.
		svc.persistVerdict(v)
		if svc.onVerdict != nil {
			svc.onVerdict(v)
		}
		return
	}

	for _, info := range infos {
		svc.applyVerdict(v, info)
	}
}

// applyVerdict persists the verdict, escalates the FILE_CARVED event severity
// when warranted, inserts an EvVerdict event linked to the file, and calls the
// SSE OnVerdict callback.
func (svc *Service) applyVerdict(v model.Verdict, info FileInfo) {
	// 1. Persist the verdict.
	svc.persistVerdict(v)

	// 2. Determine the severity this verdict implies for the FILE_CARVED event.
	var newSev model.Severity
	switch v.Status {
	case "malicious":
		newSev = model.SevCritical
	case "suspicious":
		newSev = model.SevWarning
	default:
		// no_detections / unknown / not_checked do not escalate.
	}

	if newSev != "" && info.FileID != 0 {
		// 2a. Escalate the FILE_CARVED event.
		if err := svc.store.UpdateEventSeverityByFileID(info.FileID, string(newSev)); err != nil {
			slog.Warn("intel: escalate event severity", "fileID", info.FileID, "err", err)
		}

		// 2b. Insert an EvVerdict event linked to the file.
		ev := model.Event{
			TS:       v.CheckedAt,
			Type:     model.EvVerdict,
			Severity: newSev,
			FileID:   info.FileID,
			StreamID: info.StreamID,
			Src:      info.Src,
			Dst:      info.Dst,
			Proto:    info.Proto,
			Title:    fmt.Sprintf("Threat verdict: %s (%s)", v.Status, v.Source),
			Details: map[string]any{
				"sha256":  v.SHA256,
				"source":  v.Source,
				"status":  v.Status,
				"score":   v.Score,
				"total":   v.Total,
				"file_id": info.FileID,
			},
		}
		if _, err := svc.store.InsertEvents([]model.Event{ev}); err != nil {
			slog.Warn("intel: insert verdict event", "err", err)
		}
	}

	// 3. Call SSE callback.
	if svc.onVerdict != nil {
		svc.onVerdict(v)
	}
}

// persistVerdict writes the verdict to the DB.
func (svc *Service) persistVerdict(v model.Verdict) {
	if err := svc.store.UpsertVerdict(v); err != nil {
		slog.Warn("intel: upsert verdict", "err", err)
	}
}
