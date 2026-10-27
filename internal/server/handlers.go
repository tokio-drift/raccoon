package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/report"
	"github.com/tokio-drift/raccoon/internal/store"
)

// Vocabularies accepted as query filters (docs/api.md).
var (
	severityVocab = map[string]bool{"info": true, "warning": true, "critical": true}
	phaseVocab    = map[string]bool{"recon": true, "access": true, "action": true, "exfil": true, "c2": true}
	protoVocab    = map[string]bool{
		"ftp": true, "ftp-data": true, "http": true, "dns": true,
		"tcp": true, "udp": true, "unknown": true,
	}
	confidenceVocab = map[string]bool{"": true, "all": true, "high": true, "medium": true}
)

// rfc3339Nano renders a unix-nanosecond timestamp; zero becomes "" so the UI
// can display "—".
func rfc3339Nano(ns int64) string {
	if ns == 0 {
		return ""
	}
	return time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
}

// ---------------------------------------------------------------------------
// GET /api/case/{id}
// ---------------------------------------------------------------------------

type caseResponse struct {
	ID          string `json:"id"`
	FileName    string `json:"fileName"`
	Size        int64  `json:"size"`
	PCAPSHA256  string `json:"pcapSha256"`
	Status      string `json:"status"`
	Stage       string `json:"stage"`
	Progress    int    `json:"progress"`
	DurationNs  int64  `json:"durationNs"`
	Packets     int64  `json:"packets"`
	Streams     int64  `json:"streams"`
	Files       int64  `json:"files"`
	Events      int64  `json:"events"`
	ToolVersion string `json:"toolVersion"`
	StartedAt   string `json:"startedAt"`
	FinishedAt  string `json:"finishedAt,omitempty"`
	Error       string `json:"error"`
}

func (s *Server) handleCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, tracked := s.runFor(id)
	if tracked && run.status != "ready" {
		writeJSON(w, http.StatusOK, caseFromRun(run))
		return
	}
	c, db, err := s.openCase(id)
	if err != nil {
		if tracked {
			writeJSON(w, http.StatusOK, caseFromRun(run))
			return
		}
		if errors.Is(err, errUnknownCase) {
			writeErr(w, http.StatusNotFound, codeNotFound, "unknown case")
			return
		}
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot open case database")
		return
	}
	meta, err := db.Meta()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot read case metadata")
		return
	}
	nEvents, nFiles, nStreams, err := db.Counts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot count case rows")
		return
	}

	resp := caseResponse{
		ID:          id,
		FileName:    meta["pcap_name"],
		Size:        metaInt(meta, "pcap_size"),
		PCAPSHA256:  meta["pcap_sha256"],
		Packets:     metaInt(meta, "packets"),
		Streams:     nStreams,
		Files:       nFiles,
		Events:      nEvents,
		ToolVersion: meta["tool_version"],
	}
	if resp.PCAPSHA256 != "" {
		// The pipeline writes pcap_sha256 and duration_ns only when it
		// finishes; their presence marks a ready case.
		resp.Status = "ready"
		resp.Stage = "done"
		resp.Progress = 100
		resp.DurationNs = metaInt(meta, "duration_ns")
	} else {
		resp.Status = "failed"
	}
	started := c.Meta.Created
	if started.IsZero() {
		started = time.Unix(0, metaInt(meta, "created_ns")).UTC()
	}
	resp.StartedAt = rfc3339Nano(started.UnixNano())
	if resp.DurationNs > 0 {
		resp.FinishedAt = rfc3339Nano(started.UnixNano() + resp.DurationNs)
	}
	writeJSON(w, http.StatusOK, resp)
}

func caseFromRun(run runSnapshot) caseResponse {
	resp := caseResponse{
		ID:          run.id,
		FileName:    run.fileName,
		Size:        run.size,
		Status:      run.status,
		Stage:       run.stage,
		Progress:    run.progress,
		StartedAt:   rfc3339Nano(run.started),
		Error:       run.errMsg,
		ToolVersion: "",
	}
	if run.finished != 0 && run.started != 0 {
		resp.FinishedAt = rfc3339Nano(run.finished)
		resp.DurationNs = run.finished - run.started
	}
	return resp
}

func (s *Server) handleCaseReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	formatStr := r.URL.Query().Get("format")
	if formatStr == "" {
		formatStr = "html"
	}
	f, err := report.ParseFormat(formatStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, err.Error())
		return
	}

	c, _, err := s.openCase(id)
	if err != nil {
		if errors.Is(err, errUnknownCase) {
			writeErr(w, http.StatusNotFound, codeNotFound, "unknown case")
			return
		}
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot open case")
		return
	}

	data, err := report.Assemble(c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot assemble report")
		return
	}

	var (
		body        []byte
		contentType string
		filename    string
	)
	switch f {
	case report.FormatHTML:
		body, err = report.RenderHTML(data)
		contentType = "text/html; charset=utf-8"
		filename = fmt.Sprintf("raccoon-report-%s.html", id)
	case report.FormatJSON:
		body, err = report.RenderJSON(data)
		contentType = "application/json"
		filename = fmt.Sprintf("raccoon-report-%s.json", id)
	case report.FormatPDF:
		body, err = report.RenderPDF(data)
		contentType = "application/pdf"
		filename = fmt.Sprintf("raccoon-report-%s.pdf", id)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot render report")
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func metaInt(meta map[string]string, key string) int64 {
	n, _ := strconv.ParseInt(meta[key], 10, 64)
	return n
}

// ---------------------------------------------------------------------------
// GET /api/case/{id}/events
// ---------------------------------------------------------------------------

type jsonEvent struct {
	ID         int64          `json:"id"`
	TS         string         `json:"ts"`
	PacketNo   uint64         `json:"packetNo"`
	PacketEnd  uint64         `json:"packetEnd"`
	Type       string         `json:"type"`
	Severity   string         `json:"severity"`
	Phase      string         `json:"phase"`
	StreamID   int64          `json:"streamId"`
	Src        string         `json:"src"`
	Dst        string         `json:"dst"`
	Proto      string         `json:"proto"`
	Title      string         `json:"title"`
	Details    map[string]any `json:"details"`
	Explain    string         `json:"explain"`
	ParentID   int64          `json:"parentId"`
	FileID     int64          `json:"fileId"`
	FindingIDs []int64        `json:"findingIds"`
}

type eventsPage struct {
	Items      []jsonEvent `json:"items"`
	NextCursor string      `json:"nextCursor,omitempty"`
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, db, err := s.openCase(id)
	if errors.Is(err, errUnknownCase) {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown case")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot open case database")
		return
	}
	q := r.URL.Query()

	f := store.EventFilter{Query: q.Get("q"), Cursor: q.Get("cursor"), Flat: q.Get("flat") == "1"}
	if f.Severities, err = parseSeverities(q.Get("severity")); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, err.Error())
		return
	}
	if f.Types, err = parseEventTypes(q.Get("type")); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, err.Error())
		return
	}
	if f.Phase, err = parseVocab(q.Get("phase"), phaseVocab, "phase"); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, err.Error())
		return
	}
	if f.Proto, err = parseVocab(q.Get("proto"), protoVocab, "proto"); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, err.Error())
		return
	}
	if f.Limit, err = parseLimit(q.Get("limit")); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, err.Error())
		return
	}
	if f.From, err = parseTimeBound(q.Get("from")); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, err.Error())
		return
	}
	if f.To, err = parseTimeBound(q.Get("to")); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, err.Error())
		return
	}
	if p := q.Get("parent"); p != "" {
		n, perr := strconv.ParseInt(p, 10, 64)
		if perr != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, codeInvalidQuery, "parent must be a non-negative integer")
			return
		}
		f.Parent = &n
	}

	items, next, err := db.Events(f)
	if errors.Is(err, store.ErrInvalidCursor) {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, "invalid cursor")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot query events")
		return
	}
	page := eventsPage{Items: make([]jsonEvent, 0, len(items)), NextCursor: next}
	for _, e := range items {
		page.Items = append(page.Items, jsonEvent{
			ID:         e.ID,
			TS:         rfc3339Nano(e.TS),
			PacketNo:   e.PacketNo,
			PacketEnd:  e.PacketEnd,
			Type:       string(e.Type),
			Severity:   string(e.Severity),
			Phase:      e.Phase,
			StreamID:   e.StreamID,
			Src:        e.Src,
			Dst:        e.Dst,
			Proto:      e.Proto,
			Title:      e.Title,
			Details:    orEmptyMap(e.Details),
			Explain:    e.Explain,
			ParentID:   e.ParentID,
			FileID:     e.FileID,
			FindingIDs: orEmptySlice(e.FindingIDs),
		})
	}
	writeJSON(w, http.StatusOK, page)
}

func orEmptyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func orEmptySlice(s []int64) []int64 {
	if s == nil {
		return []int64{}
	}
	return s
}

// ---------------------------------------------------------------------------
// GET /api/case/{id}/files
// ---------------------------------------------------------------------------

type jsonVerdict struct {
	Source    string `json:"source"`
	Status    string `json:"status"`
	Score     int    `json:"score"`
	Total     int    `json:"total"`
	CheckedAt string `json:"checkedAt"`
}

type jsonFile struct {
	ID          int64        `json:"id"`
	StreamID    int64        `json:"streamId"`
	Dir         string       `json:"dir"`
	StartOff    int64        `json:"startOff"`
	EndOff      int64        `json:"endOff"`
	Format      string       `json:"format"`
	Ext         string       `json:"ext"`
	Status      string       `json:"status"`
	Confidence  string       `json:"confidence"`
	Size        int64        `json:"size"`
	MD5         string       `json:"md5"`
	SHA256      string       `json:"sha256"`
	DisplayName string       `json:"displayName"`
	Path        string       `json:"path"`
	MagicHex    string       `json:"magicHex"`
	Verdict     *jsonVerdict `json:"verdict,omitempty"`
}

type filesPage struct {
	Items []jsonFile `json:"items"`
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, db, err := s.openCase(id)
	if errors.Is(err, errUnknownCase) {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown case")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot open case database")
		return
	}
	conf := r.URL.Query().Get("confidence")
	if !confidenceVocab[conf] {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery,
			"confidence must be one of all, high, medium")
		return
	}
	files, err := db.Files(store.FileFilter{Confidence: conf})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot query files")
		return
	}
	page := filesPage{Items: make([]jsonFile, 0, len(files))}
	for _, f := range files {
		jf := jsonFile{
			ID:          f.ID,
			StreamID:    f.StreamID,
			Dir:         dirString(f.Dir),
			StartOff:    f.StartOff,
			EndOff:      f.EndOff,
			Format:      f.Format,
			Ext:         f.Ext,
			Status:      f.Status,
			Confidence:  f.Confidence,
			Size:        f.Size,
			MD5:         f.MD5,
			SHA256:      f.SHA256,
			DisplayName: f.DisplayName,
			Path:        f.Path,
			MagicHex:    f.MagicHex,
		}
		if v := pickVerdict(mustVerdicts(db, f.SHA256)); v != nil {
			jf.Verdict = &jsonVerdict{
				Source:    v.Source,
				Status:    v.Status,
				Score:     v.Score,
				Total:     v.Total,
				CheckedAt: rfc3339Nano(v.CheckedAt),
			}
		}
		page.Items = append(page.Items, jf)
	}
	writeJSON(w, http.StatusOK, page)
}

func mustVerdicts(db *store.DB, sha string) []model.Verdict {
	if sha == "" {
		return nil
	}
	vs, err := db.Verdicts(sha)
	if err != nil {
		return nil
	}
	return vs
}

// verdictRank orders verdict statuses worst-first; lower is worse.
func verdictRank(status string) int {
	switch status {
	case "malicious":
		return 0
	case "suspicious":
		return 1
	case "unknown":
		return 2
	case "not_checked":
		return 3
	case "no_detections":
		return 4
	default:
		return 5
	}
}

// pickVerdict returns the most severe verdict for one file; equal severity
// resolves to the most recent check.
func pickVerdict(vs []model.Verdict) *model.Verdict {
	var best *model.Verdict
	for i := range vs {
		v := &vs[i]
		if best == nil {
			best = v
			continue
		}
		br, vr := verdictRank(best.Status), verdictRank(v.Status)
		if vr < br || (vr == br && v.CheckedAt > best.CheckedAt) {
			best = v
		}
	}
	return best
}

func dirString(d model.Direction) string {
	if d == model.S2C {
		return "s2c"
	}
	return "c2s"
}

// ---------------------------------------------------------------------------
// GET /api/case/{id}/streams
// ---------------------------------------------------------------------------

type jsonStream struct {
	ID          int64  `json:"id"`
	ParentID    int64  `json:"parentId"`
	Proto       string `json:"proto"`
	SrcIP       string `json:"srcIp"`
	SrcPort     uint16 `json:"srcPort"`
	DstIP       string `json:"dstIp"`
	DstPort     uint16 `json:"dstPort"`
	StartTS     string `json:"startTs"`
	EndTS       string `json:"endTs"`
	BytesC2S    int64  `json:"bytesC2S"`
	BytesS2C    int64  `json:"bytesS2C"`
	Packets     int64  `json:"packets"`
	FirstPacket uint64 `json:"firstPacket"`
	LastPacket  uint64 `json:"lastPacket"`
	Midstream   bool   `json:"midstream"`
	HasGaps     bool   `json:"hasGaps"`
	UDP         bool   `json:"udp"`
}

type streamsPage struct {
	Items      []jsonStream `json:"items"`
	NextCursor string       `json:"nextCursor,omitempty"`
}

func (s *Server) handleStreams(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, db, err := s.openCase(id)
	if errors.Is(err, errUnknownCase) {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown case")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot open case database")
		return
	}
	q := r.URL.Query()
	f := store.StreamFilter{Query: q.Get("q"), Cursor: q.Get("cursor")}
	if f.Proto, err = parseVocab(q.Get("proto"), protoVocab, "proto"); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, err.Error())
		return
	}
	if f.Limit, err = parseLimit(q.Get("limit")); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, err.Error())
		return
	}
	items, next, err := db.Streams(f)
	if errors.Is(err, store.ErrInvalidCursor) {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, "invalid cursor")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot query streams")
		return
	}
	page := streamsPage{Items: make([]jsonStream, 0, len(items)), NextCursor: next}
	for _, st := range items {
		page.Items = append(page.Items, jsonStream{
			ID:          st.ID,
			ParentID:    st.ParentID,
			Proto:       st.Proto,
			SrcIP:       st.SrcIP,
			SrcPort:     st.SrcPort,
			DstIP:       st.DstIP,
			DstPort:     st.DstPort,
			StartTS:     rfc3339Nano(st.StartTS),
			EndTS:       rfc3339Nano(st.EndTS),
			BytesC2S:    st.BytesC2S,
			BytesS2C:    st.BytesS2C,
			Packets:     st.Packets,
			FirstPacket: st.FirstPacket,
			LastPacket:  st.LastPacket,
			Midstream:   st.Midstream,
			HasGaps:     st.HasGaps,
			UDP:         st.UDP,
		})
	}
	writeJSON(w, http.StatusOK, page)
}

// ---------------------------------------------------------------------------
// query parameter parsing
// ---------------------------------------------------------------------------

// badQuery formats the 400 message for a rejected parameter.
func badQuery(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

func parseVocab(v string, vocab map[string]bool, name string) (string, error) {
	if v == "" {
		return "", nil
	}
	if !vocab[v] {
		return "", badQuery("invalid %s %q", name, v)
	}
	return v, nil
}

func parseSeverities(v string) ([]model.Severity, error) {
	if v == "" {
		return nil, nil
	}
	var out []model.Severity
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if !severityVocab[part] {
			return nil, badQuery("invalid severity %q", part)
		}
		out = append(out, model.Severity(part))
	}
	return out, nil
}

// parseEventTypes accepts a comma-separated set of event types.
func parseEventTypes(v string) ([]model.EventType, error) {
	if v == "" {
		return nil, nil
	}
	var out []model.EventType
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, badQuery("invalid type %q", v)
		}
		out = append(out, model.EventType(part))
	}
	return out, nil
}

func parseLimit(v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > limits.EventsPageSizeMax {
		return 0, badQuery("limit must be between 1 and %d", limits.EventsPageSizeMax)
	}
	return n, nil
}

func parseTimeBound(v string) (int64, error) {
	if v == "" {
		return 0, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return 0, badQuery("invalid time %q: expected RFC 3339", v)
	}
	return t.UnixNano(), nil
}
