package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrInvalidCursor is returned when a pagination cursor cannot be decoded.
var ErrInvalidCursor = errors.New("store: invalid cursor")

// Confidence level values accepted by FileFilter.Confidence.
const (
	// ConfidenceDefault hides low-confidence files (the API default).
	ConfidenceDefault = ""
	// ConfidenceAll includes every confidence level.
	ConfidenceAll = "all"
)

// EventFilter selects events for Events. The zero value matches every event.
type EventFilter struct {
	// Severities, when non-empty, keeps only events whose severity is in the
	// set. An empty set means "any severity".
	Severities []model.Severity
	// Types, when non-empty, keeps only events whose type is in the set.
	Types []model.EventType
	// Phase, when non-empty, keeps only events in that phase.
	Phase string
	// Proto, when non-empty, keeps only events with that protocol.
	Proto string
	// Query, when non-empty, is a case-insensitive substring match over the
	// event title and its serialised details.
	Query string
	// From bounds the event timestamp (unix ns) inclusively; zero is unbounded.
	From int64
	// To bounds the event timestamp (unix ns) exclusively; zero is unbounded.
	To int64
	// Parent, when set, returns only the children of that event id. It takes
	// precedence over Flat.
	Parent *int64
	// Flat includes grouped children (events with a non-zero parent_id) in a
	// top-level query. When false and Parent is nil such children are excluded.
	Flat bool
	// Limit is the maximum page size. Zero uses limits.EventsPageSizeDefault;
	// values above limits.EventsPageSizeMax are clamped.
	Limit int
	// Cursor resumes a previous page. Pass the nextCursor value returned by the
	// preceding call unchanged; the empty string starts at the first page.
	Cursor string
}

// FileFilter selects carved files for Files. The zero value hides low
// confidence files, matching the HTTP API default.
type FileFilter struct {
	// Confidence selects a confidence level: "high" or "medium" match exactly,
	// "all" (or ConfidenceAll) includes every level, and the empty string hides
	// low-confidence files.
	Confidence string
}

// StreamFilter selects streams for Streams. The zero value matches every stream.
type StreamFilter struct {
	// Query, when non-empty, is a case-insensitive substring match over the
	// source and destination "ip:port" and the protocol.
	Query string
	// Proto, when non-empty, keeps only streams with that protocol.
	Proto string
	// Limit is the maximum page size. Zero uses limits.EventsPageSizeDefault;
	// values above limits.EventsPageSizeMax are clamped.
	Limit int
	// Cursor resumes a previous page (id keyset pagination).
	Cursor string
}

// column lists for the query functions.
const (
	eventColumns = `id,ts,packet_no,packet_end,type,severity,phase,stream_id,src,dst,` +
		`proto,title,details_json,explain,parent_id,file_id,finding_ids`
	streamColumns = `id,parent_id,proto,src_ip,src_port,dst_ip,dst_port,start_ts,end_ts,` +
		`bytes_c2s,bytes_s2c,packets,first_packet,last_packet,midstream,has_gaps,udp`
	fileColumns = `id,stream_id,dir,start_off,end_off,format,ext,status,confidence,size,` +
		`md5,sha256,display_name,path,magic_hex`
	verdictColumns = `sha256,source,status,score,total,detail_json,checked_at`
)

// Events returns one keyset-paginated page of events ordered by (ts, id)
// ascending, plus the cursor for the next page (empty when the page is last).
func (db *DB) Events(f EventFilter) ([]model.Event, string, error) {
	var (
		conds []string
		args  []any
	)
	if len(f.Severities) > 0 {
		conds = append(conds, "severity IN ("+placeholders(len(f.Severities))+")")
		for _, s := range f.Severities {
			args = append(args, string(s))
		}
	}
	if len(f.Types) > 0 {
		conds = append(conds, "type IN ("+placeholders(len(f.Types))+")")
		for _, t := range f.Types {
			args = append(args, string(t))
		}
	}
	if f.Phase != "" {
		conds = append(conds, "phase = ?")
		args = append(args, f.Phase)
	}
	if f.Proto != "" {
		conds = append(conds, "proto = ?")
		args = append(args, f.Proto)
	}
	if f.Query != "" {
		conds = append(conds, "(instr(lower(coalesce(title,'')), lower(?)) > 0"+
			" OR instr(lower(coalesce(details_json,'')), lower(?)) > 0)")
		args = append(args, f.Query, f.Query)
	}
	if f.From != 0 {
		conds = append(conds, "ts >= ?")
		args = append(args, f.From)
	}
	if f.To != 0 {
		conds = append(conds, "ts < ?")
		args = append(args, f.To)
	}
	switch {
	case f.Parent != nil:
		conds = append(conds, "coalesce(parent_id,0) = ?")
		args = append(args, *f.Parent)
	case !f.Flat:
		conds = append(conds, "coalesce(parent_id,0) = 0")
	}
	if f.Cursor != "" {
		ts, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		conds = append(conds, "(ts > ? OR (ts = ? AND id > ?))")
		args = append(args, ts, ts, id)
	}

	limit := clampLimit(f.Limit)
	// ix_events_ts is an index on (ts) whose implicit rowid tiebreaker is the
	// primary key id, so it satisfies the (ts, id) ordering without a sort. The
	// planner otherwise prefers a filter index and builds a temp B-tree over the
	// whole match set; hinting the ordered index keeps keyset paging O(page)
	// even for large cases.
	q := "SELECT " + eventColumns + " FROM events INDEXED BY ix_events_ts"
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY ts ASC, id ASC LIMIT ?"
	args = append(args, limit+1)

	rows, err := db.conn.Query(q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("store: query events: %w", err)
	}
	defer rows.Close()

	items := make([]model.Event, 0, limit)
	for rows.Next() {
		var e model.Event
		if err := scanEvent(rows, &e); err != nil {
			return nil, "", fmt.Errorf("store: scan event: %w", err)
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("store: query events: %w", err)
	}
	return trimPage(items, limit, func(e model.Event) string { return encodeCursor(e.TS, e.ID) })
}

// Files returns carved files matching the filter, ordered by id ascending.
func (db *DB) Files(f FileFilter) ([]model.CarvedFile, error) {
	var (
		conds []string
		args  []any
	)
	switch f.Confidence {
	case ConfidenceDefault:
		conds = append(conds, "coalesce(confidence,'') <> 'low'")
	case ConfidenceAll:
		// No confidence constraint.
	default:
		conds = append(conds, "confidence = ?")
		args = append(args, f.Confidence)
	}

	q := "SELECT " + fileColumns + " FROM files"
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id ASC"

	rows, err := db.conn.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query files: %w", err)
	}
	defer rows.Close()

	var items []model.CarvedFile
	for rows.Next() {
		var (
			f        model.CarvedFile
			streamID sql.NullInt64
			dir      int64
		)
		if err := rows.Scan(&f.ID, &streamID, &dir, &f.StartOff, &f.EndOff,
			&f.Format, &f.Ext, &f.Status, &f.Confidence, &f.Size,
			&f.MD5, &f.SHA256, &f.DisplayName, &f.Path, &f.MagicHex); err != nil {
			return nil, fmt.Errorf("store: scan file: %w", err)
		}
		f.StreamID = streamID.Int64
		f.Dir = model.Direction(dir)
		items = append(items, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query files: %w", err)
	}
	return items, nil
}

// Streams returns one keyset-paginated page of streams ordered by id ascending,
// plus the cursor for the next page (empty when the page is last).
func (db *DB) Streams(f StreamFilter) ([]model.Stream, string, error) {
	var (
		conds []string
		args  []any
	)
	if f.Query != "" {
		conds = append(conds, "(instr(lower(src_ip || ':' || src_port), lower(?)) > 0"+
			" OR instr(lower(dst_ip || ':' || dst_port), lower(?)) > 0"+
			" OR instr(lower(proto), lower(?)) > 0)")
		args = append(args, f.Query, f.Query, f.Query)
	}
	if f.Proto != "" {
		conds = append(conds, "proto = ?")
		args = append(args, f.Proto)
	}
	if f.Cursor != "" {
		id, err := decodeIDCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		conds = append(conds, "id > ?")
		args = append(args, id)
	}

	limit := clampLimit(f.Limit)
	q := "SELECT " + streamColumns + " FROM streams"
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id ASC LIMIT ?"
	args = append(args, limit+1)

	rows, err := db.conn.Query(q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("store: query streams: %w", err)
	}
	defer rows.Close()

	items := make([]model.Stream, 0, limit)
	for rows.Next() {
		var s model.Stream
		if err := scanStream(rows, &s); err != nil {
			return nil, "", fmt.Errorf("store: scan stream: %w", err)
		}
		items = append(items, s)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("store: query streams: %w", err)
	}
	return trimPage(items, limit, func(s model.Stream) string { return encodeIDCursor(s.ID) })
}

// FileByID returns one carved file. It returns ErrNotFound when the id is
// unknown.
func (db *DB) FileByID(id int64) (*model.CarvedFile, error) {
	row := db.conn.QueryRow("SELECT "+fileColumns+" FROM files WHERE id = ?", id)
	var (
		f        model.CarvedFile
		streamID sql.NullInt64
		dir      int64
	)
	if err := row.Scan(&f.ID, &streamID, &dir, &f.StartOff, &f.EndOff,
		&f.Format, &f.Ext, &f.Status, &f.Confidence, &f.Size,
		&f.MD5, &f.SHA256, &f.DisplayName, &f.Path, &f.MagicHex); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: file %d", ErrNotFound, id)
		}
		return nil, fmt.Errorf("store: query file %d: %w", id, err)
	}
	f.StreamID = streamID.Int64
	f.Dir = model.Direction(dir)
	return &f, nil
}

// StreamByID returns one stream. It returns ErrNotFound when the id is unknown.
func (db *DB) StreamByID(id int64) (*model.Stream, error) {
	row := db.conn.QueryRow("SELECT "+streamColumns+" FROM streams WHERE id = ?", id)
	var s model.Stream
	if err := scanStream(row, &s); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: stream %d", ErrNotFound, id)
		}
		return nil, fmt.Errorf("store: query stream %d: %w", id, err)
	}
	return &s, nil
}

// SegmentsFor returns the reassembly segments for one stream direction, ordered
// by stream offset ascending.
func (db *DB) SegmentsFor(streamID int64, dir model.Direction) ([]Segment, error) {
	rows, err := db.conn.Query(
		`SELECT stream_id,dir,stream_off,length,ts,packet_no FROM segments `+
			`WHERE stream_id = ? AND dir = ? ORDER BY stream_off ASC`,
		streamID, int(dir))
	if err != nil {
		return nil, fmt.Errorf("store: query segments: %w", err)
	}
	defer rows.Close()

	var out []Segment
	for rows.Next() {
		var (
			seg      Segment
			d, pktNo int64
		)
		if err := rows.Scan(&seg.StreamID, &d, &seg.Offset, &seg.Length, &seg.TS, &pktNo); err != nil {
			return nil, fmt.Errorf("store: scan segment: %w", err)
		}
		seg.Dir = model.Direction(d)
		seg.PacketNo = uint64(pktNo)
		out = append(out, seg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query segments: %w", err)
	}
	return out, nil
}

// Verdicts returns every verdict recorded for a file SHA-256, ordered by source.
func (db *DB) Verdicts(sha string) ([]model.Verdict, error) {
	rows, err := db.conn.Query(
		"SELECT "+verdictColumns+" FROM verdicts WHERE sha256 = ? ORDER BY source ASC", sha)
	if err != nil {
		return nil, fmt.Errorf("store: query verdicts: %w", err)
	}
	defer rows.Close()

	var out []model.Verdict
	for rows.Next() {
		var (
			v      model.Verdict
			detail sql.NullString
		)
		if err := rows.Scan(&v.SHA256, &v.Source, &v.Status, &v.Score, &v.Total,
			&detail, &v.CheckedAt); err != nil {
			return nil, fmt.Errorf("store: scan verdict: %w", err)
		}
		if detail.Valid && detail.String != "" {
			if err := json.Unmarshal([]byte(detail.String), &v.Detail); err != nil {
				return nil, fmt.Errorf("store: decode verdict detail: %w", err)
			}
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query verdicts: %w", err)
	}
	return out, nil
}

// Counts returns the total number of events, carved files and streams stored
// for a case. It is used by the case metadata endpoint.
func (db *DB) Counts() (events, files, streams int64, err error) {
	err = db.conn.QueryRow(
		`SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM files),(SELECT COUNT(*) FROM streams)`).
		Scan(&events, &files, &streams)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("store: counts: %w", err)
	}
	return events, files, streams, nil
}

// Meta returns all case metadata key/value pairs.
func (db *DB) Meta() (map[string]string, error) {
	rows, err := db.conn.Query("SELECT key,value FROM meta ORDER BY key ASC")
	if err != nil {
		return nil, fmt.Errorf("store: query meta: %w", err)
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("store: scan meta: %w", err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query meta: %w", err)
	}
	return out, nil
}

// scanEvent reads one event row in eventColumns order.
func scanEvent(sc interface{ Scan(...any) error }, e *model.Event) error {
	var (
		typ, sev                    string
		pktNo, pktEnd               int64
		streamID, parentID, fileID  sql.NullInt64
		details, explain, findingID sql.NullString
	)
	if err := sc.Scan(&e.ID, &e.TS, &pktNo, &pktEnd, &typ, &sev, &e.Phase,
		&streamID, &e.Src, &e.Dst, &e.Proto, &e.Title, &details, &explain,
		&parentID, &fileID, &findingID); err != nil {
		return err
	}
	e.PacketNo = uint64(pktNo)
	e.PacketEnd = uint64(pktEnd)
	e.Type = model.EventType(typ)
	e.Severity = model.Severity(sev)
	e.StreamID = streamID.Int64
	e.ParentID = parentID.Int64
	e.FileID = fileID.Int64
	e.Explain = explain.String
	if details.Valid && details.String != "" {
		if err := json.Unmarshal([]byte(details.String), &e.Details); err != nil {
			return fmt.Errorf("decode details: %w", err)
		}
	}
	if findingID.Valid && findingID.String != "" {
		if err := json.Unmarshal([]byte(findingID.String), &e.FindingIDs); err != nil {
			return fmt.Errorf("decode finding ids: %w", err)
		}
	}
	return nil
}

// scanStream reads one stream row in streamColumns order.
func scanStream(sc interface{ Scan(...any) error }, s *model.Stream) error {
	var (
		parentID                sql.NullInt64
		srcPort, dstPort        int64
		srcIP, dstIP, proto     string
		midstream, hasGaps, udp int64
	)
	if err := sc.Scan(&s.ID, &parentID, &proto, &srcIP, &srcPort, &dstIP, &dstPort,
		&s.StartTS, &s.EndTS, &s.BytesC2S, &s.BytesS2C, &s.Packets,
		&s.FirstPacket, &s.LastPacket, &midstream, &hasGaps, &udp); err != nil {
		return err
	}
	s.ParentID = parentID.Int64
	s.Proto = proto
	s.SrcIP = srcIP
	s.SrcPort = uint16(srcPort)
	s.DstIP = dstIP
	s.DstPort = uint16(dstPort)
	s.Midstream = midstream != 0
	s.HasGaps = hasGaps != 0
	s.UDP = udp != 0
	return nil
}

// trimPage drops the extra look-ahead row used to detect a following page and
// returns the cursor pointing at its last retained item.
func trimPage[T any](items []T, limit int, cursor func(T) string) ([]T, string, error) {
	if len(items) > limit {
		next := cursor(items[limit-1])
		return items[:limit], next, nil
	}
	return items, "", nil
}

// clampLimit applies the default and maximum event page sizes.
func clampLimit(n int) int {
	switch {
	case n <= 0:
		return limits.EventsPageSizeDefault
	case n > limits.EventsPageSizeMax:
		return limits.EventsPageSizeMax
	default:
		return n
	}
}

// placeholders returns n comma-separated "?" bind markers.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?,", n-1) + "?"
}

// encodeCursor encodes an event (ts, id) keyset cursor. The encoding is opaque
// to callers and only meaningful to decodeCursor.
func encodeCursor(ts, id int64) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(strconv.FormatInt(ts, 10) + ":" + strconv.FormatInt(id, 10)))
}

// decodeCursor decodes an event cursor produced by encodeCursor.
func decodeCursor(s string) (int64, int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %v", ErrInvalidCursor, err)
	}
	tsStr, idStr, ok := strings.Cut(string(raw), ":")
	if !ok {
		return 0, 0, fmt.Errorf("%w: missing separator", ErrInvalidCursor)
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: bad ts", ErrInvalidCursor)
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: bad id", ErrInvalidCursor)
	}
	return ts, id, nil
}

// encodeIDCursor encodes an id keyset cursor for stream pagination.
func encodeIDCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(id, 10)))
}

// decodeIDCursor decodes a cursor produced by encodeIDCursor.
func decodeIDCursor(s string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidCursor, err)
	}
	id, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: bad id", ErrInvalidCursor)
	}
	return id, nil
}
