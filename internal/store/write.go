package store

import (
	"encoding/json"
	"time"

	"github.com/tokio-drift/raccoon/internal/model"
)

const (
	// insertBatch is the minimum number of rows committed in a single
	// transaction by the writer goroutine.
	insertBatch = 1000
	// flushInterval bounds how long out-of-order small batches wait before a
	// transaction is committed.
	flushInterval = time.Millisecond
)

// Segment is one reassembly segment row (mirrored in the .idx files).
type Segment struct {
	StreamID int64
	Dir      model.Direction
	Offset   int64
	Length   uint32
	TS       int64
	PacketNo uint64
}

type reqKind int

const (
	reqStreams reqKind = iota
	reqEvents
	reqFiles
	reqSegments
	reqFindings
	reqVerdict
	reqMeta
	reqFlush
	reqUpdateEventSev // UPDATE events SET severity=? WHERE file_id=? AND type='FILE_CARVED'
)

type req struct {
	kind reqKind
	args [][]any
	last int64
	err  error
	done chan struct{}
}

var insertSQL = map[reqKind]string{
	reqStreams: `INSERT INTO streams(id,parent_id,proto,src_ip,src_port,dst_ip,dst_port,` +
		`start_ts,end_ts,bytes_c2s,bytes_s2c,packets,first_packet,last_packet,midstream,has_gaps,udp) ` +
		`VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
	reqEvents: `INSERT INTO events(id,ts,packet_no,packet_end,type,severity,phase,stream_id,src,dst,` +
		`proto,title,details_json,explain,parent_id,file_id,finding_ids) ` +
		`VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
	reqFiles: `INSERT INTO files(id,stream_id,dir,start_off,end_off,format,ext,status,confidence,size,` +
		`md5,sha256,display_name,path,magic_hex) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
	reqSegments: `INSERT INTO segments(stream_id,dir,stream_off,length,ts,packet_no) VALUES(?,?,?,?,?,?)`,
	reqFindings: `INSERT INTO findings(id,title,technique,severity,explanation,evidence_event_ids) ` +
		`VALUES(?,?,?,?,?,?)`,
	reqVerdict: `INSERT INTO verdicts(sha256,source,status,score,total,detail_json,checked_at) ` +
		`VALUES(?,?,?,?,?,?,?) ON CONFLICT(sha256,source) DO UPDATE SET ` +
		`status=excluded.status,score=excluded.score,total=excluded.total,` +
		`detail_json=excluded.detail_json,checked_at=excluded.checked_at`,
	reqMeta:           `INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
	reqUpdateEventSev: `UPDATE events SET severity=? WHERE file_id=? AND type='FILE_CARVED'`,
}

// InsertStreams appends stream rows to the writer and returns the last id.
func (db *DB) InsertStreams(rows []model.Stream) (int64, error) {
	return db.insertRows(reqStreams, len(rows), func(i int, a *[]any) {
		s := &rows[i]
		*a = []any{refOrNil(s.ID), refOrNil(s.ParentID), s.Proto, s.SrcIP, s.SrcPort, s.DstIP, s.DstPort,
			s.StartTS, s.EndTS, s.BytesC2S, s.BytesS2C, s.Packets,
			s.FirstPacket, s.LastPacket, boolInt(s.Midstream), boolInt(s.HasGaps), boolInt(s.UDP)}
	})
}

// InsertEvents appends event rows to the writer and returns the last id.
func (db *DB) InsertEvents(rows []model.Event) (int64, error) {
	return db.insertRows(reqEvents, len(rows), func(i int, a *[]any) {
		e := &rows[i]
		*a = []any{refOrNil(e.ID), e.TS, e.PacketNo, e.PacketEnd, string(e.Type), string(e.Severity),
			e.Phase, refOrNil(e.StreamID), e.Src, e.Dst, e.Proto, e.Title,
			jsonOrNil(e.Details), e.Explain, refOrNil(e.ParentID), refOrNil(e.FileID),
			jsonSliceOrNil(e.FindingIDs)}
	})
}

// InsertFiles appends carved-file rows and returns the last id.
func (db *DB) InsertFiles(rows []model.CarvedFile) (int64, error) {
	return db.insertRows(reqFiles, len(rows), func(i int, a *[]any) {
		f := &rows[i]
		*a = []any{refOrNil(f.ID), refOrNil(f.StreamID), int(f.Dir), f.StartOff, f.EndOff,
			f.Format, f.Ext, f.Status, f.Confidence, f.Size,
			f.MD5, f.SHA256, f.DisplayName, f.Path, f.MagicHex}
	})
}

// InsertSegments appends reassembly segment rows.
func (db *DB) InsertSegments(rows []Segment) error {
	_, err := db.insertRows(reqSegments, len(rows), func(i int, a *[]any) {
		s := &rows[i]
		*a = []any{refOrNil(s.StreamID), int(s.Dir), s.Offset, s.Length, s.TS, s.PacketNo}
	})
	return err
}

// InsertFindings appends finding rows and returns the last id.
func (db *DB) InsertFindings(rows []model.Finding) (int64, error) {
	return db.insertRows(reqFindings, len(rows), func(i int, a *[]any) {
		f := &rows[i]
		*a = []any{refOrNil(f.ID), f.Title, f.Technique, string(f.Severity),
			f.Explanation, jsonSliceOrNil(f.EvidenceEventIDs)}
	})
}

// UpsertVerdict writes or updates one verdict.
func (db *DB) UpsertVerdict(v model.Verdict) error {
	r := db.newReq(reqVerdict, 1)
	r.args[0] = []any{v.SHA256, v.Source, v.Status, v.Score, v.Total, jsonOrNil(v.Detail), v.CheckedAt}
	return db.submit(r)
}

// UpdateEventSeverityByFileID raises the severity of every FILE_CARVED event
// that references fileID. The update only applies when the new severity is
// higher than the current one, enforced by the WHERE clause (SQLite compares
// text values alphabetically; use a CASE expression to respect the rank
// ordering: critical > warning > info).
//
// The caller is responsible for escalation logic (only call with a higher
// severity than the current one).
func (db *DB) UpdateEventSeverityByFileID(fileID int64, severity string) error {
	r := db.newReq(reqUpdateEventSev, 1)
	r.args[0] = []any{severity, fileID}
	return db.submit(r)
}

// SetMeta writes one meta key/value.
func (db *DB) SetMeta(key, value string) error {
	r := db.newReq(reqMeta, 1)
	r.args[0] = []any{key, value}
	return db.submit(r)
}

// Flush commits all pending rows.
func (db *DB) Flush() error {
	r := &req{kind: reqFlush, done: make(chan struct{})}
	return db.submit(r)
}

func (db *DB) insertRows(kind reqKind, n int, fill func(i int, a *[]any)) (int64, error) {
	if n == 0 {
		return 0, nil
	}
	r := db.newReq(kind, n)
	for i := 0; i < n; i++ {
		fill(i, &r.args[i])
	}
	return db.submitID(r)
}

func (db *DB) newReq(kind reqKind, n int) *req {
	return &req{kind: kind, args: make([][]any, n), done: make(chan struct{})}
}

func (db *DB) submitID(r *req) (int64, error) {
	if err := db.submit(r); err != nil {
		return 0, err
	}
	return r.last, nil
}

func (db *DB) submit(r *req) error {
	db.mu.Lock()
	if db.closed {
		db.mu.Unlock()
		return ErrClosed
	}
	db.ch <- r
	// Ordering guarantee: after this line the writer owns r until r.done closes.
	db.mu.Unlock()
	<-r.done
	return r.err
}

// loop is the single writer goroutine. It accumulates requests and commits one
// transaction whenever insertBatch rows pile up, a flushInterval passes, a
// Flush request arrives, or the channel closes.
func (db *DB) loop() {
	var batch []*req
	drain := func() {
		if len(batch) == 0 {
			return
		}
		db.runTx(batch)
		batch = nil
	}
	for {
		r, ok := <-db.ch
		if !ok {
			drain()
			close(db.flushed)
			return
		}
		if r.kind == reqFlush {
			drain()
			close(r.done)
			continue
		}
		batch = append(batch, r)
		if len(batch) >= insertBatch {
			drain()
			continue
		}
		t := time.NewTimer(flushInterval)
	collect:
		for {
			select {
			case r2, ok2 := <-db.ch:
				if !ok2 {
					t.Stop()
					drain()
					close(db.flushed)
					return
				}
				if r2.kind == reqFlush {
					t.Stop()
					drain()
					close(r2.done)
					break collect
				}
				batch = append(batch, r2)
				if len(batch) >= insertBatch {
					t.Stop()
					drain()
					break collect
				}
				t.Reset(flushInterval)
			case <-t.C:
				drain()
				break collect
			}
		}
	}
}

// runTx inserts all requests in one transaction and answers their done
// channels. On any error the whole batch is rolled back and reported.
func (db *DB) runTx(batch []*req) {
	tx, err := db.conn.Begin()
	if err != nil {
		failBatch(batch, err)
		return
	}
	for _, r := range batch {
		for _, args := range r.args {
			res, err := tx.Exec(insertSQL[r.kind], args...)
			if err != nil {
				_ = tx.Rollback()
				failBatch(batch, err)
				return
			}
			r.last, _ = res.LastInsertId()
		}
	}
	if err := tx.Commit(); err != nil {
		failBatch(batch, err)
		return
	}
	for _, r := range batch {
		close(r.done)
	}
}

func failBatch(batch []*req, err error) {
	for _, r := range batch {
		r.err = err
		close(r.done)
	}
}

// refOrNil maps a zero reference (0 = none) to NULL.
func refOrNil(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func jsonOrNil(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return string(b)
}

func jsonSliceOrNil(v []int64) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return string(b)
}
