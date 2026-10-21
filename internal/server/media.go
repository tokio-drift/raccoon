package server

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
)

// ---------------------------------------------------------------------------
// GET /api/case/{id}/streams/{sid}/bytes
// ---------------------------------------------------------------------------

type jsonSegment struct {
	Off      int64  `json:"off"`
	Len      uint32 `json:"len"`
	TS       string `json:"ts"`
	PacketNo uint64 `json:"packetNo"`
}

type jsonCarvedRange struct {
	FileID int64 `json:"fileId"`
	Start  int64 `json:"start"`
	End    int64 `json:"end"`
}

type streamBytesResponse struct {
	StreamID   int64             `json:"streamId"`
	Dir        string            `json:"dir"`
	Offset     int64             `json:"offset"`
	Length     int64             `json:"length"`
	Total      int64             `json:"total"`
	DataBase64 string            `json:"dataBase64"`
	Segments   []jsonSegment     `json:"segments"`
	Carved     []jsonCarvedRange `json:"carved"`
}

func (s *Server) handleStreamBytes(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sid, ok := parsePositiveID(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown stream")
		return
	}
	dir, ok := parseDirection(r.URL.Query().Get("dir"))
	if !ok {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, "dir must be c2s or s2c")
		return
	}
	offset, ok := parseNonNegativeInt(r.URL.Query().Get("offset"), 0)
	if !ok {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, "offset must be a non-negative integer")
		return
	}
	length, ok := parseNonNegativeInt(r.URL.Query().Get("len"), 4096)
	if !ok {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, "len must be a non-negative integer")
		return
	}
	if length > limits.StreamBytesMaxLen {
		length = limits.StreamBytesMaxLen
	}

	c, db, err := s.openCase(id)
	if errors.Is(err, errUnknownCase) {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown case")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot open case database")
		return
	}

	st, err := db.StreamByID(sid)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown stream")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot read stream")
		return
	}

	total := st.BytesC2S
	if dir == model.S2C {
		total = st.BytesS2C
	}
	want := length
	if offset > total {
		want = 0
	} else if want > total-offset {
		want = total - offset
	}

	data := make([]byte, want)
	n, readErr := readStreamWindow(c, sid, dir, offset, data)
	if readErr != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot read stream data")
		return
	}
	data = data[:n]

	segments, err := db.SegmentsFor(sid, dir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot read stream segments")
		return
	}
	files, err := db.Files(store.FileFilter{Confidence: store.ConfidenceAll})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot read carved files")
		return
	}

	windowEnd := offset + want
	resp := streamBytesResponse{
		StreamID:   sid,
		Dir:        dirString(dir),
		Offset:     offset,
		Length:     int64(n),
		Total:      total,
		DataBase64: base64.StdEncoding.EncodeToString(data),
		Segments:   make([]jsonSegment, 0),
		Carved:     make([]jsonCarvedRange, 0),
	}
	for _, seg := range segments {
		end := seg.Offset + int64(seg.Length)
		if end <= offset || seg.Offset >= windowEnd {
			continue
		}
		resp.Segments = append(resp.Segments, jsonSegment{
			Off:      seg.Offset,
			Len:      seg.Length,
			TS:       rfc3339Nano(seg.TS),
			PacketNo: seg.PacketNo,
		})
	}
	for _, f := range files {
		if f.StreamID != sid || f.Dir != dir {
			continue
		}
		if f.EndOff <= offset || f.StartOff >= windowEnd {
			continue
		}
		resp.Carved = append(resp.Carved, jsonCarvedRange{
			FileID: f.ID,
			Start:  f.StartOff,
			End:    f.EndOff,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// readStreamWindow reads up to len(buf) bytes starting at offset from the
// stream spool. A missing spool (for example a UDP flow) yields no bytes.
func readStreamWindow(c *casedir.Case, sid int64, dir model.Direction, offset int64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	f, err := os.Open(c.StreamPath(sid, dir))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()

	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// GET /api/case/{id}/files/{fid}/download
// ---------------------------------------------------------------------------

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	fid, ok := parsePositiveID(r.PathValue("fid"))
	if !ok {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown file")
		return
	}
	c, db, err := s.openCase(id)
	if errors.Is(err, errUnknownCase) {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown case")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot open case database")
		return
	}

	f, err := db.FileByID(fid)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown file")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot read file")
		return
	}

	path, ok := safeCarvedPath(c, f.Path)
	if !ok {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown file")
		return
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown file")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot open file")
		return
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil || st.IsDir() {
		writeErr(w, http.StatusNotFound, codeNotFound, "unknown file")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+downloadName(f)+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, downloadName(f), st.ModTime(), file)
}

// safeCarvedPath resolves a database path to a regular file inside the case's
// carved directory. Absolute paths, traversal, and symlink escapes are
// rejected.
func safeCarvedPath(c *casedir.Case, rel string) (string, bool) {
	if rel == "" || strings.ContainsRune(rel, 0) || filepath.IsAbs(rel) {
		return "", false
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", false
	}
	abs, err := filepath.Abs(filepath.Join(c.Dir, clean))
	if err != nil {
		return "", false
	}
	carved, err := filepath.Abs(c.CarvedDir())
	if err != nil {
		return "", false
	}
	if !pathWithin(carved, abs) {
		return "", false
	}

	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false
	}
	realCarved, err := filepath.EvalSymlinks(carved)
	if err != nil {
		return "", false
	}
	if !pathWithin(realCarved, real) {
		return "", false
	}
	return real, true
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// downloadName returns a safe ASCII attachment filename derived only from the
// database row.
func downloadName(f *model.CarvedFile) string {
	name := f.DisplayName
	if name == "" {
		name = filepath.Base(f.Path)
	}
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f || r == '"' || r == '\\' || r == '/':
			b.WriteByte('_')
		case r > 0x7e:
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	name = strings.TrimSpace(b.String())
	if name == "" || name == "." || name == ".." {
		name = "file"
	}
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

// ---------------------------------------------------------------------------
// parameter parsing
// ---------------------------------------------------------------------------

func parsePositiveID(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func parseNonNegativeInt(s string, def int64) (int64, bool) {
	if s == "" {
		return def, true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func parseDirection(s string) (model.Direction, bool) {
	switch s {
	case "c2s":
		return model.C2S, true
	case "s2c":
		return model.S2C, true
	default:
		return 0, false
	}
}
