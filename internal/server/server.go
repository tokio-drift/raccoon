// Package server serves the RACCOON HTTP API and the embedded web UI on the
// loopback interface. See docs/api.md for the endpoint contract.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/store"
)

// Config configures a Server.
type Config struct {
	// Token is the session token required on every /api request. Required.
	Token string
	// DataDir is the directory holding one sub-directory per case. Required.
	DataDir string
	// Dist is the embedded web UI asset tree (web.Dist). When nil only the
	// API is served.
	Dist fs.FS
	// Addr is the TCP listen address. Empty means "127.0.0.1:0" (an
	// ephemeral port chosen by the kernel).
	Addr string
}

// Server is the localhost HTTP server. It implements http.Handler; Start
// binds the listener and serves in the background.
type Server struct {
	cfg     Config
	handler http.Handler
	srv     *http.Server
	ln      net.Listener
	port    string

	mu   sync.Mutex
	dbs  map[string]*store.DB
	runs map[string]*RunState
}

// RunState is the in-progress state of one case. Upload registers a RunState
// with Track when a pipeline starts; the pipeline updates it through
// SetProgress and Finish. While a case is tracked the case handler serves
// status and progress from here; afterwards it falls back to the finished
// case database.
type RunState struct {
	CaseID   string
	FileName string
	Size     int64
	Started  int64 // unix ns, UTC

	mu       sync.Mutex
	status   string // queued|running|ready|failed
	stage    string
	progress int
	finished int64 // unix ns, zero until Finish
	errMsg   string
}

// NewRunState returns the initial (queued) state for one analysis run.
func NewRunState(id, fileName string, size int64, started time.Time) *RunState {
	return &RunState{
		CaseID:   id,
		FileName: fileName,
		Size:     size,
		Started:  started.UTC().UnixNano(),
		status:   "queued",
	}
}

// SetProgress records the current pipeline stage and progress percentage and
// marks the run as running.
func (r *RunState) SetProgress(stage string, progress int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = "running"
	r.stage = stage
	r.progress = progress
}

// Finish marks the run ready (errMsg empty) or failed.
func (r *RunState) Finish(errMsg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finished = time.Now().UTC().UnixNano()
	if errMsg == "" {
		r.status = "ready"
		r.stage = "done"
		r.progress = 100
	} else {
		r.status = "failed"
		r.errMsg = errMsg
	}
}

// runSnapshot is a consistent copy of a RunState for serialization.
type runSnapshot struct {
	id       string
	fileName string
	size     int64
	started  int64
	finished int64
	status   string
	stage    string
	progress int
	errMsg   string
}

func (r *RunState) snapshot() runSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return runSnapshot{
		id:       r.CaseID,
		fileName: r.FileName,
		size:     r.Size,
		started:  r.Started,
		finished: r.finished,
		status:   r.status,
		stage:    r.stage,
		progress: r.progress,
		errMsg:   r.errMsg,
	}
}

// New builds a Server. It does not listen; call Start for that.
func New(cfg Config) (*Server, error) {
	if cfg.Token == "" {
		return nil, errors.New("server: token must not be empty")
	}
	if cfg.DataDir == "" {
		return nil, errors.New("server: data dir must not be empty")
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	s := &Server{
		cfg:  cfg,
		dbs:  make(map[string]*store.DB),
		runs: make(map[string]*RunState),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/case/{id}", s.handleCase)
	mux.HandleFunc("GET /api/case/{id}/events", s.handleEvents)
	mux.HandleFunc("GET /api/case/{id}/files", s.handleFiles)
	mux.HandleFunc("GET /api/case/{id}/streams", s.handleStreams)
	mux.HandleFunc("/api/", s.handleAPINotFound)
	mux.HandleFunc("/", s.serveStatic)
	s.handler = s.wrap(mux)
	return s, nil
}

// Token returns the session token (the CLI prints it in the dashboard URL).
func (s *Server) Token() string { return s.cfg.Token }

// ServeHTTP implements http.Handler by delegating to the wrapped router.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// Track registers an in-flight run so that /api/case/{id} reports its status
// and progress before the case database exists.
func (s *Server) Track(r *RunState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[r.CaseID] = r
}

// Start binds the loopback listener and serves in the background.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		ln.Close()
		return errors.New("server: listener is not TCP")
	}
	s.ln = ln
	s.port = strconv.Itoa(tcpAddr.Port)
	s.srv = &http.Server{Handler: s}
	go func() { _ = s.srv.Serve(ln) }()
	return nil
}

// Addr returns the bound address (valid after Start).
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Shutdown stops the HTTP server and closes every cached case database.
func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	if s.srv != nil {
		err = s.srv.Shutdown(ctx)
	}
	s.closeDBs()
	return err
}

// Close is Shutdown without waiting for in-flight requests.
func (s *Server) Close() error {
	var err error
	if s.srv != nil {
		err = s.srv.Close()
	}
	s.closeDBs()
	return err
}

func (s *Server) closeDBs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, db := range s.dbs {
		db.Close()
		delete(s.dbs, id)
	}
}

// wrap applies the security headers, the host/origin check and (for /api
// paths) the token check around the router.
func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")

		if !s.hostOK(r) {
			writeErr(w, http.StatusForbidden, codeForbidden,
				"the Host header must be 127.0.0.1 or localhost with this server's port")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !s.tokenOK(r) {
			writeErr(w, http.StatusUnauthorized, codeUnauthorized,
				"missing or incorrect session token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostOK rejects requests whose Host is not this server's loopback address
// and whose Origin (when present) does not match it. This blocks DNS-rebinding
// and cross-site requests; no CORS headers are ever emitted.
func (s *Server) hostOK(r *http.Request) bool {
	host := r.Host
	switch host {
	case "127.0.0.1:" + s.port, "localhost:" + s.port:
	default:
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+host {
		return false
	}
	return true
}

// tokenOK accepts the session token from the X-Raccoon-Token header or, for
// the initial page load, the ?t= query parameter.
func (s *Server) tokenOK(r *http.Request) bool {
	got := r.Header.Get("X-Raccoon-Token")
	if got == "" {
		got = r.URL.Query().Get("t")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) == 1
}

// serveStatic serves the embedded web UI with a single-page-application
// fallback: extensionless paths return index.html so client-side routes deep
// link correctly.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Dist == nil {
		http.NotFound(w, r)
		return
	}
	clean := path.Clean("/" + r.URL.Path)
	name := strings.TrimPrefix(clean, "/")
	if name != "" {
		if f, err := s.cfg.Dist.Open(name); err == nil {
			if st, err := f.Stat(); err == nil && !st.IsDir() {
				f.Close()
				http.ServeFileFS(w, r, s.cfg.Dist, name)
				return
			}
			f.Close()
		}
	}
	if path.Ext(clean) == "" {
		http.ServeFileFS(w, r, s.cfg.Dist, "index.html")
		return
	}
	http.NotFound(w, r)
}

// handleAPINotFound answers unknown /api routes with the JSON error envelope.
func (s *Server) handleAPINotFound(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotFound, codeNotFound, "unknown API route")
}

// openCase resolves id to its case directory and opens (or reuses) its
// database. A malformed id, a missing case directory or a missing database
// all yield errUnknownCase.
func (s *Server) openCase(id string) (*casedir.Case, *store.DB, error) {
	if !casedir.ValidID(id) {
		return nil, nil, errUnknownCase
	}
	c, err := casedir.Open(filepath.Join(s.cfg.DataDir, id))
	if err != nil {
		return nil, nil, errUnknownCase
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if db, ok := s.dbs[id]; ok {
		return c, db, nil
	}
	if _, err := os.Stat(c.DB()); err != nil {
		return nil, nil, errUnknownCase
	}
	db, err := store.Open(c.DB())
	if err != nil {
		return nil, nil, err
	}
	s.dbs[id] = db
	return c, db, nil
}

// runFor returns the tracked run for id, if any.
func (s *Server) runFor(id string) (runSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok {
		return runSnapshot{}, false
	}
	return r.snapshot(), true
}

// errUnknownCase marks every condition that must answer 404.
var errUnknownCase = errors.New("server: unknown case")

// ---------------------------------------------------------------------------
// JSON envelopes
// ---------------------------------------------------------------------------

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

// Error codes from docs/api.md.
const (
	codeInvalidQuery = "invalid_query"
	codeUnauthorized = "unauthorized"
	codeForbidden    = "forbidden"
	codeNotFound     = "not_found"
	codeInternal     = "internal"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorEnvelope{Error: apiError{Code: code, Message: msg}})
}
