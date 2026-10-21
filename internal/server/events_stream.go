package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// handleEventsStream serves the case event stream. It replays the current state
// before forwarding live updates so a reconnecting EventSource never misses a
// terminal transition.
func (s *Server) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, tracked := s.runStateFor(id)

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, codeInternal, "streaming is not supported")
		return
	}

	var (
		ch     <-chan sseEvent
		replay []sseEvent
		unsub  func()
	)
	if tracked {
		var live chan sseEvent
		live, replay = run.subscribe()
		ch = live
		unsub = func() { run.unsubscribe(live) }
	} else {
		var err error
		replay, err = s.finishedReplay(id)
		if errors.Is(err, errUnknownCase) {
			writeErr(w, http.StatusNotFound, codeNotFound, "unknown case")
			return
		}
		if errors.Is(err, errNotReady) {
			writeErr(w, http.StatusConflict, codeNotReady, "analysis is still running")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, codeInternal, "cannot read case state")
			return
		}
	}
	if unsub != nil {
		defer unsub()
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	for _, ev := range replay {
		if err := writeSSE(w, ev); err != nil {
			return
		}
	}
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.shutdownCh:
			// The server is shutting down: finish the stream so the
			// shutdown is not blocked by a long-lived connection.
			return
		case <-ticker.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if err := writeSSE(w, ev); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// finishedReplay builds the state replay for a case that has no tracked run.
func (s *Server) finishedReplay(id string) ([]sseEvent, error) {
	_, db, err := s.openCase(id)
	if errors.Is(err, errUnknownCase) {
		return nil, errUnknownCase
	}
	if err != nil {
		return nil, err
	}
	meta, err := db.Meta()
	if err != nil {
		return nil, err
	}
	if meta["pcap_sha256"] == "" {
		return nil, errNotReady
	}
	nEvents, nFiles, _, err := db.Counts()
	if err != nil {
		return nil, err
	}
	return []sseEvent{
		mustSSEEvent("progress", progressEvent{Stage: "done", Percent: 100}),
		mustSSEEvent("ready", readyEvent{Events: nEvents, Files: nFiles}),
		mustSSEEvent("done", doneEvent{CaseID: id}),
	}, nil
}

func writeSSE(w io.Writer, ev sseEvent) error {
	_, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.name, ev.data)
	return err
}

var errNotReady = errors.New("server: case is not ready")
