package server

import (
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tokio-drift/raccoon/internal/capture"
	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/pipeline"
)

type uploadResponse struct {
	CaseID string `json:"caseId"`
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, limits.UploadMaxBytes+4<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery,
			"expected multipart/form-data with a file part")
		return
	}

	var part *multipart.Part
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if isTooLarge(err) {
				writeErr(w, http.StatusBadRequest, codePayloadTooLarge,
					"the capture exceeds the 500 MB limit")
				return
			}
			writeErr(w, http.StatusBadRequest, codeInvalidQuery, "cannot read upload")
			return
		}
		if p.FormName() == "file" {
			part = p
			break
		}
		_ = p.Close()
	}
	if part == nil {
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, "missing file part")
		return
	}
	defer part.Close()

	name := uploadFileName(part.FileName())
	c, err := casedir.Create(s.cfg.DataDir, casedir.Options{PCAP: name})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot create case directory")
		return
	}
	cleanup := func() { _ = casedir.Remove(s.cfg.DataDir, c.ID) }

	f, err := os.OpenFile(c.InputPCAPPath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanup()
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot save upload")
		return
	}
	n, copyErr := io.Copy(f, io.LimitReader(part, limits.UploadMaxBytes+1))
	closeErr := f.Close()
	if copyErr != nil {
		cleanup()
		if isTooLarge(copyErr) {
			writeErr(w, http.StatusBadRequest, codePayloadTooLarge,
				"the capture exceeds the 500 MB limit")
			return
		}
		writeErr(w, http.StatusBadRequest, codeInvalidQuery, "cannot read upload")
		return
	}
	if closeErr != nil {
		cleanup()
		writeErr(w, http.StatusInternalServerError, codeInternal, "cannot save upload")
		return
	}
	if n > limits.UploadMaxBytes {
		cleanup()
		writeErr(w, http.StatusBadRequest, codePayloadTooLarge,
			"the capture exceeds the 500 MB limit")
		return
	}
	if n == 0 {
		cleanup()
		writeErr(w, http.StatusBadRequest, codeInvalidCapture,
			"the file does not look like a PCAP or PCAPNG capture")
		return
	}
	if _, err := capture.Validate(c.InputPCAPPath()); err != nil {
		cleanup()
		writeErr(w, http.StatusBadRequest, codeInvalidCapture, uploadErrorMessage(err))
		return
	}

	run := NewRunState(c.ID, name, n, time.Now())
	s.Track(run)
	go s.runAnalysis(run, c)
	writeJSON(w, http.StatusOK, uploadResponse{CaseID: c.ID})
}

func (s *Server) runAnalysis(run *RunState, c *casedir.Case) {
	defer func() {
		if recover() != nil {
			run.Finish("analysis failed: internal error")
		}
	}()
	res, err := pipeline.Run(context.Background(), pipeline.Options{
		PCAPPath: c.InputPCAPPath(),
		Case:     c,
		OnProgress: func(p pipeline.ProgressSnapshot) {
			run.SetProgressFull(p.Stage, progressPercent(p.Stage),
				p.PacketsRead, p.BytesRead, p.Streams, p.Files)
		},
	})
	if err != nil {
		run.Finish(err.Error())
		return
	}
	run.SetTimelineReady(res.Events, res.Files)
	run.Finish("")
}

func progressPercent(stage string) int {
	switch stage {
	case "read":
		return 15
	case "process":
		return 80
	case "done":
		return 100
	default:
		return 0
	}
}

func uploadErrorMessage(err error) string {
	switch {
	case errors.Is(err, capture.ErrNotCapture):
		return "the file does not look like a PCAP or PCAPNG capture"
	case errors.Is(err, capture.ErrCorrupt):
		return "the capture file is corrupt or truncated"
	default:
		return "the capture file could not be read as PCAP or PCAPNG"
	}
}

func uploadFileName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' || r == '"' {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	name = strings.TrimSpace(b.String())
	if name == "" || name == "." || name == ".." {
		return casedir.InputPCAP
	}
	if len(name) > 255 {
		name = name[:255]
	}
	return name
}

func isTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr)
}
