package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

// ---------------------------------------------------------------------------
// 10.3: stream bytes
// ---------------------------------------------------------------------------

func TestStreamBytesWindow(t *testing.T) {
	f := startFixture(t, nil)
	c, err := casedir.Open(filepath.Join(f.dataDir, testID))
	if err != nil {
		t.Fatalf("casedir.Open: %v", err)
	}
	data := make([]byte, 134)
	for i := range data {
		data[i] = byte(i)
	}
	if err := os.WriteFile(c.StreamPath(1, model.C2S), data, 0o600); err != nil {
		t.Fatalf("write spool: %v", err)
	}
	db, err := store.Open(c.DB())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := db.InsertSegments([]store.Segment{
		{StreamID: 1, Dir: model.C2S, Offset: 0, Length: 32, TS: ts(500), PacketNo: 5},
		{StreamID: 1, Dir: model.C2S, Offset: 20, Length: 30, TS: ts(600), PacketNo: 6},
		{StreamID: 1, Dir: model.C2S, Offset: 100, Length: 10, TS: ts(700), PacketNo: 7},
	}); err != nil {
		t.Fatalf("InsertSegments: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	resp, body := f.get(t, "/api/case/"+testID+"/streams/1/bytes?dir=c2s&offset=10&len=20", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	got := decodeInto[streamBytesResponse](t, body)
	if got.StreamID != 1 || got.Dir != "c2s" || got.Offset != 10 || got.Length != 20 || got.Total != 134 {
		t.Fatalf("window: %+v", got)
	}
	raw, err := base64.StdEncoding.DecodeString(got.DataBase64)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if !bytes.Equal(raw, data[10:30]) {
		t.Fatalf("data mismatch: %x", raw)
	}
	if len(got.Segments) != 2 || got.Segments[0].Off != 0 || got.Segments[1].Off != 20 {
		t.Fatalf("segments: %+v", got.Segments)
	}
	if got.Segments[0].TS != "2026-01-01T12:00:00.5Z" || got.Segments[0].PacketNo != 5 {
		t.Fatalf("segment serialization: %+v", got.Segments[0])
	}
	if len(got.Carved) != 1 || got.Carved[0].FileID != 1 || got.Carved[0].Start != 0 || got.Carved[0].End != 4321 {
		t.Fatalf("carved: %+v", got.Carved)
	}

	// The length is clamped to the stream total, not the request.
	resp, body = f.get(t, "/api/case/"+testID+"/streams/1/bytes?dir=c2s&len=999999", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clamped: status %d: %s", resp.StatusCode, body)
	}
	got = decodeInto[streamBytesResponse](t, body)
	if got.Length != 134 || len(got.Segments) != 3 {
		t.Fatalf("clamped response: %+v", got)
	}

	// Reading past the end returns an empty window.
	resp, body = f.get(t, "/api/case/"+testID+"/streams/1/bytes?dir=c2s&offset=999", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("past end: status %d: %s", resp.StatusCode, body)
	}
	got = decodeInto[streamBytesResponse](t, body)
	if got.Offset != 999 || got.Length != 0 || got.DataBase64 != "" || len(got.Segments) != 0 {
		t.Fatalf("past end response: %+v", got)
	}
}

func TestStreamBytesValidation(t *testing.T) {
	f := startFixture(t, nil)
	for _, tc := range []struct {
		path string
		want int
		code string
	}{
		{"/api/case/" + testID + "/streams/1/bytes", http.StatusBadRequest, codeInvalidQuery},
		{"/api/case/" + testID + "/streams/1/bytes?dir=up", http.StatusBadRequest, codeInvalidQuery},
		{"/api/case/" + testID + "/streams/1/bytes?dir=c2s&offset=-1", http.StatusBadRequest, codeInvalidQuery},
		{"/api/case/" + testID + "/streams/1/bytes?dir=c2s&len=-1", http.StatusBadRequest, codeInvalidQuery},
		{"/api/case/" + testID + "/streams/999/bytes?dir=c2s", http.StatusNotFound, codeNotFound},
		{"/api/case/" + testID + "/streams/abc/bytes?dir=c2s", http.StatusNotFound, codeNotFound},
		{"/api/case/20260101-120000-aaaaaa/streams/1/bytes?dir=c2s", http.StatusNotFound, codeNotFound},
	} {
		code, _ := f.getErr(t, tc.path, tc.want)
		if code != tc.code {
			t.Errorf("%s: code %q, want %q", tc.path, code, tc.code)
		}
	}
}

// ---------------------------------------------------------------------------
// 10.4: carved file download
// ---------------------------------------------------------------------------

func TestFileDownload(t *testing.T) {
	f := startFixture(t, nil)
	c, err := casedir.Open(filepath.Join(f.dataDir, testID))
	if err != nil {
		t.Fatalf("casedir.Open: %v", err)
	}
	want := []byte("\x89PNG\r\n\x1a\ncarved-bytes")
	if err := os.WriteFile(c.CarvedPath("sha-high", "png"), want, 0o600); err != nil {
		t.Fatalf("write carved file: %v", err)
	}

	resp, body := f.get(t, "/api/case/"+testID+"/files/1/download", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if !bytes.Equal(body, want) {
		t.Fatalf("body %q, want %q", body, want)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != `attachment; filename="secret.png"` {
		t.Fatalf("Content-Disposition %q", cd)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("nosniff missing")
	}

	// Database-controlled names are sanitized before entering the header.
	_, db, err := f.srv.openCase(testID)
	if err != nil {
		t.Fatalf("openCase: %v", err)
	}
	if _, err := db.Conn().Exec(`UPDATE files SET display_name = ? WHERE id = 1`,
		"bad\"\r\nX-Injected: yes.png"); err != nil {
		t.Fatalf("update display name: %v", err)
	}
	resp, _ = f.get(t, "/api/case/"+testID+"/files/1/download", nil)
	cd := resp.Header.Get("Content-Disposition")
	if strings.ContainsAny(cd, "\r\n") || resp.Header.Get("X-Injected") != "" {
		t.Fatalf("unsafe Content-Disposition %q", cd)
	}
	if !strings.Contains(cd, "filename=") {
		t.Fatalf("missing filename: %q", cd)
	}
}

func TestFileDownloadCannotEscapeCase(t *testing.T) {
	f := startFixture(t, nil)
	c, err := casedir.Open(filepath.Join(f.dataDir, testID))
	if err != nil {
		t.Fatalf("casedir.Open: %v", err)
	}
	outside := filepath.Join(f.dataDir, "outside.bin")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	link := filepath.Join(c.CarvedDir(), "link.bin")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, db, err := f.srv.openCase(testID)
	if err != nil {
		t.Fatalf("openCase: %v", err)
	}
	for id, path := range map[int64]string{
		2: "../outside.bin",
		3: "carved/link.bin",
	} {
		if _, err := db.Conn().Exec(`UPDATE files SET path = ? WHERE id = ?`, path, id); err != nil {
			t.Fatalf("update path: %v", err)
		}
		code, _ := f.getErr(t, fmt.Sprintf("/api/case/%s/files/%d/download", testID, id), http.StatusNotFound)
		if code != codeNotFound {
			t.Errorf("file %d: code %q, want %q", id, code, codeNotFound)
		}
	}
	for _, path := range []string{
		"/api/case/" + testID + "/files/abc/download",
		"/api/case/" + testID + "/files/999/download",
		"/api/case/20260101-120000-aaaaaa/files/1/download",
	} {
		code, _ := f.getErr(t, path, http.StatusNotFound)
		if code != codeNotFound {
			t.Errorf("%s: code %q", path, code)
		}
	}
}

// ---------------------------------------------------------------------------
// 10.5: SSE
// ---------------------------------------------------------------------------

type sseFrame struct {
	name string
	data []byte
}

func readSSEFrame(t *testing.T, br *bufio.Reader) sseFrame {
	t.Helper()
	var frame sseFrame
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE: %v", err)
		}
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			if frame.name != "" {
				return frame
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "event: "):
			frame.name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			frame.data = append(frame.data, strings.TrimPrefix(line, "data: ")...)
		}
	}
}

func openSSE(t *testing.T, f *fixture, path string) (context.CancelFunc, *http.Response, *bufio.Reader) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+path, nil)
	if err != nil {
		cancel()
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Raccoon-Token", testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	return cancel, resp, bufio.NewReader(resp.Body)
}

func TestEventsStreamLiveAndReconnect(t *testing.T) {
	f := startFixture(t, nil)
	run := NewRunState(testID, "upload.pcap", 1234, fixtureCreated)
	f.srv.Track(run)
	run.SetProgressFull("read", 15, 12, 34, 1, 0)

	cancel, resp, br := openSSE(t, f, "/api/case/"+testID+"/events/stream")
	defer cancel()
	defer resp.Body.Close()

	frame := readSSEFrame(t, br)
	if frame.name != "progress" {
		t.Fatalf("first event %q", frame.name)
	}
	var progress progressEvent
	if err := json.Unmarshal(frame.data, &progress); err != nil {
		t.Fatalf("progress json: %v", err)
	}
	if progress.Stage != "read" || progress.Percent != 15 || progress.Packets != 12 ||
		progress.Bytes != 34 || progress.Streams != 1 {
		t.Fatalf("progress: %+v", progress)
	}

	run.SetTimelineReady(7, 3)
	if frame = readSSEFrame(t, br); frame.name != "ready" {
		t.Fatalf("ready event %q", frame.name)
	}
	var ready readyEvent
	json.Unmarshal(frame.data, &ready)
	if ready.Events != 7 || ready.Files != 3 {
		t.Fatalf("ready: %+v", ready)
	}

	run.PublishVerdict(1, "sha-high", "malicious")
	if frame = readSSEFrame(t, br); frame.name != "verdict" {
		t.Fatalf("verdict event %q", frame.name)
	}
	var verdict runVerdict
	json.Unmarshal(frame.data, &verdict)
	if verdict.FileID != 1 || verdict.SHA256 != "sha-high" || verdict.Status != "malicious" {
		t.Fatalf("verdict: %+v", verdict)
	}

	run.Finish("")
	if frame = readSSEFrame(t, br); frame.name != "done" {
		t.Fatalf("done event %q", frame.name)
	}
	var done doneEvent
	json.Unmarshal(frame.data, &done)
	if done.CaseID != testID {
		t.Fatalf("done: %+v", done)
	}

	// A reconnect first receives the complete current state.
	cancel2, resp2, br2 := openSSE(t, f, "/api/case/"+testID+"/events/stream")
	defer cancel2()
	defer resp2.Body.Close()
	var names []string
	for i := 0; i < 4; i++ {
		names = append(names, readSSEFrame(t, br2).name)
	}
	if strings.Join(names, ",") != "progress,verdict,ready,done" {
		t.Fatalf("replay order %v", names)
	}
}

func TestEventsStreamErrorAndFinishedCase(t *testing.T) {
	f := startFixture(t, nil)
	run := NewRunState("20260102-120000-bbbbbb", "bad.pcap", 1, fixtureCreated)
	f.srv.Track(run)
	run.SetProgress("read", 15)
	run.Finish("the capture file is corrupt")

	cancel, resp, br := openSSE(t, f, "/api/case/20260102-120000-bbbbbb/events/stream")
	defer cancel()
	defer resp.Body.Close()
	if frame := readSSEFrame(t, br); frame.name != "progress" {
		t.Fatalf("first event %q", frame.name)
	}
	frame := readSSEFrame(t, br)
	if frame.name != "error" {
		t.Fatalf("second event %q", frame.name)
	}
	var apiErr errorEvent
	json.Unmarshal(frame.data, &apiErr)
	if apiErr.Code != codeInternal || apiErr.Message != "the capture file is corrupt" {
		t.Fatalf("error: %+v", apiErr)
	}

	// A finished case without a tracked run replays from the database.
	cancel2, resp2, br2 := openSSE(t, f, "/api/case/"+testID+"/events/stream")
	defer cancel2()
	defer resp2.Body.Close()
	var names []string
	for i := 0; i < 3; i++ {
		names = append(names, readSSEFrame(t, br2).name)
	}
	if strings.Join(names, ",") != "progress,ready,done" {
		t.Fatalf("finished replay %v", names)
	}
}

// ---------------------------------------------------------------------------
// 10.6: upload
// ---------------------------------------------------------------------------

func postUpload(t *testing.T, f *fixture, fileName string, data []byte, field string) (*http.Response, []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile(field, fileName)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, f.base+"/api/upload", &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Raccoon-Token", testToken)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return resp, body
}

func TestUploadRunsAnalysis(t *testing.T) {
	f := startFixture(t, nil)
	pcap := testutil.Pcap(t, "tcp_basic.pcap")
	data, err := os.ReadFile(pcap)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	resp, body := postUpload(t, f, "tcp_basic.pcap", data, "file")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status %d: %s", resp.StatusCode, body)
	}
	up := decodeInto[uploadResponse](t, body)
	if !casedir.ValidID(up.CaseID) {
		t.Fatalf("case id %q", up.CaseID)
	}

	deadline := time.Now().Add(15 * time.Second)
	var c caseResponse
	for {
		resp, body = f.get(t, "/api/case/"+up.CaseID, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("case status %d: %s", resp.StatusCode, body)
		}
		c = decodeInto[caseResponse](t, body)
		if c.Status == "ready" || c.Status == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("analysis did not finish: %+v", c)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if c.Status != "ready" || c.Progress != 100 || c.Stage != "done" {
		t.Fatalf("finished case: %+v", c)
	}
	if c.FileName != "tcp_basic.pcap" {
		t.Fatalf("fileName %q", c.FileName)
	}
	if c.Packets == 0 || c.Streams == 0 {
		t.Fatalf("counts: %+v", c)
	}
	caseDir, err := casedir.Open(filepath.Join(f.dataDir, up.CaseID))
	if err != nil {
		t.Fatalf("casedir.Open: %v", err)
	}
	st, err := os.Stat(caseDir.InputPCAPPath())
	if err != nil {
		t.Fatalf("input.pcap: %v", err)
	}
	if st.Size() != int64(len(data)) {
		t.Fatalf("input size %d, want %d", st.Size(), len(data))
	}
}

func TestUploadRejectsInvalidCaptures(t *testing.T) {
	f := startFixture(t, nil)
	bad, err := os.ReadFile(testutil.Pcap(t, "corrupt_header.pcap"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	before, _ := os.ReadDir(f.dataDir)

	resp, body := postUpload(t, f, "bad.pcap", bad, "file")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("error json: %v", err)
	}
	if env.Error.Code != codeInvalidCapture || env.Error.Message == "" {
		t.Fatalf("error: %+v", env.Error)
	}

	resp, body = postUpload(t, f, "bad.pcap", bad, "other")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing file status %d: %s", resp.StatusCode, body)
	}
	json.Unmarshal(body, &env)
	if env.Error.Code != codeInvalidQuery {
		t.Fatalf("missing file error: %+v", env.Error)
	}

	after, _ := os.ReadDir(f.dataDir)
	if len(after) != len(before) {
		t.Fatalf("case directories left behind: before=%d after=%d", len(before), len(after))
	}
}
