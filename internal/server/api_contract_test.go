package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/testutil"
)

// ---------------------------------------------------------------------------
// 10.10: API contract tests driven through httptest.
// ---------------------------------------------------------------------------

// apiHarness serves the API on an httptest server.
type apiHarness struct {
	srv     *Server
	ts      *httptest.Server
	base    string
	dataDir string
}

// newAPIHarness starts the API on an httptest server with one seeded case.
func newAPIHarness(t *testing.T, dist fs.FS) *apiHarness {
	t.Helper()
	dataDir := t.TempDir()
	seedCase(t, dataDir)
	srv, err := New(Config{Token: testToken, DataDir: dataDir, Dist: dist})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewUnstartedServer(srv)
	// The Host check compares against the listening port, so it has to be
	// known before the first request.
	srv.port = strconv.Itoa(ts.Listener.Addr().(*net.TCPAddr).Port)
	ts.Start()
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})
	return &apiHarness{srv: srv, ts: ts, base: ts.URL, dataDir: dataDir}
}

// do performs a request against the harness.
func (h *apiHarness) do(t *testing.T, method, path string, body io.Reader, mutate func(*http.Request)) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, h.base+path, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Raccoon-Token", testToken)
	if mutate != nil {
		mutate(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	return resp, data
}

// get performs a GET with the valid token.
func (h *apiHarness) get(t *testing.T, path string) (*http.Response, []byte) {
	t.Helper()
	return h.do(t, http.MethodGet, path, nil, nil)
}

// errorCode decodes the error envelope of a response body.
func errorCode(t *testing.T, body []byte) (string, string) {
	t.Helper()
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("bad error envelope %v: %s", err, body)
	}
	return env.Error.Code, env.Error.Message
}

// TestAPIContractTokenIsRequired covers 10.10: a missing or wrong token is
// answered with 401 and the JSON error envelope.
func TestAPIContractTokenIsRequired(t *testing.T) {
	h := newAPIHarness(t, nil)
	caseURL := "/api/case/" + testID

	t.Run("missing", func(t *testing.T) {
		resp, body := h.do(t, http.MethodGet, caseURL, nil, func(r *http.Request) {
			r.Header.Del("X-Raccoon-Token")
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401 (body %s)", resp.StatusCode, body)
		}
		code, msg := errorCode(t, body)
		if code != codeUnauthorized {
			t.Fatalf("code %q, want %q", code, codeUnauthorized)
		}
		if msg == "" {
			t.Fatal("the error message is empty")
		}
	})

	t.Run("incorrect", func(t *testing.T) {
		resp, body := h.do(t, http.MethodGet, caseURL, nil, func(r *http.Request) {
			r.Header.Set("X-Raccoon-Token", "not-the-token")
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401 (body %s)", resp.StatusCode, body)
		}
		if code, _ := errorCode(t, body); code != codeUnauthorized {
			t.Fatalf("code %q, want %q", code, codeUnauthorized)
		}
	})

	t.Run("upload without token", func(t *testing.T) {
		resp, body := h.do(t, http.MethodPost, "/api/upload", nil, func(r *http.Request) {
			r.Header.Del("X-Raccoon-Token")
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401 (body %s)", resp.StatusCode, body)
		}
	})
}

// TestAPIContractBadHost covers 10.10: a request with a foreign Host header
// is answered with 403.
func TestAPIContractBadHost(t *testing.T) {
	h := newAPIHarness(t, nil)
	for _, host := range []string{"evil.example", "127.0.0.1:1", "localhost:1", "10.0.0.5:8080"} {
		resp, body := h.do(t, http.MethodGet, "/api/case/"+testID, nil, func(r *http.Request) {
			r.Host = host
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("host %q: status %d, want 403 (body %s)", host, resp.StatusCode, body)
		}
		if code, _ := errorCode(t, body); code != codeForbidden {
			t.Fatalf("host %q: code %q, want %q", host, code, codeForbidden)
		}
	}
}

// TestAPIContractRouteHappyPaths covers 10.10: every API route answers 200
// on the fixture case.
func TestAPIContractRouteHappyPaths(t *testing.T) {
	h := newAPIHarness(t, fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>RACCOON</title>")},
	})
	// The carved file and the stream spool have to exist on disk.
	c, err := casedir.Open(filepath.Join(h.dataDir, testID))
	if err != nil {
		t.Fatalf("casedir.Open: %v", err)
	}
	if err := os.WriteFile(c.CarvedPath("sha-high", "png"), []byte("\x89PNG\r\n\x1a\ncarved"), 0o600); err != nil {
		t.Fatalf("write carved file: %v", err)
	}
	spool := make([]byte, 134)
	for i := range spool {
		spool[i] = byte(i)
	}
	if err := os.WriteFile(c.StreamPath(1, model.C2S), spool, 0o600); err != nil {
		t.Fatalf("write spool: %v", err)
	}

	for _, tc := range []struct {
		name   string
		method string
		path   string
		check  func(t *testing.T, body []byte)
	}{
		{
			name: "case", method: http.MethodGet, path: "/api/case/" + testID,
			check: func(t *testing.T, body []byte) {
				c := decodeInto[caseResponse](t, body)
				if c.ID != testID || c.Status != "ready" {
					t.Fatalf("case: %+v", c)
				}
			},
		},
		{
			name: "events", method: http.MethodGet, path: "/api/case/" + testID + "/events",
			check: func(t *testing.T, body []byte) {
				page := decodeInto[eventsPage](t, body)
				if len(page.Items) != 5 {
					t.Fatalf("events: %d items", len(page.Items))
				}
			},
		},
		{
			name: "files", method: http.MethodGet, path: "/api/case/" + testID + "/files",
			check: func(t *testing.T, body []byte) {
				page := decodeInto[filesPage](t, body)
				if len(page.Items) != 2 {
					t.Fatalf("files: %d items", len(page.Items))
				}
			},
		},
		{
			name: "streams", method: http.MethodGet, path: "/api/case/" + testID + "/streams",
			check: func(t *testing.T, body []byte) {
				page := decodeInto[streamsPage](t, body)
				if len(page.Items) != 3 {
					t.Fatalf("streams: %d items", len(page.Items))
				}
			},
		},
		{
			name: "stream bytes", method: http.MethodGet, path: "/api/case/" + testID + "/streams/1/bytes?dir=c2s",
			check: func(t *testing.T, body []byte) {
				w := decodeInto[streamBytesResponse](t, body)
				if w.Total != 134 || w.Length != 134 {
					t.Fatalf("stream bytes: %+v", w)
				}
			},
		},
		{
			name: "file download", method: http.MethodGet, path: "/api/case/" + testID + "/files/1/download",
			check: func(t *testing.T, body []byte) {
				if !bytes.Contains(body, []byte("carved")) {
					t.Fatalf("download body %q", body)
				}
			},
		},
		{
			name: "ui shell", method: http.MethodGet, path: "/",
			check: func(t *testing.T, body []byte) {
				if !strings.Contains(string(body), "RACCOON") {
					t.Fatalf("index body %q", body)
				}
			},
		},
		{
			name: "report default", method: http.MethodGet, path: "/api/case/" + testID + "/report",
			check: func(t *testing.T, body []byte) {
				if !bytes.Contains(body, []byte("RACCOON case report")) {
					t.Fatalf("default report body unexpected:\n%s", body)
				}
			},
		},
		{
			name: "report html", method: http.MethodGet, path: "/api/case/" + testID + "/report?format=html",
			check: func(t *testing.T, body []byte) {
				if !bytes.Contains(body, []byte("RACCOON case report")) {
					t.Fatalf("html report body unexpected:\n%s", body)
				}
			},
		},
		{
			name: "report json", method: http.MethodGet, path: "/api/case/" + testID + "/report?format=json",
			check: func(t *testing.T, body []byte) {
				if !bytes.Contains(body, []byte(`"schemaVersion": 1`)) {
					t.Fatalf("json report body unexpected:\n%s", body)
				}
			},
		},
		{
			name: "report pdf", method: http.MethodGet, path: "/api/case/" + testID + "/report?format=pdf",
			check: func(t *testing.T, body []byte) {
				if !strings.HasPrefix(string(body), "%PDF-") || len(body) <= 2048 {
					t.Fatalf("pdf report body unexpected (len=%d)", len(body))
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := h.do(t, tc.method, tc.path, nil, nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s %s: status %d: %s", tc.method, tc.path, resp.StatusCode, body)
			}
			tc.check(t, body)
		})
	}

	t.Run("upload", func(t *testing.T) {
		pcap, err := os.ReadFile(testutil.Pcap(t, "tcp_basic.pcap"))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		resp, body := h.upload(t, "tcp_basic.pcap", pcap, "file")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, body)
		}
		up := decodeInto[uploadResponse](t, body)
		if !casedir.ValidID(up.CaseID) {
			t.Fatalf("case id %q", up.CaseID)
		}
	})
}

// TestAPIContractEventStream covers 10.10: the SSE route replays the state of
// a finished case.
func TestAPIContractEventStream(t *testing.T) {
	h := newAPIHarness(t, nil)
	req, err := http.NewRequest(http.MethodGet, h.base+"/api/case/"+testID+"/events/stream", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Raccoon-Token", testToken)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type %q", ct)
	}
	br := bufio.NewReader(resp.Body)
	var names []string
	for i := 0; i < 3; i++ {
		names = append(names, readSSEFrame(t, br).name)
	}
	if strings.Join(names, ",") != "progress,ready,done" {
		t.Fatalf("replay %v", names)
	}
}

// TestAPIContractUploadCorruptCapture covers 10.10: a capture with a broken
// header is rejected with 400 and a readable message.
func TestAPIContractUploadCorruptCapture(t *testing.T) {
	h := newAPIHarness(t, nil)
	bad, err := os.ReadFile(testutil.Pcap(t, "corrupt_header.pcap"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	resp, body := h.upload(t, "corrupt_header.pcap", bad, "file")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (body %s)", resp.StatusCode, body)
	}
	code, msg := errorCode(t, body)
	if code != codeInvalidCapture {
		t.Fatalf("code %q, want %q", code, codeInvalidCapture)
	}
	if msg == "" {
		t.Fatal("the error message is empty")
	}
	if len(msg) < 8 {
		t.Fatalf("the error message %q is not readable", msg)
	}
}

// TestAPIContractDownloadPathTraversal covers 10.10: crafted file ids and
// database paths cannot escape the case directory.
func TestAPIContractDownloadPathTraversal(t *testing.T) {
	h := newAPIHarness(t, nil)
	c, err := casedir.Open(filepath.Join(h.dataDir, testID))
	if err != nil {
		t.Fatalf("casedir.Open: %v", err)
	}
	outside := filepath.Join(h.dataDir, "outside.bin")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}

	// Crafted ids are rejected before the database is consulted.
	for _, id := range []string{
		"..%2F..%2Fetc%2Fpasswd",
		"..",
		"1%00",
		"abc",
		"999",
	} {
		path := fmt.Sprintf("/api/case/%s/files/%s/download", testID, id)
		resp, body := h.get(t, path)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status %d, want 404 (body %s)", path, resp.StatusCode, body)
		}
		if code, _ := errorCode(t, body); code != codeNotFound {
			t.Fatalf("%s: code %q, want %q", path, code, codeNotFound)
		}
	}

	// A database path pointing outside the case directory is refused.
	_, db, err := h.srv.openCase(testID)
	if err != nil {
		t.Fatalf("openCase: %v", err)
	}
	for id, path := range map[int64]string{
		1: "../outside.bin",
		2: "carved/../../outside.bin",
		3: filepath.Join(c.CarvedDir(), "..", "..", "outside.bin"),
	} {
		if _, err := db.Conn().Exec(`UPDATE files SET path = ? WHERE id = ?`, path, id); err != nil {
			t.Fatalf("update path: %v", err)
		}
	}
	for id := int64(1); id <= 3; id++ {
		path := fmt.Sprintf("/api/case/%s/files/%d/download", testID, id)
		resp, body := h.get(t, path)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status %d, want 404 (body %s)", path, resp.StatusCode, body)
		}
	}
}

// upload posts a multipart upload to /api/upload.
func (h *apiHarness) upload(t *testing.T, fileName string, data []byte, field string) (*http.Response, []byte) {
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
	req, err := http.NewRequest(http.MethodPost, h.base+"/api/upload", &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Raccoon-Token", testToken)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return resp, body
}
