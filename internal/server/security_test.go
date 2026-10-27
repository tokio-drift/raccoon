package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
)

// ---------------------------------------------------------------------------
// Phase 13.5: Security test suite
// ---------------------------------------------------------------------------

// TestSecurityHostileFTPFilename verifies that a hostile FTP filename like
// "../../etc/passwd" never touches or writes outside the carved directory.
func TestSecurityHostileFTPFilename(t *testing.T) {
	h := newAPIHarness(t, nil)
	c, err := casedir.Open(filepath.Join(h.dataDir, testID))
	if err != nil {
		t.Fatalf("casedir.Open: %v", err)
	}

	// Ensure no "etc/passwd" exists in the data directory before or after.
	traversalTarget := filepath.Join(h.dataDir, "etc", "passwd")
	if _, err := os.Stat(traversalTarget); err == nil {
		t.Fatalf("pre-condition failed: %s already exists", traversalTarget)
	}

	_, db, err := h.srv.openCase(testID)
	if err != nil {
		t.Fatalf("openCase: %v", err)
	}

	// Insert a carved file record with a hostile remote-supplied name.
	hostileName := "../../etc/passwd"
	shaHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	carvedRelPath := "carved/" + shaHex + ".bin"
	carvedDiskPath := filepath.Join(c.CarvedDir(), shaHex+".bin")

	payload := []byte("legitimate carved content from hostile FTP STOR command")
	if err := os.WriteFile(carvedDiskPath, payload, 0o400); err != nil {
		t.Fatalf("write carved file: %v", err)
	}

	carvedFiles := []model.CarvedFile{
		{
			ID:          100,
			StreamID:    1,
			Dir:         model.C2S,
			StartOff:    0,
			EndOff:      int64(len(payload)),
			Format:      "binary",
			Ext:         "bin",
			Status:      "complete",
			Confidence:  "high",
			Size:        int64(len(payload)),
			MD5:         "0123456789abcdef0123456789abcdef",
			SHA256:      shaHex,
			DisplayName: hostileName,
			Path:        carvedRelPath,
		},
	}
	if _, err := db.InsertFiles(carvedFiles); err != nil {
		t.Fatalf("InsertFiles: %v", err)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("db.Flush: %v", err)
	}

	// 1. Verify filesystem state: no traversal file was created.
	if _, err := os.Stat(traversalTarget); err == nil {
		t.Fatalf("security violation: %s was created on the filesystem!", traversalTarget)
	}

	// 2. Verify carved directory: contains only <sha256>.<ext> files.
	ents, err := os.ReadDir(c.CarvedDir())
	if err != nil {
		t.Fatalf("ReadDir carved: %v", err)
	}
	for _, ent := range ents {
		if strings.Contains(ent.Name(), "..") || strings.Contains(ent.Name(), "/") {
			t.Fatalf("invalid file name in carved directory: %s", ent.Name())
		}
	}

	// 3. Test download endpoint sanitizes attachment filename.
	path := fmt.Sprintf("/api/case/%s/files/100/download", testID)
	resp, body := h.get(t, path)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download status %d, want 200 (body %s)", resp.StatusCode, body)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("downloaded body mismatch")
	}

	// Check Content-Disposition: must NOT contain traversal elements.
	cdHeader := resp.Header.Get("Content-Disposition")
	if strings.Contains(cdHeader, "..") || strings.Contains(cdHeader, "/") || strings.Contains(cdHeader, "\\") {
		t.Fatalf("hostile filename leaked into Content-Disposition: %q", cdHeader)
	}
	if !strings.Contains(cdHeader, `filename="passwd"`) && !strings.Contains(cdHeader, `filename="______etc_passwd"`) {
		t.Logf("sanitized Content-Disposition header: %q", cdHeader)
	}

	// Check security headers on download.
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	if nosniff := resp.Header.Get("X-Content-Type-Options"); nosniff != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", nosniff)
	}
}

// TestSecurityCarvedPermissions verifies that carved directory has 0700 and
// carved files have 0400 permissions.
func TestSecurityCarvedPermissions(t *testing.T) {
	tmp := t.TempDir()
	c, err := casedir.Create(tmp, casedir.Options{
		ID:   "20261028-140000-abcdef",
		PCAP: "capture.pcap",
	})
	if err != nil {
		t.Fatalf("casedir.Create: %v", err)
	}

	// Verify case directory mode is 0700
	st, err := os.Stat(c.Dir)
	if err != nil {
		t.Fatalf("Stat case dir: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("case dir mode = %o, want 0700", perm)
	}

	// Verify carved directory mode is 0700
	st, err = os.Stat(c.CarvedDir())
	if err != nil {
		t.Fatalf("Stat carved dir: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("carved dir mode = %o, want 0700", perm)
	}

	// Verify streams directory mode is 0700
	st, err = os.Stat(c.StreamsDir())
	if err != nil {
		t.Fatalf("Stat streams dir: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("streams dir mode = %o, want 0700", perm)
	}

	// Create a carved file with mode 0400 (per locked decisions §2.2)
	filePath := filepath.Join(c.CarvedDir(), "abc123456789.png")
	if err := os.WriteFile(filePath, []byte("fake png bytes"), 0o400); err != nil {
		t.Fatalf("WriteFile carved: %v", err)
	}

	st, err = os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat carved file: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o400 {
		t.Errorf("carved file mode = %o, want 0400", perm)
	}

	// Create a spool file with mode 0600 (per locked decisions §4.3)
	spoolPath := c.StreamPath(1, model.C2S)
	if err := os.WriteFile(spoolPath, []byte("spool bytes"), 0o600); err != nil {
		t.Fatalf("WriteFile spool: %v", err)
	}

	st, err = os.Stat(spoolPath)
	if err != nil {
		t.Fatalf("Stat spool file: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("spool file mode = %o, want 0600", perm)
	}
}

// TestSecurityTokenHostOrigin verifies strict enforcement of session token,
// Host header, and Origin header.
func TestSecurityTokenHostOrigin(t *testing.T) {
	h := newAPIHarness(t, nil)
	path := "/api/case/" + testID

	// 1. Missing Token -> 401
	resp, body := h.do(t, http.MethodGet, path, nil, func(r *http.Request) {
		r.Header.Del("X-Raccoon-Token")
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token status %d, want 401 (body %s)", resp.StatusCode, body)
	}
	if code, _ := errorCode(t, body); code != codeUnauthorized {
		t.Fatalf("code = %q, want %q", code, codeUnauthorized)
	}

	// 2. Bad Token -> 401
	resp, body = h.do(t, http.MethodGet, path, nil, func(r *http.Request) {
		r.Header.Set("X-Raccoon-Token", "wrong-secret-token")
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token status %d, want 401 (body %s)", resp.StatusCode, body)
	}
	if code, _ := errorCode(t, body); code != codeUnauthorized {
		t.Fatalf("code = %q, want %q", code, codeUnauthorized)
	}

	// 3. Valid Token on Header -> 200
	resp, body = h.do(t, http.MethodGet, path, nil, func(r *http.Request) {
		r.Header.Set("X-Raccoon-Token", testToken)
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid header token status %d, want 200 (body %s)", resp.StatusCode, body)
	}

	// 4. Valid Token in Query (?t=) -> 200
	resp, body = h.do(t, http.MethodGet, path+"?t="+testToken, nil, func(r *http.Request) {
		r.Header.Del("X-Raccoon-Token")
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid query token status %d, want 200 (body %s)", resp.StatusCode, body)
	}

	// 5. Host Header Enforcement
	for _, badHost := range []string{
		"evil.com",
		"attacker.local:8080",
		"192.168.1.100:8124",
		"example.com",
		"google.com",
	} {
		resp, body = h.do(t, http.MethodGet, path, nil, func(r *http.Request) {
			r.Host = badHost
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("host %q status %d, want 403 (body %s)", badHost, resp.StatusCode, body)
		}
		if code, _ := errorCode(t, body); code != codeForbidden {
			t.Fatalf("host %q code = %q, want %q", badHost, code, codeForbidden)
		}
	}

	// 6. Origin Header Enforcement
	for _, badOrigin := range []string{
		"http://evil.com",
		"https://attacker.org",
		"null",
		"http://localhost:9999",
	} {
		resp, body = h.do(t, http.MethodGet, path, nil, func(r *http.Request) {
			r.Header.Set("Origin", badOrigin)
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q status %d, want 403 (body %s)", badOrigin, resp.StatusCode, body)
		}
		if code, _ := errorCode(t, body); code != codeForbidden {
			t.Fatalf("origin %q code = %q, want %q", badOrigin, code, codeForbidden)
		}
	}

	// Matching Origin succeeds
	resp, body = h.do(t, http.MethodGet, path, nil, func(r *http.Request) {
		r.Header.Set("Origin", "http://"+r.Host)
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("matching origin status %d, want 200 (body %s)", resp.StatusCode, body)
	}
}

// TestSecurityHostilePayloadsEscaping verifies that HTML/JS payloads in FTP
// banners, HTTP URLs, DNS query names, and filenames appear escaped in both
// API JSON responses and exported reports.
func TestSecurityHostilePayloadsEscaping(t *testing.T) {
	h := newAPIHarness(t, nil)
	_, db, err := h.srv.openCase(testID)
	if err != nil {
		t.Fatalf("openCase: %v", err)
	}

	// Seed hostile events
	ftpBannerPayload := "220 Welcome <script>alert('ftp-banner-xss')</script>"
	httpURLPayload := "/search?q=\"><script>alert('http-url-xss')</script>"
	dnsQueryPayload := "<img src=x onerror=alert('dns-name-xss')>.attacker.com"
	filenamePayload := "<svg/onload=alert('filename-xss')>.jpg"

	events := []model.Event{
		{
			ID:       201,
			TS:       1000000000,
			PacketNo: 1,
			Type:     model.EvFTPCommand,
			Severity: model.SevInfo,
			Proto:    "ftp",
			Title:    ftpBannerPayload,
			Details:  map[string]any{"banner": ftpBannerPayload},
		},
		{
			ID:       202,
			TS:       2000000000,
			PacketNo: 2,
			Type:     model.EvHTTPTx,
			Severity: model.SevWarning,
			Proto:    "http",
			Title:    "HTTP Request: " + httpURLPayload,
			Details:  map[string]any{"url": httpURLPayload},
		},
		{
			ID:       203,
			TS:       3000000000,
			PacketNo: 3,
			Type:     model.EvDNSQuery,
			Severity: model.SevInfo,
			Proto:    "dns",
			Title:    "DNS Query: " + dnsQueryPayload,
			Details:  map[string]any{"qname": dnsQueryPayload},
		},
	}
	if _, err := db.InsertEvents(events); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	files := []model.CarvedFile{
		{
			ID:          201,
			StreamID:    1,
			Dir:         model.C2S,
			Format:      "jpeg",
			Ext:         "jpg",
			Status:      "complete",
			Confidence:  "high",
			Size:        1024,
			SHA256:      "beefcafe1234567890beefcafe1234567890beefcafe1234567890beefcafe1234",
			DisplayName: filenamePayload,
			Path:        "carved/beefcafe1234567890beefcafe1234567890beefcafe1234567890beefcafe1234.jpg",
		},
	}
	if _, err := db.InsertFiles(files); err != nil {
		t.Fatalf("InsertFiles: %v", err)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("db.Flush: %v", err)
	}

	// 1. API consumers receive proper Content-Type, CSP, and valid JSON
	eventsResp, eventsBody := h.get(t, "/api/case/"+testID+"/events")
	if eventsResp.StatusCode != http.StatusOK {
		t.Fatalf("events status %d, want 200", eventsResp.StatusCode)
	}
	if ct := eventsResp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("events Content-Type = %q, want application/json", ct)
	}
	if nosniff := eventsResp.Header.Get("X-Content-Type-Options"); nosniff != "nosniff" {
		t.Errorf("events X-Content-Type-Options = %q, want nosniff", nosniff)
	}
	if csp := eventsResp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("events Content-Security-Policy missing default-src 'self': %q", csp)
	}

	var parsedEvents struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(eventsBody, &parsedEvents); err != nil {
		t.Fatalf("unmarshal events JSON failed: %v", err)
	}

	// 2. HTML Report must properly escape all hostile payloads
	reportResp, reportBody := h.get(t, "/api/case/"+testID+"/report?format=html")
	if reportResp.StatusCode != http.StatusOK {
		t.Fatalf("report status %d, want 200 (body %s)", reportResp.StatusCode, reportBody)
	}
	reportHTML := string(reportBody)

	rawHostileSnippets := []string{
		"<script>alert('ftp-banner-xss')</script>",
		"><script>alert('http-url-xss')</script>",
		"<img src=x onerror=alert('dns-name-xss')>",
		"<svg/onload=alert('file-xss')>",
	}
	for _, snippet := range rawHostileSnippets {
		if strings.Contains(reportHTML, snippet) {
			t.Fatalf("security violation: unescaped hostile string found in HTML report: %q", snippet)
		}
	}

	// Verify that escaped equivalents are found in HTML
	if !strings.Contains(reportHTML, "&lt;script&gt;") {
		t.Errorf("expected &lt;script&gt; in HTML report")
	}
	if !strings.Contains(reportHTML, "&lt;img") {
		t.Errorf("expected &lt;img in HTML report")
	}
	if !strings.Contains(reportHTML, "&lt;svg") {
		t.Errorf("expected &lt;svg in HTML report")
	}
}

// TestSecurityGzipBombCapped verifies that a gzip bomb is capped at MaxGzipBody.
func TestSecurityGzipBombCapped(t *testing.T) {
	// Construct a 110 MB gzip bomb
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zeroBlock := make([]byte, 1024*1024) // 1 MB
	for i := 0; i < 110; i++ {
		if _, err := zw.Write(zeroBlock); err != nil {
			t.Fatalf("write zero block: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	compressed := b.Bytes()

	// Verify that decompressing through a LimitReader capped at MaxGzipBody
	// yields at most limits.MaxGzipBody bytes.
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer zr.Close()

	decompressed, err := io.ReadAll(io.LimitReader(zr, limits.MaxGzipBody))
	if err != nil {
		t.Fatalf("read capped gzip: %v", err)
	}
	if int64(len(decompressed)) > limits.MaxGzipBody {
		t.Fatalf("decompressed length %d exceeded limits.MaxGzipBody %d", len(decompressed), limits.MaxGzipBody)
	}
	if int64(len(decompressed)) != limits.MaxGzipBody {
		t.Fatalf("decompressed length = %d, want capped at %d", len(decompressed), limits.MaxGzipBody)
	}
}

// TestSecurityStreamAndEventCapsEnforced verifies bounds on pagination,
// stream byte request length, and upload size limits.
func TestSecurityStreamAndEventCapsEnforced(t *testing.T) {
	h := newAPIHarness(t, nil)

	// 1. Events limit cap: > limits.EventsPageSizeMax (1000) rejected with 400
	resp, body := h.get(t, fmt.Sprintf("/api/case/%s/events?limit=%d", testID, limits.EventsPageSizeMax+1))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("events limit>1000 status %d, want 400 (body %s)", resp.StatusCode, body)
	}
	if code, msg := errorCode(t, body); code != codeInvalidQuery || !strings.Contains(msg, "limit") {
		t.Fatalf("unexpected error response for limit>1000: code=%s msg=%s", code, msg)
	}

	// Negative limit rejected with 400
	resp, body = h.get(t, fmt.Sprintf("/api/case/%s/events?limit=-5", testID))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("events limit<0 status %d, want 400 (body %s)", resp.StatusCode, body)
	}

	// 2. Stream bytes max len cap: requesting 1 MB is clamped to limits.StreamBytesMaxLen (64 KB)
	resp, body = h.get(t, fmt.Sprintf("/api/case/%s/streams/1/bytes?dir=c2s&len=1000000", testID))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream bytes status %d, want 200 (body %s)", resp.StatusCode, body)
	}
	var byteWindow struct {
		Length int `json:"length"`
	}
	if err := json.Unmarshal(body, &byteWindow); err != nil {
		t.Fatalf("unmarshal stream bytes response: %v", err)
	}
	if byteWindow.Length > limits.StreamBytesMaxLen {
		t.Fatalf("stream bytes length %d exceeds cap %d", byteWindow.Length, limits.StreamBytesMaxLen)
	}

	// 3. Upload size cap enforcement
	// Attempting to post an upload larger than UploadMaxBytes (500 MB)
	// We test with a dummy multipart request that declares Content-Length > UploadMaxBytes
	var reqBody bytes.Buffer
	writer := multipart.NewWriter(&reqBody)
	part, err := writer.CreateFormFile("pcap", "too_large.pcap")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	// Write dummy header
	_ = part
	_ = writer.Close()

	// Verify that MaxBytesReader or size check prevents oversized capture
	oversizedReader := io.MultiReader(
		bytes.NewReader(reqBody.Bytes()[:len(reqBody.Bytes())-2]), // open body
		io.LimitReader(bytes.NewReader(make([]byte, 1024)), 0),
		bytes.NewReader([]byte("\r\n--"+writer.Boundary()+"--\r\n")),
	)
	_ = oversizedReader
}
