package intel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// makeVTServer builds a test server that responds with the given status code
// and (optional) JSON body.
func makeVTServer(t *testing.T, statusCode int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request carries the API key header.
		if r.Header.Get("x-apikey") == "" {
			t.Error("request missing x-apikey header")
		}
		// Verify only the hash path is sent — no file bytes.
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
}

// vtResponse builds a minimal VirusTotal /files/{sha} JSON payload.
func vtResponse(malicious, suspicious, harmless, undetected int) string {
	return `{
		"data": {
			"attributes": {
				"last_analysis_stats": {
					"malicious":  ` + itoa(malicious) + `,
					"suspicious": ` + itoa(suspicious) + `,
					"harmless":   ` + itoa(harmless) + `,
					"undetected": ` + itoa(undetected) + `
				}
			}
		}
	}`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestVTLookupMalicious checks that ≥3 malicious engines → status "malicious".
func TestVTLookupMalicious(t *testing.T) {
	srv := makeVTServer(t, http.StatusOK, vtResponse(5, 1, 10, 30))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	v, err := c.Lookup(context.Background(), testSHA256)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if v.Status != "malicious" {
		t.Errorf("status = %q, want %q", v.Status, "malicious")
	}
	if v.Score != 5 {
		t.Errorf("Score = %d, want 5", v.Score)
	}
	if v.Source != "virustotal" {
		t.Errorf("Source = %q, want \"virustotal\"", v.Source)
	}
	if v.SHA256 != testSHA256 {
		t.Errorf("SHA256 mismatch")
	}
	// Detail map must carry the raw counts.
	if v.Detail["malicious"] != 5 {
		t.Errorf("Detail[malicious] = %v, want 5", v.Detail["malicious"])
	}
}

// TestVTLookupSuspicious checks that malicious<3 but malicious+suspicious≥1 → "suspicious".
func TestVTLookupSuspicious(t *testing.T) {
	// 2 malicious + 1 suspicious → suspicious (malicious < 3)
	srv := makeVTServer(t, http.StatusOK, vtResponse(2, 1, 10, 30))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	v, err := c.Lookup(context.Background(), testSHA256)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if v.Status != "suspicious" {
		t.Errorf("status = %q, want %q", v.Status, "suspicious")
	}
}

// TestVTLookupSuspiciousOnlySuspicious checks that 0 malicious + ≥1 suspicious → "suspicious".
func TestVTLookupSuspiciousOnlySuspicious(t *testing.T) {
	srv := makeVTServer(t, http.StatusOK, vtResponse(0, 2, 10, 30))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	v, err := c.Lookup(context.Background(), testSHA256)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if v.Status != "suspicious" {
		t.Errorf("status = %q, want %q", v.Status, "suspicious")
	}
}

// TestVTLookupNoDetections checks that 0 malicious + 0 suspicious → "no_detections".
func TestVTLookupNoDetections(t *testing.T) {
	srv := makeVTServer(t, http.StatusOK, vtResponse(0, 0, 20, 50))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	v, err := c.Lookup(context.Background(), testSHA256)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if v.Status != "no_detections" {
		t.Errorf("status = %q, want %q", v.Status, "no_detections")
	}
}

// TestVTLookupExactlyMalicious3 checks the boundary: exactly 3 malicious → "malicious".
func TestVTLookupExactlyMalicious3(t *testing.T) {
	srv := makeVTServer(t, http.StatusOK, vtResponse(3, 0, 10, 30))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	v, err := c.Lookup(context.Background(), testSHA256)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if v.Status != "malicious" {
		t.Errorf("status = %q, want %q (boundary: exactly 3 malicious)", v.Status, "malicious")
	}
}

// TestVTLookupNotFound checks that HTTP 404 → status "unknown" + ErrVTNotFound.
func TestVTLookupNotFound(t *testing.T) {
	srv := makeVTServer(t, http.StatusNotFound, `{"error":{"code":"NotFoundError"}}`)
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	v, err := c.Lookup(context.Background(), testSHA256)
	if !errors.Is(err, ErrVTNotFound) {
		t.Errorf("err = %v, want ErrVTNotFound", err)
	}
	if v.Status != "unknown" {
		t.Errorf("status = %q, want \"unknown\"", v.Status)
	}
	if v.Source != "virustotal" {
		t.Errorf("Source = %q, want \"virustotal\"", v.Source)
	}
}

// TestVTLookupRateLimit checks that HTTP 429 → ErrVTRetryable.
func TestVTLookupRateLimit(t *testing.T) {
	srv := makeVTServer(t, http.StatusTooManyRequests, `{"error":{"code":"QuotaExceededError"}}`)
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	_, err := c.Lookup(context.Background(), testSHA256)
	if !errors.Is(err, ErrVTRetryable) {
		t.Errorf("err = %v, want ErrVTRetryable", err)
	}
}

// TestVTLookup5xx checks that HTTP 500 → ErrVTRetryable.
func TestVTLookup5xx(t *testing.T) {
	srv := makeVTServer(t, http.StatusInternalServerError, `{"error":"internal"}`)
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	_, err := c.Lookup(context.Background(), testSHA256)
	if !errors.Is(err, ErrVTRetryable) {
		t.Errorf("err = %v, want ErrVTRetryable", err)
	}
}

// TestVTLookupUnexpectedStatus checks that an unexpected HTTP status returns an error
// that is neither ErrVTNotFound nor ErrVTRetryable.
func TestVTLookupUnexpectedStatus(t *testing.T) {
	srv := makeVTServer(t, http.StatusForbidden, `{"error":"forbidden"}`)
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	_, err := c.Lookup(context.Background(), testSHA256)
	if err == nil {
		t.Fatal("expected error for HTTP 403, got nil")
	}
	if errors.Is(err, ErrVTRetryable) || errors.Is(err, ErrVTNotFound) {
		t.Errorf("err should not be ErrVTRetryable or ErrVTNotFound, got: %v", err)
	}
}

// TestVTLookupContextCancelled checks that a cancelled context returns an error.
func TestVTLookupContextCancelled(t *testing.T) {
	// Server that blocks long enough for the context to cancel.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	_, err := c.Lookup(ctx, testSHA256)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

// TestVTLookupCheckedAt verifies that a successful response sets CheckedAt
// close to the current time (within 5 seconds).
func TestVTLookupCheckedAt(t *testing.T) {
	srv := makeVTServer(t, http.StatusOK, vtResponse(0, 0, 10, 30))
	defer srv.Close()

	before := time.Now().UnixNano()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	v, err := c.Lookup(context.Background(), testSHA256)
	after := time.Now().UnixNano()
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if v.CheckedAt < before || v.CheckedAt > after {
		t.Errorf("CheckedAt %d out of range [%d, %d]", v.CheckedAt, before, after)
	}
}

// TestVTLookupTotalCount verifies that Total = sum of all four engine buckets.
func TestVTLookupTotalCount(t *testing.T) {
	srv := makeVTServer(t, http.StatusOK, vtResponse(3, 2, 10, 55))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "testkey"}
	v, err := c.Lookup(context.Background(), testSHA256)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if v.Total != 70 {
		t.Errorf("Total = %d, want 70 (3+2+10+55)", v.Total)
	}
}

// TestVTStatusFunction is a pure unit test of the vtStatus helper.
func TestVTStatusFunction(t *testing.T) {
	tests := []struct {
		mal, sus   int
		wantStatus string
	}{
		{3, 0, "malicious"},
		{5, 2, "malicious"},
		{2, 1, "suspicious"},
		{0, 1, "suspicious"},
		{2, 0, "suspicious"}, // 2 mal + 0 sus ≥ 1 → suspicious (mal < 3)
		{0, 0, "no_detections"},
	}
	for _, tc := range tests {
		s := vtStatus(vtAnalysisStats{Malicious: tc.mal, Suspicious: tc.sus})
		if s != tc.wantStatus {
			t.Errorf("vtStatus(mal=%d, sus=%d) = %q, want %q", tc.mal, tc.sus, s, tc.wantStatus)
		}
	}
}
