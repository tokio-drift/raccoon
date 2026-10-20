package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tokio-drift/raccoon/internal/model"
)

// vtDefaultBaseURL is the VirusTotal v3 API base URL.
const vtDefaultBaseURL = "https://www.virustotal.com/api/v3"

// Retryable sentinel — callers distinguish this from hard failures.

// ErrVTRetryable is returned for HTTP 429 or 5xx responses, indicating the
// caller should back off and retry the request.
var ErrVTRetryable = errors.New("intel: virustotal: retryable error")

// ErrVTNotFound is returned when VirusTotal responds with HTTP 404, meaning
// the file hash is not in its database.
var ErrVTNotFound = errors.New("intel: virustotal: hash not found")

// vtAnalysisStats mirrors the JSON shape of
// data.attributes.last_analysis_stats in the VT file report.
type vtAnalysisStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
	Undetected int `json:"undetected"`
}

// vtFileResponse is the minimal subset of the VT v3 /files/{sha256} response
// that we need to compute the verdict.
type vtFileResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats vtAnalysisStats `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

// Client is a thin VirusTotal v3 API client. Only the hash is ever sent to
// the remote service; carved file bytes are never uploaded.
//
// Construct via NewVTClient; the zero value is not usable.
type Client struct {
	HTTP    *http.Client
	BaseURL string
	APIKey  string
}

// NewVTClient returns a Client with sensible defaults (30 s HTTP timeout,
// production base URL).
func NewVTClient(apiKey string) *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		BaseURL: vtDefaultBaseURL,
		APIKey:  apiKey,
	}
}

// Lookup queries VirusTotal for the reputation of the given lower-case hex
// SHA-256 digest. It returns a model.Verdict whose Source is "virustotal".
//
// Status mapping:
//   - malicious ≥ 3              → "malicious"
//   - malicious+suspicious ≥ 1   → "suspicious"
//   - otherwise                  → "no_detections"
//   - HTTP 404                   → "unknown"    (ErrVTNotFound is also returned)
//   - HTTP 429 / 5xx             → ""           (ErrVTRetryable is returned)
//
// Only the hash string is sent to VirusTotal; file bytes are never uploaded.
func (c *Client) Lookup(ctx context.Context, sha256 string) (model.Verdict, error) {
	url := c.BaseURL + "/files/" + sha256

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return model.Verdict{}, fmt.Errorf("intel: virustotal: build request: %w", err)
	}
	req.Header.Set("x-apikey", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return model.Verdict{}, fmt.Errorf("intel: virustotal: http: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return model.Verdict{
			SHA256:    sha256,
			Source:    "virustotal",
			Status:    "unknown",
			CheckedAt: time.Now().UnixNano(),
		}, ErrVTNotFound

	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return model.Verdict{}, fmt.Errorf("%w: HTTP %d", ErrVTRetryable, resp.StatusCode)

	case resp.StatusCode != http.StatusOK:
		return model.Verdict{}, fmt.Errorf("intel: virustotal: unexpected HTTP %d", resp.StatusCode)
	}

	var parsed vtFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return model.Verdict{}, fmt.Errorf("intel: virustotal: decode response: %w", err)
	}

	stats := parsed.Data.Attributes.LastAnalysisStats
	status := vtStatus(stats)

	detail := map[string]any{
		"malicious":  stats.Malicious,
		"suspicious": stats.Suspicious,
		"harmless":   stats.Harmless,
		"undetected": stats.Undetected,
	}

	return model.Verdict{
		SHA256:    sha256,
		Source:    "virustotal",
		Status:    status,
		Score:     stats.Malicious,
		Total:     stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected,
		Detail:    detail,
		CheckedAt: time.Now().UnixNano(),
	}, nil
}

// vtStatus converts the raw analysis stats into a verdict status string using
// the thresholds specified in the plan:
//
//	malicious ≥ 3              → "malicious"
//	malicious+suspicious ≥ 1   → "suspicious"
//	otherwise                  → "no_detections"
func vtStatus(s vtAnalysisStats) string {
	switch {
	case s.Malicious >= 3:
		return "malicious"
	case s.Malicious+s.Suspicious >= 1:
		return "suspicious"
	default:
		return "no_detections"
	}
}
