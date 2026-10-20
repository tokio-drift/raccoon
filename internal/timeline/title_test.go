package timeline

import (
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{142, "142 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{12697, "12.4 KB"},
		{5452595, "5.2 MB"},
		{1181116006, "1.1 GB"},
		{-5, "0 B"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := FormatBytes(tc.bytes); got != tc.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tc.bytes, got, tc.want)
			}
		})
	}
}

func TestFTPTitles(t *testing.T) {
	tests := []struct {
		name string
		ev   model.Event
		want string
	}{
		{
			name: "FTP login successful with user detail",
			ev: model.Event{
				Type:    model.EvFTPLoginOK,
				Details: map[string]any{"user": "bob"},
			},
			want: "FTP login successful as bob",
		},
		{
			name: "FTP login successful parsed from title",
			ev: model.Event{
				Type:  model.EvFTPLoginOK,
				Title: "FTP login successful: bob",
			},
			want: "FTP login successful as bob",
		},
		{
			name: "FTP login successful without user",
			ev: model.Event{
				Type: model.EvFTPLoginOK,
			},
			want: "FTP login successful",
		},
		{
			name: "FTP login failed",
			ev: model.Event{
				Type:    model.EvFTPLoginFail,
				Details: map[string]any{"user": "alice"},
			},
			want: "FTP login failed for alice",
		},
		{
			name: "FTP login attempt",
			ev: model.Event{
				Type:    model.EvFTPLoginTry,
				Details: map[string]any{"user": "root"},
			},
			want: "FTP login attempt for root",
		},
		{
			name: "FTP command with argument",
			ev: model.Event{
				Type: model.EvFTPCommand,
				Details: map[string]any{
					"command": "STOR",
					"arg":     "secret.png",
				},
			},
			want: "FTP command: STOR secret.png",
		},
		{
			name: "FTP command without argument",
			ev: model.Event{
				Type: model.EvFTPCommand,
				Details: map[string]any{
					"command": "QUIT",
				},
			},
			want: "FTP command: QUIT",
		},
		{
			name: "FTP file transfer",
			ev: model.Event{
				Type: model.EvFTPTransfer,
				Details: map[string]any{
					"filename": "secret.png",
				},
			},
			want: "FTP file transfer: secret.png",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Title(tc.ev); got != tc.want {
				t.Errorf("Title() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHTTPTitles(t *testing.T) {
	ev := model.Event{
		Type: model.EvHTTPTx,
		Details: map[string]any{
			"method": "GET",
			"url":    "/img.jpg",
			"status": 200,
		},
	}
	want := "HTTP GET /img.jpg -> 200"
	if got := Title(ev); got != want {
		t.Errorf("Title() = %q, want %q", got, want)
	}
}

func TestDNSTitles(t *testing.T) {
	ev := model.Event{
		Type: model.EvDNSQuery,
		Details: map[string]any{
			"qname": "example.com",
			"qtype": "A",
		},
	}
	want := "DNS query: example.com (A)"
	if got := Title(ev); got != want {
		t.Errorf("Title() = %q, want %q", got, want)
	}
}

func TestFileCarvedTitles(t *testing.T) {
	tests := []struct {
		name string
		ev   model.Event
		want string
	}{
		{
			name: "Carved file with full details matching PLAN example",
			ev: model.Event{
				Type: model.EvFileCarved,
				Details: map[string]any{
					"displayName": "secret.png",
					"format":      "png",
					"size":        int64(12697),
				},
			},
			want: "File carved: secret.png (PNG, 12.4 KB)",
		},
		{
			name: "Carved file small bytes",
			ev: model.Event{
				Type: model.EvFileCarved,
				Details: map[string]any{
					"name":   "plans.pdf",
					"format": "pdf",
					"size":   int64(328),
				},
			},
			want: "File carved: plans.pdf (PDF, 328 B)",
		},
		{
			name: "Carved file enrich existing title",
			ev: model.Event{
				Type:  model.EvFileCarved,
				Title: "File carved: secret.png",
				Details: map[string]any{
					"format": "png",
					"size":   int64(12697),
				},
			},
			want: "File carved: secret.png (PNG, 12.4 KB)",
		},
		{
			name: "Carved file without size",
			ev: model.Event{
				Type: model.EvFileCarved,
				Details: map[string]any{
					"filename": "document.docx",
					"format":   "zip",
				},
			},
			want: "File carved: document.docx (ZIP)",
		},
		{
			name: "Carved file name only",
			ev: model.Event{
				Type: model.EvFileCarved,
				Details: map[string]any{
					"displayName": "data.bin",
				},
			},
			want: "File carved: data.bin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Title(tc.ev); got != tc.want {
				t.Errorf("Title() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOtherEventTitles(t *testing.T) {
	tests := []struct {
		name string
		ev   model.Event
		want string
	}{
		{
			name: "Opaque region from real entropy details",
			ev: model.Event{
				Type: model.EvOpaqueRegion,
				Details: map[string]any{
					"dir":      "c2s",
					"startOff": int64(0),
					"endOff":   int64(16384),
					"meanH":    7.8,
				},
			},
			want: "Opaque high-entropy region (16.0 KB)",
		},
		{
			name: "Opaque region with explicit size",
			ev: model.Event{
				Type: model.EvOpaqueRegion,
				Details: map[string]any{
					"size": int64(16384),
				},
			},
			want: "Opaque high-entropy region (16.0 KB)",
		},
		{
			name: "TCP anomaly gap",
			ev: model.Event{
				Type:    model.EvTCPAnomaly,
				Details: map[string]any{"kind": "gap"},
			},
			want: "TCP anomaly: Gap in data",
		},
		{
			name: "TCP anomaly overlap conflict",
			ev: model.Event{
				Type:    model.EvTCPAnomaly,
				Details: map[string]any{"kind": "overlap_conflict"},
			},
			want: "TCP anomaly: Overlapping data",
		},
		{
			name: "TCP anomaly midstream",
			ev: model.Event{
				Type:    model.EvTCPAnomaly,
				Details: map[string]any{"kind": "midstream"},
			},
			want: "TCP anomaly: Started mid-stream",
		},
		{
			name: "TCP anomaly parse error",
			ev: model.Event{
				Type:    model.EvTCPAnomaly,
				Details: map[string]any{"kind": "parse_error"},
			},
			want: "TCP anomaly: parse error",
		},
		{
			name: "Stream opened",
			ev: model.Event{
				Type:  model.EvStreamOpened,
				Src:   "10.0.0.1:50000",
				Dst:   "10.0.0.2:80",
				Proto: "tcp",
			},
			want: "Stream opened: 10.0.0.1:50000 -> 10.0.0.2:80 (tcp)",
		},
		{
			name: "Threat verdict",
			ev: model.Event{
				Type: model.EvVerdict,
				Details: map[string]any{
					"status": "malicious",
					"source": "virustotal",
				},
			},
			want: "Threat verdict: malicious (virustotal)",
		},
		{
			name: "Finding event",
			ev: model.Event{
				Type: model.EvFinding,
				Details: map[string]any{
					"title":     "Brute force password guessing",
					"technique": "T1110",
				},
			},
			want: "Finding: Brute force password guessing (T1110)",
		},
		{
			name: "Group event",
			ev: model.Event{
				Type: model.EvGroup,
				Details: map[string]any{
					"count": 500,
				},
			},
			want: "Event group: 500 events",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Title(tc.ev); got != tc.want {
				t.Errorf("Title() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTitleWithProducerDetails covers the exact Details shapes emitted by the
// analyzers and pipeline stages (including values decoded back from the store,
// where JSON numbers arrive as float64).
func TestTitleWithProducerDetails(t *testing.T) {
	tests := []struct {
		name string
		ev   model.Event
		want string
	}{
		{
			name: "HTTP transaction decoded from store",
			ev: model.Event{
				Type:    model.EvHTTPTx,
				Title:   "HTTP GET /img.jpg -> 200",
				Details: map[string]any{"method": "GET", "host": "example.com", "url": "/img.jpg", "status": float64(200)},
			},
			want: "HTTP GET /img.jpg -> 200",
		},
		{
			name: "HTTP transaction from analyzer",
			ev: model.Event{
				Type:    model.EvHTTPTx,
				Title:   "HTTP GET /img.jpg -> 200",
				Details: map[string]any{"method": "GET", "host": "example.com", "url": "/img.jpg", "status": int(200)},
			},
			want: "HTTP GET /img.jpg -> 200",
		},
		{
			name: "Carved file as emitted by the carve stage",
			ev: model.Event{
				Type:  model.EvFileCarved,
				Title: "File carved: img.jpg",
				Details: map[string]any{
					"dir":      "s2c",
					"endOff":   int64(685),
					"format":   "jpeg",
					"magicHex": "ffd8ff",
					"size":     int64(685),
					"startOff": int64(0),
					"status":   "complete",
				},
			},
			want: "File carved: img.jpg (JPEG, 685 B)",
		},
		{
			name: "FTP login success as emitted by the analyzer",
			ev: model.Event{
				Type:  model.EvFTPLoginOK,
				Title: "FTP login successful: bob",
				Details: map[string]any{
					"user":            "bob",
					"passwordPresent": true,
					"password":        "s3cr3t",
					"reply":           "230 Logged in",
				},
			},
			want: "FTP login successful as bob",
		},
		{
			name: "FTP login failure as emitted by the analyzer",
			ev: model.Event{
				Type:  model.EvFTPLoginFail,
				Title: "FTP login failed: alice",
				Details: map[string]any{
					"user":            "alice",
					"passwordPresent": true,
					"reply":           "530 Login incorrect",
				},
			},
			want: "FTP login failed for alice",
		},
		{
			name: "DNS query as emitted by the analyzer",
			ev: model.Event{
				Type:    model.EvDNSQuery,
				Title:   "DNS query: example.com (A)",
				Details: map[string]any{"qname": "example.com", "qtype": "A", "rcode": "No Error"},
			},
			want: "DNS query: example.com (A)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Title(tc.ev); got != tc.want {
				t.Errorf("Title() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBuildAppliesHumanTitles checks the PLAN 9.3 examples survive Build, that
// Build is idempotent, and that title formatting does not change severities.
func TestBuildAppliesHumanTitles(t *testing.T) {
	events := []model.Event{
		{
			TS:       100,
			PacketNo: 1,
			Type:     model.EvFTPLoginOK,
			Title:    "FTP login successful: bob",
			Details:  map[string]any{"user": "bob", "passwordPresent": true, "password": "s3cr3t"},
		},
		{
			TS:       200,
			PacketNo: 2,
			Type:     model.EvFileCarved,
			Title:    "File carved: secret.png",
			Details:  map[string]any{"format": "png", "size": int64(12697)},
		},
		{
			TS:       300,
			PacketNo: 3,
			Type:     model.EvDNSQuery,
			Title:    "DNS query: example.com (A)",
			Details:  map[string]any{"qname": "example.com", "qtype": "A"},
		},
	}

	want := []string{
		"FTP login successful as bob",
		"File carved: secret.png (PNG, 12.4 KB)",
		"DNS query: example.com (A)",
	}

	built := Build(events)
	if len(built) != len(want) {
		t.Fatalf("len = %d, want %d", len(built), len(want))
	}
	for i := range want {
		if built[i].Title != want[i] {
			t.Errorf("built[%d].Title = %q, want %q", i, built[i].Title, want[i])
		}
	}

	// Rate runs before titles; formatting must not lower or raise severities.
	if built[0].Severity != model.SevWarning {
		t.Errorf("FTP login severity = %q, want warning", built[0].Severity)
	}
	if built[1].Severity != model.SevInfo {
		t.Errorf("FILE_CARVED severity = %q, want info", built[1].Severity)
	}

	// Applying Build to its own output must not change the titles again.
	again := Build(built)
	for i := range want {
		if again[i].Title != want[i] {
			t.Errorf("second Build title[%d] = %q, want %q", i, again[i].Title, want[i])
		}
	}
}
