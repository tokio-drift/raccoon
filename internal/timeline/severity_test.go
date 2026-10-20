package timeline

import (
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
)

func TestRateDefaults(t *testing.T) {
	tests := []struct {
		name string
		ev   model.Event
	}{
		{
			name: "FTP login success",
			ev:   model.Event{Type: model.EvFTPLoginOK, Title: "FTP login successful: bob"},
		},
		{
			name: "HTTP transaction",
			ev:   model.Event{Type: model.EvHTTPTx, Title: "HTTP GET /index.html -> 200"},
		},
		{
			name: "DNS query",
			ev:   model.Event{Type: model.EvDNSQuery, Title: "DNS query: example.com (A)"},
		},
		{
			name: "Stream opened",
			ev:   model.Event{Type: model.EvStreamOpened, Title: "Stream opened"},
		},
		{
			name: "FTP command",
			ev:   model.Event{Type: model.EvFTPCommand, Title: "FTP command: PWD"},
		},
		{
			name: "FTP login failed",
			ev:   model.Event{Type: model.EvFTPLoginFail, Title: "FTP login failed: alice"},
		},
		{
			name: "Benign carved file",
			ev: model.Event{
				Type:  model.EvFileCarved,
				Title: "File carved: image.png",
				Details: map[string]any{
					"format":   "png",
					"ext":      "png",
					"magicHex": "89504e470d0a1a0a",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Rate(tc.ev)
			if got != model.SevInfo {
				t.Errorf("Rate(%s) = %q, want %q", tc.name, got, model.SevInfo)
			}
		})
	}
}

func TestRateCleartextCredentials(t *testing.T) {
	tests := []struct {
		name    string
		evType  model.EventType
		details map[string]any
	}{
		{
			name:   "FTP passwordPresent bool",
			evType: model.EvFTPLoginOK,
			details: map[string]any{
				"user":            "bob",
				"passwordPresent": true,
				"password":        "secret123",
			},
		},
		{
			name:   "HTTP basic auth password string",
			evType: model.EvHTTPTx,
			details: map[string]any{
				"authUser": "alice",
				"password": "supersecret",
			},
		},
		{
			name:   "FTP login failed with cleartext credential",
			evType: model.EvFTPLoginFail,
			details: map[string]any{
				"user":            "admin",
				"passwordPresent": true,
			},
		},
		{
			name:   "Generic event with cleartext flag",
			evType: model.EvStreamOpened,
			details: map[string]any{
				"cleartext": true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := model.Event{
				Type:    tc.evType,
				Details: tc.details,
			}
			got := Rate(ev)
			if got != model.SevWarning {
				t.Errorf("Rate(%s) = %q, want %q", tc.name, got, model.SevWarning)
			}
		})
	}
}

func TestRateFileCarved(t *testing.T) {
	tests := []struct {
		name    string
		title   string
		details map[string]any
		wantSev model.Severity
	}{
		{
			name:    "Benign JPEG",
			title:   "File carved: photo.jpg",
			details: map[string]any{"format": "jpeg", "ext": "jpg", "magicHex": "ffd8ff"},
			wantSev: model.SevInfo,
		},
		{
			name:    "PE by format",
			title:   "File carved: unknown",
			details: map[string]any{"format": "pe", "magicHex": "4d5a9000"},
			wantSev: model.SevWarning,
		},
		{
			name:    "PE by extension",
			title:   "File carved: payload.exe",
			details: map[string]any{"ext": "exe"},
			wantSev: model.SevWarning,
		},
		{
			name:    "PE by magic hex",
			title:   "File carved: dropped.bin",
			details: map[string]any{"magicHex": "4d5a0000"},
			wantSev: model.SevWarning,
		},
		{
			name:    "ELF by format",
			title:   "File carved: implant",
			details: map[string]any{"format": "elf"},
			wantSev: model.SevWarning,
		},
		{
			name:    "ELF by magic hex",
			title:   "File carved: blob.dat",
			details: map[string]any{"magicHex": "7f454c46020101"},
			wantSev: model.SevWarning,
		},
		{
			name:    "Shell script by ext",
			title:   "File carved: setup.sh",
			details: map[string]any{"ext": "sh"},
			wantSev: model.SevWarning,
		},
		{
			name:    "PowerShell script by ext",
			title:   "File carved: run.ps1",
			details: map[string]any{"ext": "ps1"},
			wantSev: model.SevWarning,
		},
		{
			name:    "Script by shebang magic hex",
			title:   "File carved: init",
			details: map[string]any{"magicHex": "23212f62696e2f7368"}, // "#!/bin/sh"
			wantSev: model.SevWarning,
		},
		{
			name:    "Carved file with malicious status",
			title:   "File carved: eicar.com",
			details: map[string]any{"status": "malicious"},
			wantSev: model.SevCritical,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := model.Event{
				Type:    model.EvFileCarved,
				Title:   tc.title,
				Details: tc.details,
			}
			got := Rate(ev)
			if got != tc.wantSev {
				t.Errorf("Rate(%s) = %q, want %q", tc.name, got, tc.wantSev)
			}
		})
	}
}

func TestRateOpaqueRegion(t *testing.T) {
	ev := model.Event{
		Type:  model.EvOpaqueRegion,
		Title: "Opaque high-entropy region (16 KB)",
	}
	if got := Rate(ev); got != model.SevWarning {
		t.Errorf("Rate(EvOpaqueRegion) = %q, want %q", got, model.SevWarning)
	}
}

func TestRateTCPAnomaly(t *testing.T) {
	tests := []struct {
		name    string
		kind    string
		wantSev model.Severity
	}{
		{
			name:    "Overlap conflict anomaly",
			kind:    "overlap_conflict",
			wantSev: model.SevWarning,
		},
		{
			name:    "Gap anomaly",
			kind:    "gap",
			wantSev: model.SevInfo,
		},
		{
			name:    "Midstream anomaly",
			kind:    "midstream",
			wantSev: model.SevInfo,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := model.Event{
				Type:    model.EvTCPAnomaly,
				Title:   "TCP anomaly: " + tc.kind,
				Details: map[string]any{"kind": tc.kind},
			}
			got := Rate(ev)
			if got != tc.wantSev {
				t.Errorf("Rate(%s) = %q, want %q", tc.name, got, tc.wantSev)
			}
		})
	}
}

func TestRateVerdict(t *testing.T) {
	tests := []struct {
		name    string
		title   string
		details map[string]any
		wantSev model.Severity
	}{
		{
			name:    "Malicious VT verdict",
			title:   "Threat verdict: malicious (virustotal)",
			details: map[string]any{"status": "malicious", "source": "virustotal"},
			wantSev: model.SevCritical,
		},
		{
			name:    "YARA rule hit",
			title:   "Threat verdict: malicious (yara)",
			details: map[string]any{"source": "yara", "score": 2, "rules": []string{"eicar"}},
			wantSev: model.SevCritical,
		},
		{
			name:    "Suspicious VT verdict",
			title:   "Threat verdict: suspicious (virustotal)",
			details: map[string]any{"status": "suspicious", "source": "virustotal"},
			wantSev: model.SevWarning,
		},
		{
			name:    "No detections",
			title:   "Threat verdict: no_detections (yara)",
			details: map[string]any{"status": "no_detections", "source": "yara"},
			wantSev: model.SevInfo,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := model.Event{
				Type:    model.EvVerdict,
				Title:   tc.title,
				Details: tc.details,
			}
			got := Rate(ev)
			if got != tc.wantSev {
				t.Errorf("Rate(%s) = %q, want %q", tc.name, got, tc.wantSev)
			}
		})
	}
}

func TestRateEscalationOnly(t *testing.T) {
	// A DNS query that was somehow already rated Critical must not be downgraded to Info.
	evCriticalDNS := model.Event{
		Type:     model.EvDNSQuery,
		Severity: model.SevCritical,
		Title:    "DNS query: evil.com",
	}
	if got := Rate(evCriticalDNS); got != model.SevCritical {
		t.Errorf("expected Critical to be preserved on DNS query, got %q", got)
	}

	// An FTP command already rated Warning must not be downgraded to Info.
	evWarningFTP := model.Event{
		Type:     model.EvFTPCommand,
		Severity: model.SevWarning,
		Title:    "FTP command: RETR",
	}
	if got := Rate(evWarningFTP); got != model.SevWarning {
		t.Errorf("expected Warning to be preserved on FTP command, got %q", got)
	}

	// A benign file starting at Info that has malicious status must escalate to Critical.
	evEscalatingFile := model.Event{
		Type:     model.EvFileCarved,
		Severity: model.SevInfo,
		Title:    "File carved: bad.exe",
		Details:  map[string]any{"status": "malicious"},
	}
	if got := Rate(evEscalatingFile); got != model.SevCritical {
		t.Errorf("expected Info to escalate to Critical, got %q", got)
	}
}

func TestRankAndEscalate(t *testing.T) {
	if Rank(model.SevCritical) <= Rank(model.SevWarning) {
		t.Errorf("Critical rank (%d) must exceed Warning rank (%d)", Rank(model.SevCritical), Rank(model.SevWarning))
	}
	if Rank(model.SevWarning) <= Rank(model.SevInfo) {
		t.Errorf("Warning rank (%d) must exceed Info rank (%d)", Rank(model.SevWarning), Rank(model.SevInfo))
	}

	if Escalate(model.SevInfo, model.SevWarning) != model.SevWarning {
		t.Error("Escalate(Info, Warning) should be Warning")
	}
	if Escalate(model.SevWarning, model.SevInfo) != model.SevWarning {
		t.Error("Escalate(Warning, Info) should be Warning")
	}
	if Escalate(model.SevCritical, model.SevWarning) != model.SevCritical {
		t.Error("Escalate(Critical, Warning) should be Critical")
	}
	if Escalate("", model.SevInfo) != model.SevInfo {
		t.Error("Escalate(\"\", Info) should be Info")
	}
}
