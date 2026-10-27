package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
)

func seedTestCase(t *testing.T, dir, caseID string, hostile bool) *casedir.Case {
	t.Helper()
	c, err := casedir.Create(dir, casedir.Options{
		ID:      caseID,
		PCAP:    "capture.pcap",
		Created: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("casedir.Create: %v", err)
	}

	db, err := store.Open(c.DB())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	if err := db.SetMeta("pcap_name", "capture.pcap"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMeta("pcap_sha256", "abcdef123456"); err != nil {
		t.Fatal(err)
	}

	title1 := "FTP login successful"
	title2 := "Suspicious script execution"
	fname := "secret.png"
	if hostile {
		title1 = "<script>alert('hostile-title')</script>"
		title2 = "\"><img src=x onerror=alert(1)>"
		fname = "<svg onload=alert('xss')>.png"
	}

	events := []model.Event{
		{
			ID:       1,
			TS:       1000000000,
			PacketNo: 1,
			Type:     model.EvFTPLoginOK,
			Severity: model.SevInfo,
			Proto:    "ftp",
			Title:    title1,
			Details:  map[string]any{"user": "alice", "hostile": "<script>alert('details')</script>"},
		},
		{
			ID:       2,
			TS:       2000000000,
			PacketNo: 5,
			Type:     model.EvFileCarved,
			Severity: model.SevWarning,
			Proto:    "tcp",
			Title:    title2,
			Details:  map[string]any{"warning": "possible script"},
		},
		{
			ID:       3,
			TS:       3000000000,
			PacketNo: 10,
			Type:     model.EvTCPAnomaly,
			Severity: model.SevCritical,
			Proto:    "tcp",
			Title:    "Critical exploit detected",
			Details:  map[string]any{"cve": "2026-9999"},
		},
	}
	if _, err := db.InsertEvents(events); err != nil {
		t.Fatal(err)
	}

	files := []model.CarvedFile{
		{
			ID:          1,
			Format:      "png",
			DisplayName: fname,
			Size:        4096,
			SHA256:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Status:      "complete",
		},
	}
	if _, err := db.InsertFiles(files); err != nil {
		t.Fatal(err)
	}

	if err := db.UpsertVerdict(model.Verdict{
		SHA256:    files[0].SHA256,
		Source:    "virustotal",
		Status:    "malicious",
		Score:     50,
		Total:     72,
		CheckedAt: time.Now().UTC().UnixNano(),
	}); err != nil {
		t.Fatal(err)
	}

	findings := []model.Finding{
		{
			ID:               1,
			Title:            "Brute force detected",
			Technique:        "T1110",
			Severity:         model.SevCritical,
			Explanation:      "High rate of failed authentications",
			EvidenceEventIDs: []int64{1, 2},
		},
	}
	if _, err := db.InsertFindings(findings); err != nil {
		t.Fatal(err)
	}

	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}

	return c
}

func TestAssembleReportData(t *testing.T) {
	tmp := t.TempDir()
	c := seedTestCase(t, tmp, "20261028-120000-abcdef", false)

	data, err := Assemble(c)
	if err != nil {
		t.Fatalf("Assemble failed: %v", err)
	}

	if data.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", data.SchemaVersion, SchemaVersion)
	}
	if data.CaseID != c.ID {
		t.Errorf("CaseID = %s, want %s", data.CaseID, c.ID)
	}
	if data.Counts.Events != 3 {
		t.Errorf("Counts.Events = %d, want 3", data.Counts.Events)
	}
	if data.Counts.Files != 1 {
		t.Errorf("Counts.Files = %d, want 1", data.Counts.Files)
	}
	if data.Counts.Critical != 1 {
		t.Errorf("Counts.Critical = %d, want 1", data.Counts.Critical)
	}
	if data.Counts.Warning != 1 {
		t.Errorf("Counts.Warning = %d, want 1", data.Counts.Warning)
	}
	if data.Counts.Info != 1 {
		t.Errorf("Counts.Info = %d, want 1", data.Counts.Info)
	}
	if len(data.Events) != 3 {
		t.Errorf("len(Events) = %d, want 3", len(data.Events))
	}
	if len(data.Files) != 1 {
		t.Errorf("len(Files) = %d, want 1", len(data.Files))
	}
	if len(data.Files[0].Verdicts) != 1 {
		t.Errorf("len(Files[0].Verdicts) = %d, want 1", len(data.Files[0].Verdicts))
	}
	if len(data.Findings) != 1 {
		t.Errorf("len(Findings) = %d, want 1", len(data.Findings))
	}
	if data.Findings[0].Technique != "T1110" {
		t.Errorf("Findings[0].Technique = %s, want T1110", data.Findings[0].Technique)
	}
}

func TestRenderJSON(t *testing.T) {
	tmp := t.TempDir()
	c := seedTestCase(t, tmp, "20261028-120000-abcdef", false)

	data, err := Load(c)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	raw, err := RenderJSON(data)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("Unmarshal raw JSON failed: %v", err)
	}

	if v, ok := parsed["schemaVersion"].(float64); !ok || int(v) != SchemaVersion {
		t.Errorf("schemaVersion = %v, want %d", parsed["schemaVersion"], SchemaVersion)
	}
	if _, ok := parsed["counts"]; !ok {
		t.Errorf("missing counts in JSON")
	}
	if _, ok := parsed["events"]; !ok {
		t.Errorf("missing events in JSON")
	}
	if _, ok := parsed["files"]; !ok {
		t.Errorf("missing files in JSON")
	}
	if _, ok := parsed["findings"]; !ok {
		t.Errorf("missing findings in JSON")
	}
}

func TestRenderHTMLSelfContainedAndNoExternalRequests(t *testing.T) {
	tmp := t.TempDir()
	c := seedTestCase(t, tmp, "20261028-120000-abcdef", false)

	data, err := Load(c)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	htmlBytes, err := RenderHTML(data)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	htmlStr := string(htmlBytes)

	// Must be self-contained HTML
	if !strings.HasPrefix(strings.TrimSpace(htmlStr), "<!doctype html>") && !strings.HasPrefix(strings.TrimSpace(htmlStr), "<!DOCTYPE html>") {
		t.Errorf("HTML does not start with doctype")
	}

	// Must contain no external requests
	forbiddenPrefixes := []string{"http://", "https://", "src=\"//", "href=\"//"}
	for _, forbidden := range forbiddenPrefixes {
		if strings.Contains(htmlStr, forbidden) {
			t.Errorf("HTML contains forbidden external link/resource prefix: %q", forbidden)
		}
	}

	// Must contain print-friendly CSS
	if !strings.Contains(htmlStr, "@media print") {
		t.Errorf("HTML missing @media print styles")
	}

	// Must use design tokens
	if !strings.Contains(htmlStr, "--sev-critical") || !strings.Contains(htmlStr, "--accent") {
		t.Errorf("HTML missing design tokens")
	}

	// Must NEVER describe a verdict as "safe"
	if strings.Contains(strings.ToLower(htmlStr), "safe") && !strings.Contains(strings.ToLower(htmlStr), "safety") {
		t.Errorf("HTML must never describe verdicts as safe")
	}
}

func TestRenderHTMLHostileStringEscaping(t *testing.T) {
	tmp := t.TempDir()
	c := seedTestCase(t, tmp, "20261028-120000-fa1100", true)

	data, err := Load(c)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	htmlBytes, err := RenderHTML(data)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	htmlStr := string(htmlBytes)

	// Verify unescaped hostile tags are NOT present
	hostilePatterns := []string{
		"<script>alert('hostile-title')</script>",
		"<script>alert('details')</script>",
		"\"><img src=x onerror=alert(1)>",
		"<svg onload=alert('xss')>",
	}
	for _, hostile := range hostilePatterns {
		if strings.Contains(htmlStr, hostile) {
			t.Errorf("Hostile unescaped string found in HTML report: %s", hostile)
		}
	}

	// Verify escaped versions are present
	if !strings.Contains(htmlStr, "&lt;script&gt;alert(&#39;hostile-title&#39;)&lt;/script&gt;") &&
		!strings.Contains(htmlStr, "&lt;script&gt;alert('hostile-title')&lt;/script&gt;") {
		t.Errorf("Escaped script tag expected in HTML output")
	}
}

func TestWriteReport(t *testing.T) {
	tmp := t.TempDir()
	c := seedTestCase(t, tmp, "20261028-120000-beef00", false)

	// Write JSON
	jsonPath, err := Write(c.Dir, FormatJSON)
	if err != nil {
		t.Fatalf("Write(JSON) failed: %v", err)
	}
	if filepath.Base(jsonPath) != "report.json" {
		t.Errorf("expected report.json, got %s", filepath.Base(jsonPath))
	}
	jsonContent, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile(json) failed: %v", err)
	}
	if !json.Valid(jsonContent) {
		t.Errorf("written json report is not valid JSON")
	}

	// Write HTML
	htmlPath, err := Write(c.Dir, FormatHTML)
	if err != nil {
		t.Fatalf("Write(HTML) failed: %v", err)
	}
	if filepath.Base(htmlPath) != "report.html" {
		t.Errorf("expected report.html, got %s", filepath.Base(htmlPath))
	}
	htmlContent, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("ReadFile(html) failed: %v", err)
	}
	if len(htmlContent) == 0 {
		t.Errorf("written html report is empty")
	}

	// Write PDF
	pdfPath, err := Write(c.Dir, FormatPDF)
	if err != nil {
		t.Fatalf("Write(PDF) failed: %v", err)
	}
	if filepath.Base(pdfPath) != "report.pdf" {
		t.Errorf("expected report.pdf, got %s", filepath.Base(pdfPath))
	}
	pdfContent, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("ReadFile(pdf) failed: %v", err)
	}
	if !strings.HasPrefix(string(pdfContent), "%PDF-") {
		t.Errorf("PDF report does not start with %%PDF-")
	}
	if len(pdfContent) <= 2048 {
		t.Errorf("PDF report length = %d, want > 2048", len(pdfContent))
	}
}

func TestRenderPDF(t *testing.T) {
	tmp := t.TempDir()
	c := seedTestCase(t, tmp, "20261028-120000-fa1101", false)

	data, err := Load(c)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Add non-Latin1 and long title to test wrapping and replacement
	data.Events = append(data.Events, model.Event{
		ID:       99,
		TS:       4000000000,
		PacketNo: 20,
		Type:     model.EvHTTPTx,
		Severity: model.SevInfo,
		Proto:    "http",
		Title:    "HTTP transaction with Unicode: 🦊 raccoon / “quotes” / 日本語 / " + strings.Repeat("very long string wrapping check ", 5),
	})

	pdfBytes, err := RenderPDF(data)
	if err != nil {
		t.Fatalf("RenderPDF failed: %v", err)
	}

	if !strings.HasPrefix(string(pdfBytes), "%PDF-") {
		t.Errorf("PDF output does not start with %%PDF-")
	}

	if len(pdfBytes) <= 2048 {
		t.Errorf("PDF output length = %d bytes, want > 2 KB", len(pdfBytes))
	}
}
