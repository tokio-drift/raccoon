package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"time"
)

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"time": func(ns int64) string {
		if ns == 0 {
			return ""
		}
		return time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
	},
	"formatBytes": func(b int64) string {
		switch {
		case b < 1024:
			return fmt.Sprintf("%d B", b)
		case b < 1024*1024:
			return fmt.Sprintf("%.1f KB", float64(b)/1024)
		case b < 1024*1024*1024:
			return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
		default:
			return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
		}
	},
	"verdictClass": func(status string) string {
		switch status {
		case "malicious":
			return "badge-malicious"
		case "suspicious":
			return "badge-suspicious"
		case "no_detections":
			return "badge-no-detections"
		case "not_checked":
			return "badge-not-checked"
		default:
			return "badge-unknown"
		}
	},
	"verdictLabel": func(status string) string {
		switch status {
		case "malicious":
			return "Malicious"
		case "suspicious":
			return "Suspicious"
		case "no_detections":
			return "No detections"
		case "not_checked":
			return "Not checked"
		case "unknown":
			return "Unknown"
		default:
			if status == "" {
				return "Not checked"
			}
			return status
		}
	},
	"details": func(m map[string]any) string {
		if len(m) == 0 {
			return ""
		}
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetIndent("", "  ")
		_ = enc.Encode(m)
		return b.String()
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RACCOON Case Report — {{.CaseID}}</title>
<style>
:root {
  color-scheme: light;
  --bg: #f7f5f2;
  --panel: #ffffff;
  --panel-muted: #fbf9f6;
  --ink: #1f1b16;
  --muted: #6e655f;
  --line: #e3ded8;
  --line-subtle: #eee9e3;
  --accent: #b85d19;
  --accent-light: #fbeee3;

  --sev-critical: #a12c25;
  --sev-critical-bg: #fdf2f1;
  --sev-critical-line: #f1b7b3;

  --sev-warning: #8a5200;
  --sev-warning-bg: #fef7ed;
  --sev-warning-line: #f8d39e;

  --sev-info: #14495d;
  --sev-info-bg: #f0f7fa;
  --sev-info-line: #b5d8e6;

  --verdict-nodetect: #1b633e;
  --verdict-nodetect-bg: #edf7f0;
  --verdict-nodetect-line: #b7dec6;
}

* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 13px;
  line-height: 1.5;
}

main {
  max-width: 1200px;
  margin: 0 auto;
  padding: 32px 24px;
}

header {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 24px;
  margin-bottom: 24px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.brand h1 {
  font-size: 20px;
  font-weight: 700;
  margin: 0;
  letter-spacing: -0.01em;
}

.badge-tag {
  display: inline-block;
  padding: 2px 8px;
  font-size: 11px;
  font-weight: 600;
  border-radius: 4px;
  background: var(--accent-light);
  color: var(--accent);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.meta-sub {
  color: var(--muted);
  font-size: 12px;
  margin: 4px 0 0;
}

.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
  margin: 20px 0 28px;
}

.card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 14px 16px;
}

.card .label {
  display: block;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  margin-bottom: 4px;
}

.card .val {
  font-size: 24px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
}

.card-critical { border-color: var(--sev-critical-line); background: var(--sev-critical-bg); color: var(--sev-critical); }
.card-warning { border-color: var(--sev-warning-line); background: var(--sev-warning-bg); color: var(--sev-warning); }
.card-info { border-color: var(--sev-info-line); background: var(--sev-info-bg); color: var(--sev-info); }

section {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 20px 24px;
  margin-bottom: 24px;
}

h2 {
  font-size: 16px;
  font-weight: 600;
  margin: 0 0 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--line-subtle);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}

th, td {
  padding: 8px 10px;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--line-subtle);
}

th {
  color: var(--muted);
  font-weight: 600;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  background: var(--panel-muted);
}

tr:last-child td { border-bottom: none; }

code, pre {
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 11px;
}

pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  background: var(--panel-muted);
  padding: 6px 8px;
  border-radius: 4px;
  border: 1px solid var(--line-subtle);
}

.pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 7px;
  font-size: 11px;
  font-weight: 600;
  border-radius: 4px;
  text-transform: capitalize;
}

.pill-critical { background: var(--sev-critical-bg); color: var(--sev-critical); border: 1px solid var(--sev-critical-line); }
.pill-warning { background: var(--sev-warning-bg); color: var(--sev-warning); border: 1px solid var(--sev-warning-line); }
.pill-info { background: var(--sev-info-bg); color: var(--sev-info); border: 1px solid var(--sev-info-line); }

.badge-malicious { background: var(--sev-critical-bg); color: var(--sev-critical); border: 1px solid var(--sev-critical-line); }
.badge-suspicious { background: var(--sev-warning-bg); color: var(--sev-warning); border: 1px solid var(--sev-warning-line); }
.badge-no-detections { background: var(--verdict-nodetect-bg); color: var(--verdict-nodetect); border: 1px solid var(--verdict-nodetect-line); }
.badge-not-checked { background: var(--panel-muted); color: var(--muted); border: 1px solid var(--line); }
.badge-unknown { background: var(--panel-muted); color: var(--muted); border: 1px solid var(--line); }

.finding-item {
  border: 1px solid var(--line);
  border-left: 4px solid var(--accent);
  border-radius: 6px;
  padding: 12px 16px;
  margin-bottom: 12px;
  background: var(--panel-muted);
}

.finding-item.finding-critical { border-left-color: var(--sev-critical); }
.finding-item.finding-warning { border-left-color: var(--sev-warning); }

.finding-title {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 4px;
}

.finding-tech {
  display: inline-block;
  padding: 1px 6px;
  font-size: 10px;
  font-weight: 700;
  background: var(--line);
  border-radius: 3px;
  margin-right: 6px;
}

footer {
  text-align: center;
  color: var(--muted);
  font-size: 11px;
  margin-top: 36px;
  padding: 16px 0;
}

@media print {
  body { background: #ffffff; font-size: 11px; color: #000000; }
  main { max-width: 100%; padding: 0; }
  header, section, .card, .finding-item {
    border: 1px solid #cccccc !important;
    border-radius: 0;
    box-shadow: none !important;
    background: #ffffff !important;
  }
  .card, table, tr, .finding-item { break-inside: avoid; page-break-inside: avoid; }
  thead { display: table-header-group; }
}
</style>
</head>
<body>
<main>
<header>
  <div class="brand">
    <h1>RACCOON case report</h1>
    <span class="badge-tag">Offline Forensic Report</span>
  </div>
  <p class="meta-sub">Case ID: <b>{{.CaseID}}</b> &middot; Generated at {{.GeneratedAt}} &middot; Tool Version {{.ToolVersion}}</p>
</header>

<div class="cards">
  <div class="card"><span class="label">Total Events</span><span class="val">{{.Counts.Events}}</span></div>
  <div class="card"><span class="label">Carved Files</span><span class="val">{{.Counts.Files}}</span></div>
  <div class="card"><span class="label">Streams</span><span class="val">{{.Counts.Streams}}</span></div>
  <div class="card card-critical"><span class="label">Critical Events</span><span class="val">{{.Counts.Critical}}</span></div>
  <div class="card card-warning"><span class="label">Warning Events</span><span class="val">{{.Counts.Warning}}</span></div>
  <div class="card card-info"><span class="label">Info Events</span><span class="val">{{.Counts.Info}}</span></div>
</div>

{{if .Findings}}
<section>
  <h2>Key Findings ({{len .Findings}})</h2>
  {{range .Findings}}
  <div class="finding-item finding-{{.Severity}}">
    <div class="finding-title">
      {{if .Technique}}<span class="finding-tech">{{.Technique}}</span>{{end}}
      <b>{{.Title}}</b>
      <span class="pill pill-{{.Severity}}">{{.Severity}}</span>
    </div>
    {{if .Explanation}}<p style="margin: 4px 0;">{{.Explanation}}</p>{{end}}
    {{if .EvidenceEventIDs}}<p style="margin: 4px 0; font-size: 11px; color: var(--muted);">Evidence Event IDs: {{range .EvidenceEventIDs}}#{{.}} {{end}}</p>{{end}}
  </div>
  {{end}}
</section>
{{end}}

<section>
  <h2>Case &amp; Capture Metadata</h2>
  <table>
    <tbody>
      {{range $k, $v := .Meta}}
      <tr>
        <th style="width: 220px;">{{$k}}</th>
        <td>{{$v}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
</section>

<section>
  <h2>Carved Artifacts ({{len .Files}})</h2>
  <table>
    <thead>
      <tr>
        <th>Display Name</th>
        <th>Format</th>
        <th>Size</th>
        <th>SHA-256</th>
        <th>Extraction</th>
        <th>Verdicts</th>
      </tr>
    </thead>
    <tbody>
      {{range .Files}}
      <tr>
        <td><b>{{.DisplayName}}</b></td>
        <td>{{.Format}}</td>
        <td>{{formatBytes .Size}}</td>
        <td><code>{{.SHA256}}</code></td>
        <td>{{.Status}}</td>
        <td>
          {{range .Verdicts}}
            <span class="pill {{verdictClass .Status}}">{{verdictLabel .Status}}</span>
            {{if .Source}}<small>({{.Source}}{{if .Score}} {{.Score}}/{{.Total}}{{end}})</small>{{end}}
            <br>
          {{else}}
            <span class="pill badge-not-checked">Not checked</span>
          {{end}}
        </td>
      </tr>
      {{else}}
      <tr><td colspan="6" style="text-align: center; color: var(--muted); padding: 16px;">No carved artifacts found.</td></tr>
      {{end}}
    </tbody>
  </table>
</section>

<section>
  <h2>Timeline ({{len .Events}})</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 170px;">Time (UTC)</th>
        <th style="width: 70px;">Packet</th>
        <th style="width: 80px;">Severity</th>
        <th style="width: 60px;">Proto</th>
        <th>Title</th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody>
      {{range .Events}}
      <tr>
        <td>{{time .TS}}</td>
        <td>#{{.PacketNo}}</td>
        <td><span class="pill pill-{{.Severity}}">{{.Severity}}</span></td>
        <td>{{.Proto}}</td>
        <td><b>{{.Title}}</b></td>
        <td>{{if .Details}}<pre>{{details .Details}}</pre>{{end}}</td>
      </tr>
      {{else}}
      <tr><td colspan="6" style="text-align: center; color: var(--muted); padding: 16px;">No timeline events recorded.</td></tr>
      {{end}}
    </tbody>
  </table>
</section>

<footer>
  <p>Generated by RACCOON v{{.ToolVersion}} &middot; Report Case {{.CaseID}} &middot; Offline Security Assessment</p>
</footer>
</main>
</body>
</html>
`))

// RenderHTML produces a self-contained HTML report.
func RenderHTML(data *ReportData) ([]byte, error) {
	return renderHTML(data)
}

func renderHTML(data *ReportData) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("report: nil report data")
	}
	var b bytes.Buffer
	if err := htmlTemplate.Execute(&b, data); err != nil {
		return nil, fmt.Errorf("report: render html: %w", err)
	}
	return b.Bytes(), nil
}
