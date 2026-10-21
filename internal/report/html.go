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
<title>RACCOON report {{.CaseID}}</title>
<style>
:root{color-scheme:light;--ink:#1c2430;--muted:#5b6675;--line:#d9dee6;--bg:#f7f8fa;--panel:#fff;--accent:#8f2d2d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px}h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
p{margin:4px 0}.meta{color:var(--muted)}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:130px}
.card b{display:block;font-size:22px;font-variant-numeric:tabular-nums}table{width:100%;border-collapse:collapse;background:var(--panel)}
th,td{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top;font-size:12px}
th{color:var(--muted);font-weight:600}code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px}
pre{white-space:pre-wrap;word-break:break-word;margin:0}.sev-critical{color:#a01818;font-weight:700}.sev-warning{color:#9a5b00;font-weight:700}
@media print{body{background:#fff}main{padding:0}.card,table{break-inside:avoid}}
</style>
</head>
<body><main>
<h1>RACCOON case report</h1>
<p class="meta">{{.CaseID}} &middot; generated {{.GeneratedAt}} &middot; RACCOON {{.ToolVersion}}</p>
<section class="cards">
<div class="card"><span>Events</span><b>{{.Counts.Events}}</b></div>
<div class="card"><span>Files</span><b>{{.Counts.Files}}</b></div>
<div class="card"><span>Streams</span><b>{{.Counts.Streams}}</b></div>
</section>
<h2>Case</h2>
<table><tbody>
{{range $k, $v := .Meta}}<tr><th>{{$k}}</th><td>{{$v}}</td></tr>{{end}}
</tbody></table>
<h2>Carved files</h2>
<table><thead><tr><th>Name</th><th>Format</th><th>Size</th><th>SHA-256</th><th>Status</th><th>Verdicts</th></tr></thead><tbody>
{{range .Files}}<tr><td>{{.DisplayName}}</td><td>{{.Format}}</td><td>{{.Size}}</td><td><code>{{.SHA256}}</code></td><td>{{.Status}}</td><td>{{range .Verdicts}}{{.Source}}: {{.Status}}{{if .Score}} ({{.Score}}/{{.Total}}){{end}}<br>{{end}}</td></tr>
{{else}}<tr><td colspan="6">No carved files.</td></tr>{{end}}
</tbody></table>
<h2>Timeline</h2>
<table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Title</th><th>Details</th></tr></thead><tbody>
{{range .Events}}<tr><td>{{time .TS}}</td><td class="sev-{{.Severity}}">{{.Severity}}</td><td>{{.Type}}</td><td>{{.Title}}</td><td><pre>{{details .Details}}</pre></td></tr>
{{else}}<tr><td colspan="5">No events.</td></tr>{{end}}
</tbody></table>
</main></body></html>
`))

type htmlData struct {
	*Data
	GeneratedAt string
}

func renderHTML(data *Data) ([]byte, error) {
	var b bytes.Buffer
	if err := htmlTemplate.Execute(&b, htmlData{Data: data, GeneratedAt: data.GeneratedAt}); err != nil {
		return nil, fmt.Errorf("report: render html: %w", err)
	}
	return b.Bytes(), nil
}
