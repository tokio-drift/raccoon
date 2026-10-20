package timeline

import (
	"fmt"
	"strings"

	"github.com/tokio-drift/raccoon/internal/model"
)

// FormatBytes formats a byte count into a human-readable string according to
// UI_Design.md §12.5 (1024-based steps, one decimal place above 1 KB):
//   - Under 1 KB: "142 B"
//   - Under 1 MB: "12.4 KB"
//   - Under 1 GB: "5.2 MB"
//   - 1 GB and above: "1.1 GB"
func FormatBytes(n int64) string {
	if n < 0 {
		return "0 B"
	}
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case n < kb:
		return fmt.Sprintf("%d B", n)
	case n < mb:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(kb))
	case n < gb:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(mb))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(gb))
	}
}

// Title formats a human-readable title for an event based on its type and
// recorded details (e.g. "FTP login successful as bob", "File carved: secret.png (PNG, 12.4 KB)",
// "DNS query: example.com (A)").
func Title(e model.Event) string {
	return FormatTitle(e)
}

// FormatTitle generates or enriches a human-friendly title for the given event.
func FormatTitle(e model.Event) string {
	switch e.Type {
	case model.EvFTPLoginOK:
		return ftpLoginSuccessTitle(e)

	case model.EvFTPLoginFail:
		return ftpLoginFailedTitle(e)

	case model.EvFTPLoginTry:
		return ftpLoginAttemptTitle(e)

	case model.EvFTPCommand:
		return ftpCommandTitle(e)

	case model.EvFTPTransfer:
		return ftpTransferTitle(e)

	case model.EvHTTPTx:
		return httpTxTitle(e)

	case model.EvDNSQuery:
		return dnsQueryTitle(e)

	case model.EvFileCarved:
		return fileCarvedTitle(e)

	case model.EvOpaqueRegion:
		return opaqueRegionTitle(e)

	case model.EvTCPAnomaly:
		return tcpAnomalyTitle(e)

	case model.EvStreamOpened:
		return streamOpenedTitle(e)

	case model.EvVerdict:
		return verdictTitle(e)

	case model.EvFinding:
		return findingTitle(e)

	case model.EvGroup:
		return groupTitle(e)

	default:
		if e.Title != "" {
			return e.Title
		}
		if e.Type != "" {
			return string(e.Type)
		}
		return "Event"
	}
}

func ftpLoginSuccessTitle(e model.Event) string {
	user := stringDetail(e, "user")
	if user == "" {
		user = extractUserFromTitle(e.Title)
	}
	if user != "" {
		return fmt.Sprintf("FTP login successful as %s", user)
	}
	return "FTP login successful"
}

func ftpLoginFailedTitle(e model.Event) string {
	user := stringDetail(e, "user")
	if user == "" {
		user = extractUserFromTitle(e.Title)
	}
	if user != "" {
		return fmt.Sprintf("FTP login failed for %s", user)
	}
	return "FTP login failed"
}

func ftpLoginAttemptTitle(e model.Event) string {
	user := stringDetail(e, "user")
	if user == "" {
		user = extractUserFromTitle(e.Title)
	}
	if user != "" {
		return fmt.Sprintf("FTP login attempt for %s", user)
	}
	return "FTP login attempt"
}

func ftpCommandTitle(e model.Event) string {
	cmd := stringDetail(e, "command")
	if cmd == "" {
		cmd = stringDetail(e, "cmd")
	}
	arg := stringDetail(e, "arg")
	if cmd != "" && arg != "" {
		return fmt.Sprintf("FTP command: %s %s", cmd, arg)
	}
	if cmd != "" {
		return fmt.Sprintf("FTP command: %s", cmd)
	}
	if e.Title != "" {
		return e.Title
	}
	return "FTP command"
}

func ftpTransferTitle(e model.Event) string {
	filename := stringDetail(e, "filename")
	if filename != "" {
		return fmt.Sprintf("FTP file transfer: %s", filename)
	}
	if e.Title != "" {
		return e.Title
	}
	return "FTP file transfer"
}

func httpTxTitle(e model.Event) string {
	method := stringDetail(e, "method")
	url := stringDetail(e, "url")
	if url == "" {
		url = stringDetail(e, "target")
	}
	status := intDetail(e, "status")
	if method != "" && url != "" && status > 0 {
		return fmt.Sprintf("HTTP %s %s -> %d", method, url, status)
	}
	if e.Title != "" {
		return e.Title
	}
	return "HTTP transaction"
}

func dnsQueryTitle(e model.Event) string {
	qname := stringDetail(e, "qname")
	qtype := stringDetail(e, "qtype")
	if qname != "" && qtype != "" {
		return fmt.Sprintf("DNS query: %s (%s)", qname, qtype)
	}
	if qname != "" {
		return fmt.Sprintf("DNS query: %s", qname)
	}
	if e.Title != "" {
		return e.Title
	}
	return "DNS query"
}

func fileCarvedTitle(e model.Event) string {
	name := extractFileName(e)
	format := stringDetail(e, "format")
	size := int64Detail(e, "size")

	var meta []string
	if format != "" {
		meta = append(meta, strings.ToUpper(format))
	}
	if size > 0 {
		meta = append(meta, FormatBytes(size))
	}

	if name != "" && len(meta) > 0 {
		return fmt.Sprintf("File carved: %s (%s)", name, strings.Join(meta, ", "))
	}
	if name != "" {
		return fmt.Sprintf("File carved: %s", name)
	}
	if len(meta) > 0 {
		return fmt.Sprintf("File carved (%s)", strings.Join(meta, ", "))
	}
	if e.Title != "" {
		return e.Title
	}
	return "File carved"
}

func opaqueRegionTitle(e model.Event) string {
	// The entropy stage records the region as startOff/endOff; size is only
	// present when an earlier producer supplied it. Keep the legacy start/end
	// keys as a last resort.
	size := int64Detail(e, "size")
	if size <= 0 {
		start := int64Detail(e, "startOff")
		end := int64Detail(e, "endOff")
		if end <= start {
			start = int64Detail(e, "start")
			end = int64Detail(e, "end")
		}
		if end > start {
			size = end - start
		}
	}
	if size > 0 {
		return fmt.Sprintf("Opaque high-entropy region (%s)", FormatBytes(size))
	}
	if e.Title != "" {
		return e.Title
	}
	return "Opaque high-entropy region"
}

func tcpAnomalyTitle(e model.Event) string {
	kind := stringDetail(e, "kind")
	switch kind {
	case "gap":
		return "TCP anomaly: Gap in data"
	case "overlap_conflict":
		return "TCP anomaly: Overlapping data"
	case "midstream":
		return "TCP anomaly: Started mid-stream"
	case "":
		// Fall through to the existing title below.
	default:
		return "TCP anomaly: " + strings.ReplaceAll(kind, "_", " ")
	}
	if e.Title != "" {
		return e.Title
	}
	return "TCP anomaly"
}

func streamOpenedTitle(e model.Event) string {
	if e.Src != "" && e.Dst != "" {
		proto := e.Proto
		if proto == "" {
			proto = "tcp"
		}
		return fmt.Sprintf("Stream opened: %s -> %s (%s)", e.Src, e.Dst, proto)
	}
	if e.Title != "" {
		return e.Title
	}
	return "Stream opened"
}

func verdictTitle(e model.Event) string {
	status := stringDetail(e, "status")
	source := stringDetail(e, "source")
	if status != "" && source != "" {
		return fmt.Sprintf("Threat verdict: %s (%s)", status, source)
	}
	if status != "" {
		return fmt.Sprintf("Threat verdict: %s", status)
	}
	if e.Title != "" {
		return e.Title
	}
	return "Threat verdict"
}

func findingTitle(e model.Event) string {
	tech := stringDetail(e, "technique")
	title := stringDetail(e, "title")
	if title == "" {
		title = e.Title
	}
	title = strings.TrimPrefix(title, "Finding: ")
	if title != "" && tech != "" {
		return fmt.Sprintf("Finding: %s (%s)", title, tech)
	}
	if title != "" {
		return fmt.Sprintf("Finding: %s", title)
	}
	return "Finding"
}

func groupTitle(e model.Event) string {
	count := intDetail(e, "count")
	if count > 0 {
		return fmt.Sprintf("Event group: %d events", count)
	}
	if e.Title != "" {
		return e.Title
	}
	return "Event group"
}

// extractFileName derives the display filename from Details or existing Title.
func extractFileName(e model.Event) string {
	for _, k := range []string{"displayName", "name", "filename"} {
		if s := stringDetail(e, k); s != "" {
			return s
		}
	}
	// Parse from existing Title: "File carved: name (META)" -> "name"
	if strings.HasPrefix(e.Title, "File carved: ") {
		raw := strings.TrimPrefix(e.Title, "File carved: ")
		if idx := strings.Index(raw, " ("); idx != -1 {
			return raw[:idx]
		}
		return raw
	}
	return ""
}

func extractUserFromTitle(title string) string {
	for _, prefix := range []string{
		"FTP login successful as ",
		"FTP login successful: ",
		"FTP login failed for ",
		"FTP login failed: ",
		"FTP login attempt for ",
		"FTP login attempt: ",
	} {
		if strings.HasPrefix(title, prefix) {
			return strings.TrimPrefix(title, prefix)
		}
	}
	return ""
}

func stringDetail(e model.Event, key string) string {
	if e.Details == nil {
		return ""
	}
	if v, ok := e.Details[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intDetail(e model.Event, key string) int {
	if e.Details == nil {
		return 0
	}
	if v, ok := e.Details[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return 0
}

func int64Detail(e model.Event, key string) int64 {
	if e.Details == nil {
		return 0
	}
	if v, ok := e.Details[key]; ok {
		switch n := v.(type) {
		case int64:
			return n
		case int:
			return int64(n)
		case float64:
			return int64(n)
		}
	}
	return 0
}
