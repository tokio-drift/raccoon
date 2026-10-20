package timeline

import (
	"path/filepath"
	"strings"

	"github.com/tokio-drift/raccoon/internal/model"
)

// Rank returns the numeric priority of a severity:
// critical (3) > warning (2) > info (1) > unset (0).
func Rank(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 3
	case model.SevWarning:
		return 2
	case model.SevInfo:
		return 1
	default:
		return 0
	}
}

// Escalate returns the higher severity between a and b.
// Escalation only: severity can never be lowered.
func Escalate(a, b model.Severity) model.Severity {
	if Rank(a) >= Rank(b) {
		if a == "" {
			return model.SevInfo
		}
		return a
	}
	return b
}

// Rate computes the triage severity for an event according to core timeline rules:
//   - FTP_LOGIN_SUCCESS, HTTP_TRANSACTION, DNS_QUERY, STREAM_OPENED, FTP_COMMAND → info
//   - FTP_LOGIN_FAILED → info (bursts of failed logins are handled later in PLUS-C)
//   - cleartext credential present → warning
//   - FILE_CARVED of PE/ELF/script → warning
//   - OPAQUE_REGION → warning
//   - TCP_ANOMALY with overlap conflict → warning
//   - malicious verdict / YARA hit → critical
//
// Escalation only: the returned severity is always at least as high as e.Severity.
func Rate(e model.Event) model.Severity {
	calculated := rateBase(e)
	return Escalate(e.Severity, calculated)
}

// rateBase evaluates the intrinsic severity of the event ignoring existing escalation.
func rateBase(e model.Event) model.Severity {
	switch e.Type {
	case model.EvVerdict:
		if isMaliciousVerdict(e) {
			return model.SevCritical
		}
		if isSuspiciousVerdict(e) {
			return model.SevWarning
		}
		return model.SevInfo

	case model.EvOpaqueRegion:
		return model.SevWarning

	case model.EvTCPAnomaly:
		if isOverlapConflict(e) {
			return model.SevWarning
		}
		return model.SevInfo

	case model.EvFileCarved:
		if isMaliciousCarve(e) {
			return model.SevCritical
		}
		if isPEELFScript(e) {
			return model.SevWarning
		}
		return model.SevInfo

	case model.EvFTPLoginOK, model.EvFTPLoginFail, model.EvFTPLoginTry,
		model.EvHTTPTx, model.EvFTPCommand, model.EvDNSQuery,
		model.EvStreamOpened, model.EvFTPTransfer:
		if hasCleartextCredential(e) {
			return model.SevWarning
		}
		return model.SevInfo

	default:
		if hasCleartextCredential(e) {
			return model.SevWarning
		}
		return model.SevInfo
	}
}

// isMaliciousVerdict reports whether a verdict event represents a malicious detection
// or YARA hit.
func isMaliciousVerdict(e model.Event) bool {
	if e.Details == nil {
		return strings.Contains(strings.ToLower(e.Title), "malicious")
	}

	if s, ok := e.Details["status"].(string); ok {
		if strings.EqualFold(s, "malicious") {
			return true
		}
	}

	// YARA rule hits are malicious detections.
	if src, ok := e.Details["source"].(string); ok && strings.EqualFold(src, "yara") {
		if score, ok := e.Details["score"].(int); ok && score > 0 {
			return true
		}
		if score, ok := e.Details["score"].(float64); ok && score > 0 {
			return true
		}
		if rules, ok := e.Details["rules"].([]string); ok && len(rules) > 0 {
			return true
		}
	}

	return strings.Contains(strings.ToLower(e.Title), "malicious")
}

// isSuspiciousVerdict reports whether a verdict event represents a suspicious detection.
func isSuspiciousVerdict(e model.Event) bool {
	if e.Details == nil {
		return strings.Contains(strings.ToLower(e.Title), "suspicious")
	}
	if s, ok := e.Details["status"].(string); ok {
		if strings.EqualFold(s, "suspicious") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(e.Title), "suspicious")
}

// isMaliciousCarve reports whether a carved file event is marked as malicious
// (e.g. from prior intel evaluation).
func isMaliciousCarve(e model.Event) bool {
	if e.Details == nil {
		return false
	}
	if s, ok := e.Details["status"].(string); ok && strings.EqualFold(s, "malicious") {
		return true
	}
	if s, ok := e.Details["verdict"].(string); ok && strings.EqualFold(s, "malicious") {
		return true
	}
	return false
}

// hasCleartextCredential checks whether cleartext credentials were recovered
// in the event details.
func hasCleartextCredential(e model.Event) bool {
	if e.Details == nil {
		return false
	}

	if b, ok := e.Details["passwordPresent"].(bool); ok && b {
		return true
	}
	if s, ok := e.Details["password"].(string); ok && s != "" {
		return true
	}
	if s, ok := e.Details["pass"].(string); ok && s != "" {
		return true
	}
	if b, ok := e.Details["cleartext"].(bool); ok && b {
		return true
	}
	if _, ok := e.Details["credential"]; ok {
		return true
	}
	if _, ok := e.Details["credentials"]; ok {
		return true
	}

	return false
}

// isPEELFScript reports whether a carved file is a Windows PE, Linux ELF, or script.
func isPEELFScript(e model.Event) bool {
	if e.Details != nil {
		// 1. Check format name.
		if fmtName, ok := e.Details["format"].(string); ok {
			fmtLower := strings.ToLower(fmtName)
			switch fmtLower {
			case "pe", "exe", "dll", "elf", "script", "sh", "bash", "ps1", "bat", "vbs", "python", "py", "javascript", "js":
				return true
			}
		}

		// 2. Check extension in details.
		if ext, ok := e.Details["ext"].(string); ok {
			if isExecutableOrScriptExt(ext) {
				return true
			}
		}

		// 3. Check magic hex:
		// 4d5a: "MZ" (PE)
		// 7f454c46: "\x7fELF" (ELF)
		// 2321: "#!" (Shebang script)
		if magic, ok := e.Details["magicHex"].(string); ok {
			mLower := strings.ToLower(magic)
			if strings.HasPrefix(mLower, "4d5a") ||
				strings.HasPrefix(mLower, "7f454c46") ||
				strings.HasPrefix(mLower, "2321") {
				return true
			}
		}
	}

	// 4. Fallback check on Title / filename extension.
	ext := strings.TrimPrefix(filepath.Ext(e.Title), ".")
	return isExecutableOrScriptExt(ext)
}

// isExecutableOrScriptExt checks if an extension indicates an executable binary or script.
func isExecutableOrScriptExt(ext string) bool {
	ext = strings.ToLower(strings.TrimPrefix(ext, "."))
	switch ext {
	// PE
	case "exe", "dll", "sys", "scr", "drv", "cpl", "ocx":
		return true
	// ELF
	case "elf", "so", "bin", "o":
		return true
	// Scripts
	case "sh", "bash", "ps1", "bat", "cmd", "vbs", "vbe", "wsf", "js", "jse", "py", "pyc", "php", "pl", "rb":
		return true
	default:
		return false
	}
}

// isOverlapConflict checks whether a TCP_ANOMALY event represents an overlap conflict.
func isOverlapConflict(e model.Event) bool {
	if e.Details != nil {
		if k, ok := e.Details["kind"].(string); ok {
			if strings.EqualFold(k, "overlap_conflict") {
				return true
			}
		}
	}
	return strings.Contains(strings.ToLower(e.Title), "overlap_conflict")
}
