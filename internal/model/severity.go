package model

// Rank returns the ordering weight of a severity: info=0, warning=1,
// critical=2. Unknown severities rank below info at -1 so that a malformed
// value can never outrank a real one.
func (s Severity) Rank() int {
	switch s {
	case SevInfo:
		return 0
	case SevWarning:
		return 1
	case SevCritical:
		return 2
	default:
		return -1
	}
}

// Escalate returns the higher of the two severities. Severity can only be
// escalated, never lowered. If both rank equally the first argument is
// returned.
func Escalate(a, b Severity) Severity {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}
