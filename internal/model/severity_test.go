package model

import "testing"

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		name string
		sev  Severity
		want int
	}{
		{"info", SevInfo, 0},
		{"warning", SevWarning, 1},
		{"critical", SevCritical, 2},
		{"unknown", Severity("bogus"), -1},
		{"empty", Severity(""), -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sev.Rank(); got != tt.want {
				t.Fatalf("Rank() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEscalate(t *testing.T) {
	tests := []struct {
		name string
		a, b Severity
		want Severity
	}{
		{"info,warning", SevInfo, SevWarning, SevWarning},
		{"warning,info", SevWarning, SevInfo, SevWarning},
		{"critical,info", SevCritical, SevInfo, SevCritical},
		{"info,critical", SevInfo, SevCritical, SevCritical},
		{"warning,critical", SevWarning, SevCritical, SevCritical},
		{"equal", SevWarning, SevWarning, SevWarning},
		{"unknown,critical", Severity("bogus"), SevCritical, SevCritical},
		{"critical,unknown", SevCritical, Severity("bogus"), SevCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Escalate(tt.a, tt.b); got != tt.want {
				t.Fatalf("Escalate(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
