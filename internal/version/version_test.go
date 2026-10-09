package version

import "testing"

func TestStringOverride(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	Version = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Fatalf("String() = %q, want %q", got, "v1.2.3")
	}
}

func TestStringFallback(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	Version = ""
	if got := String(); got == "" {
		t.Fatal("String() returned an empty string")
	}
}
