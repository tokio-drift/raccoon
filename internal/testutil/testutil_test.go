package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

type sample struct {
	Name  string   `json:"name"`
	Count int      `json:"count"`
	Tags  []string `json:"tags"`
}

func TestLoadExpectedFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.json")
	want := sample{Name: "alpha", Count: 3, Tags: []string{"a", "b"}}

	loadExpectedFile(t, path, true, want)

	var got sample
	loadExpectedFile(t, path, false, &got)
	if got.Name != want.Name || got.Count != want.Count || len(got.Tags) != len(want.Tags) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestRootIsRepositoryRoot(t *testing.T) {
	dir := root()
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("root() returned an unusable path %q: %v", dir, err)
	}
}
