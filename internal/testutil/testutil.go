package testutil

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// update, when passed to `go test` as -update, rewrites golden files with the
// current value instead of comparing against them.
var update = flag.Bool("update", false, "update golden files")

// root returns the absolute path of the repository root, derived from the
// location of this source file.
func root() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("testutil: cannot determine source location")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// Pcap returns the absolute path to testdata/<name>, failing the test if the
// fixture does not exist.
func Pcap(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(root(), "testdata", name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("testutil: testdata fixture %q: %v", name, err)
	}
	return path
}

// LoadExpected loads testdata/expected/<name> as JSON into v. With the -update
// flag it writes the current value of v to that path instead.
func LoadExpected(t *testing.T, name string, v any) {
	t.Helper()
	path := filepath.Join(root(), "testdata", "expected", name)
	loadExpectedFile(t, path, *update, v)
}

// Updating reports whether tests are running with -update. Tests that seed the
// value handed to LoadExpected must only do so when Updating is true: seeding
// it during a comparison run would let json.Unmarshal merge the decoded golden
// into live structs and maps.
func Updating() bool { return *update }

func loadExpectedFile(t *testing.T, path string, update bool, v any) {
	t.Helper()
	if update {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatalf("testutil: marshal golden %s: %v", path, err)
		}
		data = append(data, '\n')
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("testutil: create golden dir: %v", err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("testutil: write golden %s: %v", path, err)
		}
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("testutil: read golden %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("testutil: decode golden %s: %v", path, err)
	}
}
