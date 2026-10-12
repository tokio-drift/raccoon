package casedir_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/reassembly"
)

const testID = "20260101-000000-000001"

func TestCreateOpen(t *testing.T) {
	base := t.TempDir()
	c, err := casedir.Create(base, casedir.Options{
		ID:      testID,
		PCAP:    "/tmp/x.pcap",
		Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Extra:   map[string]any{"k": "v"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != testID || c.Dir != filepath.Join(base, testID) {
		t.Fatalf("case=%+v", c)
	}

	for _, d := range []string{c.Dir, c.StreamsDir(), c.CarvedDir(), c.ReportsDir()} {
		st, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %o, want 700", d, st.Mode().Perm())
		}
	}

	mode, _ := os.Stat(c.Path(casedir.CaseJSON))
	if mode.Mode().Perm() != 0o600 {
		t.Errorf("case.json mode %o, want 600", mode.Mode().Perm())
	}

	opened, err := casedir.Open(c.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if opened.ID != testID || opened.Meta.PCAP != "/tmp/x.pcap" {
		t.Fatalf("opened=%+v", opened)
	}
	if opened.Meta.Options["k"] != "v" {
		t.Fatalf("options=%v", opened.Meta.Options)
	}
	if opened.Meta.Version == "" {
		t.Fatal("version missing")
	}

	if c.DB() != filepath.Join(c.Dir, "raccoon.db") ||
		c.PktIndex() != filepath.Join(c.Dir, "pktindex.bin") ||
		c.CarvedPath("abc123", "png") != filepath.Join(c.Dir, "carved", "abc123.png") {
		t.Fatal("helper paths wrong")
	}
}

func TestCreateInvalidID(t *testing.T) {
	base := t.TempDir()
	for _, id := range []string{"../evil", "a/b", "20260101-000000-zzzzzz", "20260101-000000", "x"} {
		if _, err := casedir.Create(base, casedir.Options{ID: id}); err == nil {
			t.Errorf("Create with id %q should fail", id)
		} else if !errorsIs(err, casedir.ErrInvalidID) {
			t.Errorf("Create %q: %v, want ErrInvalidID", id, err)
		}
	}
}

func TestRemove(t *testing.T) {
	base := t.TempDir()
	c, err := casedir.Create(base, casedir.Options{ID: testID})
	if err != nil {
		t.Fatal(err)
	}
	if err := casedir.Remove(base, testID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.Dir); !os.IsNotExist(err) {
		t.Fatalf("case dir still present: %v", err)
	}
	if err := casedir.Remove(base, "../x"); err == nil {
		t.Fatal("Remove with traversal id should fail")
	}
}

func TestList(t *testing.T) {
	base := t.TempDir()
	for _, id := range []string{"20250101-000000-000001", "20260101-000000-000001"} {
		if _, err := casedir.Create(base, casedir.Options{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(base, "not_a_case"), 0o700); err != nil {
		t.Fatal(err)
	}
	cases, err := casedir.List(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 {
		t.Fatalf("List=%d, want 2", len(cases))
	}
	if cases[0].ID != "20260101-000000-000001" {
		t.Fatalf("List not newest first: %s", cases[0].ID)
	}
}

// TestSpoolNaming keeps casedir and reassembly file names in lockstep.
func TestSpoolNaming(t *testing.T) {
	base := t.TempDir()
	c, err := casedir.Create(base, casedir.Options{ID: testID})
	if err != nil {
		t.Fatal(err)
	}
	spool, err := reassembly.NewSpool(c.StreamsDir(), 7)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	big := bytes.Repeat([]byte{'x'}, 1<<20+64)
	if _, err := spool.Writer(model.C2S).Write(big); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Writer(model.S2C).Write(big); err != nil {
		t.Fatal(err)
	}
	if err := spool.Finalize(); err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		filepath.Base(c.StreamPath(7, model.C2S)): true,
		filepath.Base(c.StreamPath(7, model.S2C)): true,
		filepath.Base(c.StreamIndex(7)):           true,
	}
	ents, err := os.ReadDir(c.StreamsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !want[e.Name()] {
			t.Errorf("unexpected spool file %q (want %v)", e.Name(), want)
		}
		delete(want, e.Name())
	}
	if len(want) != 0 {
		t.Errorf("spool files missing: %v", want)
	}
}

func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
