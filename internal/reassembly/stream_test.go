package reassembly

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/model"
)

var (
	_ StreamData = (*Spool)(nil)
	_ StreamData = (*Stream)(nil)
)

func TestStreamBasic(t *testing.T) {
	dir := t.TempDir()
	spool, err := NewSpool(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	s := NewStream(StreamConfig{ID: 1, Proto: "tcp", Spool: spool})
	s.AddPacket(model.C2S, 1000, decode.FlagSYN, nil, 0, 1)
	s.AddPacket(model.C2S, 1001, decode.FlagPSH|decode.FlagACK, []byte("GET"), 1, 2)
	s.AddPacket(model.S2C, 5000, decode.FlagSYN|decode.FlagACK, nil, 0, 3)
	s.AddPacket(model.S2C, 5001, decode.FlagPSH|decode.FlagACK, []byte("OK"), 1, 4)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if got := s.Len(model.C2S); got != 3 {
		t.Fatalf("c2s len=%d", got)
	}
	if got := readAll(t, s.ReaderAt(model.C2S), s.Len(model.C2S)); string(got) != "GET" {
		t.Fatalf("c2s=%q", got)
	}
	if got := readAll(t, s.ReaderAt(model.S2C), s.Len(model.S2C)); string(got) != "OK" {
		t.Fatalf("s2c=%q", got)
	}
	if len(s.Gaps(model.C2S)) != 0 {
		t.Fatalf("unexpected gaps: %+v", s.Gaps(model.C2S))
	}
}

func TestStreamMidstream(t *testing.T) {
	dir := t.TempDir()
	spool, err := NewSpool(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	var got []Anomaly
	s := NewStream(StreamConfig{
		ID: 2, Proto: "tcp", Spool: spool, Midstream: true,
		OnAnomaly: func(a Anomaly) { got = append(got, a) },
	})
	s.AddPacket(model.C2S, 7000, decode.FlagPSH|decode.FlagACK, []byte("hi"), 0, 1)
	s.Close()
	if len(got) != 1 || got[0].Kind != AnomalyMidstream {
		t.Fatalf("anomalies=%+v", got)
	}
	if string(readAll(t, s.ReaderAt(model.C2S), s.Len(model.C2S))) != "hi" {
		t.Fatal("midstream data not reassembled")
	}
}

func TestSpoolSpill(t *testing.T) {
	dir := t.TempDir()
	spool, err := NewSpool(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	big := bytes.Repeat([]byte("abc"), (1<<20)/3+1000)
	if _, err := spool.Writer(model.C2S).Write(big); err != nil {
		t.Fatal(err)
	}
	if err := spool.Finalize(); err != nil {
		t.Fatal(err)
	}
	if spool.Len(model.C2S) != int64(len(big)) {
		t.Fatalf("len=%d want %d", spool.Len(model.C2S), len(big))
	}
	if got := readAll(t, spool.ReaderAt(model.C2S), spool.Len(model.C2S)); !bytes.Equal(got, big) {
		t.Fatal("spilled bytes mismatch")
	}
}

func TestSpoolFinalizePersistsMemory(t *testing.T) {
	dir := t.TempDir()
	spool, err := NewSpool(dir, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	if _, err := spool.Writer(model.C2S).Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	if err := spool.Finalize(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, streamFileName(4, model.C2S)))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "GET" {
		t.Fatalf("persisted bytes=%q", got)
	}
}

func readAll(t *testing.T, r io.ReaderAt, n int64) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return buf
}
