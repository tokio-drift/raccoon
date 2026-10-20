package intel

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
)

type memStore struct {
	verdicts map[string][]model.Verdict
}

func newMemStore() *memStore {
	return &memStore{verdicts: make(map[string][]model.Verdict)}
}

func (m *memStore) Verdicts(sha string) ([]model.Verdict, error) {
	return m.verdicts[sha], nil
}

func (m *memStore) UpsertVerdict(v model.Verdict) error {
	list := m.verdicts[v.SHA256]
	for i, existing := range list {
		if existing.Source == v.Source {
			list[i] = v
			return nil
		}
	}
	m.verdicts[v.SHA256] = append(list, v)
	return nil
}

func TestCachePutGet(t *testing.T) {
	ms := newMemStore()
	cache := NewCache(ms, 24*time.Hour)

	now := time.Now().UnixNano()
	v := model.Verdict{
		SHA256:    "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000",
		Source:    "virustotal",
		Status:    "malicious",
		Score:     5,
		Total:     70,
		Detail:    map[string]any{"malicious": 5},
		CheckedAt: now,
	}

	if err := cache.Put(v); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok, err := cache.Get(v.SHA256, "virustotal")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected verdict to be found in cache")
	}
	if got.SHA256 != v.SHA256 || got.Status != "malicious" || got.Score != 5 {
		t.Errorf("got %+v, want %+v", got, v)
	}
}

func TestCacheExpiration(t *testing.T) {
	ms := newMemStore()
	ttl := 1 * time.Hour
	cache := NewCache(ms, ttl)

	baseTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return baseTime }

	v := model.Verdict{
		SHA256:    "222222223333444455556666777788889999aaaabbbbccccddddeeeeffff0000",
		Source:    "virustotal",
		Status:    "suspicious",
		CheckedAt: baseTime.UnixNano(),
	}

	if err := cache.Put(v); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// 1. Within TTL (30 minutes later) -> still fresh.
	cache.now = func() time.Time { return baseTime.Add(30 * time.Minute) }
	got, ok, err := cache.Get(v.SHA256, "virustotal")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok || got.Status != "suspicious" {
		t.Errorf("expected fresh verdict, got ok=%v, v=%+v", ok, got)
	}

	// 2. Past TTL (2 hours later) -> expired, returns false.
	cache.now = func() time.Time { return baseTime.Add(2 * time.Hour) }
	_, ok, err = cache.Get(v.SHA256, "virustotal")
	if err != nil {
		t.Fatalf("Get after expiry: %v", err)
	}
	if ok {
		t.Error("expected expired verdict to not be returned (ok=false)")
	}
}

func TestCacheNotFound(t *testing.T) {
	ms := newMemStore()
	cache := NewCache(ms, 24*time.Hour)

	_, ok, err := cache.Get("nonexistent", "virustotal")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Error("expected ok=false for non-existent SHA")
	}
}

func TestCacheDifferentSources(t *testing.T) {
	ms := newMemStore()
	cache := NewCache(ms, 24*time.Hour)

	sha := "333333333333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
	vVT := model.Verdict{
		SHA256:    sha,
		Source:    "virustotal",
		Status:    "no_detections",
		CheckedAt: time.Now().UnixNano(),
	}
	vYara := model.Verdict{
		SHA256:    sha,
		Source:    "yara",
		Status:    "malicious",
		CheckedAt: time.Now().UnixNano(),
	}

	if err := cache.Put(vVT); err != nil {
		t.Fatalf("Put VT: %v", err)
	}
	if err := cache.Put(vYara); err != nil {
		t.Fatalf("Put Yara: %v", err)
	}

	gotVT, ok, err := cache.Get(sha, "virustotal")
	if err != nil || !ok || gotVT.Status != "no_detections" {
		t.Errorf("VT verdict unexpected: ok=%v, got=%+v", ok, gotVT)
	}

	gotYara, ok, err := cache.Get(sha, "yara")
	if err != nil || !ok || gotYara.Status != "malicious" {
		t.Errorf("Yara verdict unexpected: ok=%v, got=%+v", ok, gotYara)
	}
}

func TestCacheZeroCheckedAtPopulated(t *testing.T) {
	cache := NewCache(nil, 24*time.Hour)

	v := model.Verdict{
		SHA256: "444444444444444455556666777788889999aaaabbbbccccddddeeeeffff0000",
		Source: "virustotal",
		Status: "malicious",
	}

	before := time.Now().UnixNano()
	if err := cache.Put(v); err != nil {
		t.Fatalf("Put: %v", err)
	}
	after := time.Now().UnixNano()

	got, ok, err := cache.Get(v.SHA256, "virustotal")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v, err=%v", ok, err)
	}
	if got.CheckedAt < before || got.CheckedAt > after {
		t.Errorf("CheckedAt %d not between %d and %d", got.CheckedAt, before, after)
	}
}

func TestCacheWithRealStoreDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	cache := NewCache(db, 24*time.Hour)

	sha := "555555555555555555556666777788889999aaaabbbbccccddddeeeeffff0000"
	v := model.Verdict{
		SHA256:    sha,
		Source:    "virustotal",
		Status:    "malicious",
		Score:     10,
		Total:     72,
		Detail:    map[string]any{"threat": "trojan"},
		CheckedAt: time.Now().UnixNano(),
	}

	if err := cache.Put(v); err != nil {
		t.Fatalf("cache.Put: %v", err)
	}

	// Create a new fresh Cache instance pointing to the same DB to ensure
	// retrieval hits the persistent SQLite store, not just in-memory map.
	cache2 := NewCache(db, 24*time.Hour)
	got, ok, err := cache2.Get(sha, "virustotal")
	if err != nil {
		t.Fatalf("cache2.Get: %v", err)
	}
	if !ok {
		t.Fatal("expected verdict to be fetched from SQLite store")
	}
	if got.SHA256 != sha || got.Status != "malicious" || got.Score != 10 {
		t.Errorf("got %+v, want %+v", got, v)
	}
	if got.Detail["threat"] != "trojan" {
		t.Errorf("got detail %+v, want trojan", got.Detail)
	}
}
