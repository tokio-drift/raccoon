package intel

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
)

// ErrNotFound is returned when no verdict is found for the given SHA-256.
var ErrNotFound = errors.New("intel: verdict not found")

// Store represents the persistence layer for verdicts.
// The *store.DB type satisfies this interface.
type Store interface {
	Verdicts(sha string) ([]model.Verdict, error)
	UpsertVerdict(v model.Verdict) error
}

// Cache provides caching of reputation verdicts backed by the SQLite verdicts
// table, enforcing a time-to-live (TTL).
type Cache struct {
	mu    sync.RWMutex
	store Store
	ttl   time.Duration
	mem   map[string]model.Verdict
	now   func() time.Time
}

// NewCache constructs a Cache backed by store with the given TTL.
// If ttl <= 0, limits.VerdictCacheTTL (7 days) is used.
// store may be nil (in which case the cache operates purely in-memory).
func NewCache(store Store, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = limits.VerdictCacheTTL
	}
	return &Cache{
		store: store,
		ttl:   ttl,
		mem:   make(map[string]model.Verdict),
		now:   time.Now,
	}
}

// cacheKey formats a compound key for the in-memory cache map.
func cacheKey(sha256, source string) string {
	return sha256 + ":" + source
}

// Get looks up a cached verdict for the given file SHA-256 and source (e.g. "virustotal", "yara").
// It checks in-memory cache first, then falls back to the database.
// If a verdict exists but has expired according to the TTL, it returns (model.Verdict{}, false, nil).
// If a fresh verdict is found, it returns (verdict, true, nil).
// If not found, it returns (model.Verdict{}, false, nil).
func (c *Cache) Get(sha256, source string) (model.Verdict, bool, error) {
	key := cacheKey(sha256, source)

	// 1. Check in-memory cache.
	c.mu.RLock()
	v, ok := c.mem[key]
	c.mu.RUnlock()

	if ok {
		if c.IsFresh(v) {
			return v, true, nil
		}
		// Expired: delete from in-memory cache.
		c.mu.Lock()
		delete(c.mem, key)
		c.mu.Unlock()
	}

	// 2. Query persistent store if available.
	if c.store == nil {
		return model.Verdict{}, false, nil
	}

	verdicts, err := c.store.Verdicts(sha256)
	if err != nil {
		return model.Verdict{}, false, fmt.Errorf("intel: cache get: %w", err)
	}

	for _, candidate := range verdicts {
		if candidate.Source == source {
			if c.IsFresh(candidate) {
				// Populate in-memory cache.
				c.mu.Lock()
				c.mem[key] = candidate
				c.mu.Unlock()
				return candidate, true, nil
			}
			// Verdict exists in DB but is expired.
			return model.Verdict{}, false, nil
		}
	}

	return model.Verdict{}, false, nil
}

// Put writes a verdict to the cache and the persistent store.
// If v.CheckedAt is 0, it is populated with the current Unix nanoseconds.
func (c *Cache) Put(v model.Verdict) error {
	if v.CheckedAt <= 0 {
		v.CheckedAt = c.now().UnixNano()
	}

	key := cacheKey(v.SHA256, v.Source)
	c.mu.Lock()
	c.mem[key] = v
	c.mu.Unlock()

	if c.store != nil {
		if err := c.store.UpsertVerdict(v); err != nil {
			return fmt.Errorf("intel: cache put: %w", err)
		}
	}
	return nil
}

// IsFresh reports whether a verdict is still within the cache TTL.
func (c *Cache) IsFresh(v model.Verdict) bool {
	if v.CheckedAt <= 0 {
		return false
	}
	now := c.now().UnixNano()
	age := time.Duration(now - v.CheckedAt)
	return age >= 0 && age <= c.ttl
}

// TTL returns the configured cache time-to-live.
func (c *Cache) TTL() time.Duration {
	return c.ttl
}
