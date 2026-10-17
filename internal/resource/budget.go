package resource

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
)

// Minimum memory budget (256 MB).
const minMemBytes int64 = 256 * 1024 * 1024

// Category names for per-pool accounting.
const (
	// CatStreamBuffers is the memory pool for TCP reassembly pending buffers.
	CatStreamBuffers = "stream_buffers"
	// CatDecodeBuffers is the memory pool for decode and HTTP decompression buffers.
	CatDecodeBuffers = "decode_buffers"
	// CatStoreBatches is the memory pool for store write batches.
	CatStoreBatches = "store_batches"
	// CatHeadroom is reserved headroom that is not allocated to any pool.
	CatHeadroom = "headroom"
)

// Budget share fractions (sum = 1.0).
const (
	shareStreamBuffers = 0.40
	shareDecodeBuffers = 0.15
	shareStoreBatches  = 0.15
	shareHeadroom      = 0.30
)

// Sentinel errors.
var (
	// ErrMemTooLow is returned when the requested memory budget is below the minimum (256 MB).
	ErrMemTooLow = errors.New("memory budget must be at least 256 MB")
	// ErrWorkersInvalid is returned when the worker count is less than 1.
	ErrWorkersInvalid = errors.New("workers must be at least 1")
	// ErrInvalidSize is returned when ParseSize cannot parse the input string.
	ErrInvalidSize = errors.New("invalid size string")
)

// Budget holds the resource limits for an analysis run.
type Budget struct {
	// MaxMem is the maximum memory budget in bytes.
	MaxMem int64
	// MaxDisk is the maximum disk budget in bytes (0 = unlimited).
	MaxDisk int64
	// Workers is the number of worker goroutines.
	Workers int

	// Derived per-category pool caps.
	StreamBuffersCap int64
	DecodeBuffersCap int64
	StoreBatchesCap  int64
	HeadroomCap      int64
}

// NewBudget creates a validated Budget with derived per-category pool caps.
// maxMem must be at least 256 MB; maxDisk of 0 means unlimited; workers must
// be at least 1.
func NewBudget(maxMem, maxDisk int64, workers int) (*Budget, error) {
	if maxMem < minMemBytes {
		return nil, fmt.Errorf("%w: got %d bytes (%s)", ErrMemTooLow, maxMem, FormatSize(maxMem))
	}
	if workers < 1 {
		return nil, fmt.Errorf("%w: got %d", ErrWorkersInvalid, workers)
	}

	b := &Budget{
		MaxMem:  maxMem,
		MaxDisk: maxDisk,
		Workers: workers,
	}
	b.StreamBuffersCap = int64(float64(maxMem) * shareStreamBuffers)
	b.DecodeBuffersCap = int64(float64(maxMem) * shareDecodeBuffers)
	b.StoreBatchesCap = int64(float64(maxMem) * shareStoreBatches)
	b.HeadroomCap = maxMem - b.StreamBuffersCap - b.DecodeBuffersCap - b.StoreBatchesCap

	return b, nil
}

// ParseSize parses a human-readable size string such as "512MB", "2GB", or
// "1024KB". The supported suffixes are KB, MB, and GB (case-insensitive) using
// base 1024. A bare number (no suffix) is interpreted as bytes.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("%w: empty string", ErrInvalidSize)
	}

	upper := strings.ToUpper(s)
	var suffix string
	var multiplier int64

	switch {
	case strings.HasSuffix(upper, "GB"):
		suffix = upper[:len(upper)-2]
		multiplier = 1024 * 1024 * 1024
	case strings.HasSuffix(upper, "MB"):
		suffix = upper[:len(upper)-2]
		multiplier = 1024 * 1024
	case strings.HasSuffix(upper, "KB"):
		suffix = upper[:len(upper)-2]
		multiplier = 1024
	default:
		// Bare number interpreted as bytes.
		suffix = upper
		multiplier = 1
	}

	suffix = strings.TrimSpace(suffix)
	if suffix == "" {
		return 0, fmt.Errorf("%w: missing numeric part in %q", ErrInvalidSize, s)
	}

	n, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q: %v", ErrInvalidSize, s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("%w: negative size %q", ErrInvalidSize, s)
	}

	return n * multiplier, nil
}

// FormatSize returns a human-readable string for a byte count.
func FormatSize(n int64) string {
	const (
		gb = 1024 * 1024 * 1024
		mb = 1024 * 1024
		kb = 1024
	)
	switch {
	case n >= gb && n%gb == 0:
		return fmt.Sprintf("%dGB", n/gb)
	case n >= mb && n%mb == 0:
		return fmt.Sprintf("%dMB", n/mb)
	case n >= kb && n%kb == 0:
		return fmt.Sprintf("%dKB", n/kb)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// Accountant tracks memory usage for a single category pool using atomic
// counters. It is safe for concurrent use.
type Accountant struct {
	name string
	used atomic.Int64
	cap  int64
}

// NewAccountant returns an Accountant for the given category with the specified
// capacity in bytes. The name is used for diagnostic purposes.
func NewAccountant(name string, cap int64) *Accountant {
	return &Accountant{
		name: name,
		cap:  cap,
	}
}

// Reserve tries to reserve n bytes. It returns true if the reservation
// succeeded (used + n <= cap) or false if it would exceed the cap. On failure,
// no bytes are reserved. n must be positive.
func (a *Accountant) Reserve(n int64) bool {
	for {
		cur := a.used.Load()
		if cur+n > a.cap {
			return false
		}
		if a.used.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// Release frees n previously reserved bytes. The caller must not release more
// than was reserved.
func (a *Accountant) Release(n int64) {
	a.used.Add(-n)
}

// Used returns the number of bytes currently reserved.
func (a *Accountant) Used() int64 {
	return a.used.Load()
}

// Cap returns the capacity of this pool in bytes.
func (a *Accountant) Cap() int64 {
	return a.cap
}

// Name returns the category name of this pool.
func (a *Accountant) Name() string {
	return a.name
}

// NewAccountants returns per-category Accountant instances derived from the
// Budget. The headroom pool is included for completeness but is typically not
// drawn from.
func (b *Budget) NewAccountants() map[string]*Accountant {
	return map[string]*Accountant{
		CatStreamBuffers: NewAccountant(CatStreamBuffers, b.StreamBuffersCap),
		CatDecodeBuffers: NewAccountant(CatDecodeBuffers, b.DecodeBuffersCap),
		CatStoreBatches:  NewAccountant(CatStoreBatches, b.StoreBatchesCap),
		CatHeadroom:      NewAccountant(CatHeadroom, b.HeadroomCap),
	}
}
