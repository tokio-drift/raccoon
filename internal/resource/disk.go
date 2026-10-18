package resource

import (
	"sync/atomic"
)

// DiskCounter tracks disk usage for stream spool files and carved files against
// an optional maximum disk limit. A MaxDisk value of 0 indicates unlimited disk
// usage. DiskCounter is safe for concurrent use across multiple goroutines.
type DiskCounter struct {
	maxDisk     int64
	spoolBytes  atomic.Int64
	carvedBytes atomic.Int64
}

// NewDiskCounter returns a DiskCounter configured with the given maxDisk limit
// in bytes. A maxDisk of 0 means unlimited disk usage.
func NewDiskCounter(maxDisk int64) *DiskCounter {
	return &DiskCounter{
		maxDisk: maxDisk,
	}
}

// NewDiskCounter returns a DiskCounter configured with the budget's MaxDisk limit.
func (b *Budget) NewDiskCounter() *DiskCounter {
	return NewDiskCounter(b.MaxDisk)
}

// AddSpool records a change of n bytes in stream spool storage. n may be
// negative when spool storage is released or deleted.
func (d *DiskCounter) AddSpool(n int64) {
	d.spoolBytes.Add(n)
}

// AddCarved records a change of n bytes in carved file storage. n may be
// negative when carved files are deleted.
func (d *DiskCounter) AddCarved(n int64) {
	d.carvedBytes.Add(n)
}

// Spool returns the number of bytes currently stored in stream spools.
func (d *DiskCounter) Spool() int64 {
	return d.spoolBytes.Load()
}

// Carved returns the number of bytes currently stored in carved files.
func (d *DiskCounter) Carved() int64 {
	return d.carvedBytes.Load()
}

// Total returns the total disk usage in bytes (spool bytes + carved bytes).
func (d *DiskCounter) Total() int64 {
	return d.spoolBytes.Load() + d.carvedBytes.Load()
}

// MaxDisk returns the configured maximum disk limit in bytes (0 = unlimited).
func (d *DiskCounter) MaxDisk() int64 {
	return d.maxDisk
}

// Exceeded reports whether total disk usage has reached or exceeded MaxDisk.
// When MaxDisk is 0 (unlimited), Exceeded always returns false.
func (d *DiskCounter) Exceeded() bool {
	if d.maxDisk <= 0 {
		return false
	}
	return d.Total() >= d.maxDisk
}

// WouldExceed reports whether adding n bytes would cause total disk usage to
// reach or exceed MaxDisk. When MaxDisk is 0 (unlimited), it always returns false.
func (d *DiskCounter) WouldExceed(n int64) bool {
	if d.maxDisk <= 0 {
		return false
	}
	return d.Total()+n >= d.maxDisk
}

// Reset resets the spool and carved byte counters to zero.
func (d *DiskCounter) Reset() {
	d.spoolBytes.Store(0)
	d.carvedBytes.Store(0)
}
