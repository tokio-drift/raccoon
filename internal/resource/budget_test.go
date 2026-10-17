package resource

import (
	"errors"
	"math"
	"sync"
	"testing"
)

// ParseSize
func TestParseSizeValid(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"512MB", 512 * 1024 * 1024},
		{"512mb", 512 * 1024 * 1024},
		{"512Mb", 512 * 1024 * 1024},
		{"2GB", 2 * 1024 * 1024 * 1024},
		{"2gb", 2 * 1024 * 1024 * 1024},
		{"1024KB", 1024 * 1024},
		{"1024kb", 1024 * 1024},
		{"256", 256},
		{"0", 0},
		{"0MB", 0},
		{"  512MB  ", 512 * 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseSize(tt.input)
			if err != nil {
				t.Fatalf("ParseSize(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSizeInvalid(t *testing.T) {
	tests := []string{
		"",
		"MB",
		"abc",
		"12XB",
		"-1MB",
		"1.5GB",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := ParseSize(input)
			if err == nil {
				t.Fatalf("ParseSize(%q) should have returned an error", input)
			}
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("ParseSize(%q) error = %v; want ErrInvalidSize", input, err)
			}
		})
	}
}

// FormatSize
func TestFormatSize(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0"},
		{1024, "1KB"},
		{1024 * 1024, "1MB"},
		{512 * 1024 * 1024, "512MB"},
		{2 * 1024 * 1024 * 1024, "2GB"},
		{1500, "1500"},
		{1024*1024 + 1, "1048577"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatSize(tt.input)
			if got != tt.want {
				t.Errorf("FormatSize(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// NewBudget
func TestNewBudgetValid(t *testing.T) {
	b, err := NewBudget(2*1024*1024*1024, 0, 4)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	if b.MaxMem != 2*1024*1024*1024 {
		t.Errorf("MaxMem = %d, want %d", b.MaxMem, 2*1024*1024*1024)
	}
	if b.MaxDisk != 0 {
		t.Errorf("MaxDisk = %d, want 0", b.MaxDisk)
	}
	if b.Workers != 4 {
		t.Errorf("Workers = %d, want 4", b.Workers)
	}

	// Check derived shares sum to MaxMem.
	sum := b.StreamBuffersCap + b.DecodeBuffersCap + b.StoreBatchesCap + b.HeadroomCap
	if sum != b.MaxMem {
		t.Errorf("shares sum %d != MaxMem %d", sum, b.MaxMem)
	}

	// Check approximate percentages (within 1 byte of rounding).
	expectStream := int64(float64(b.MaxMem) * 0.40)
	expectDecode := int64(float64(b.MaxMem) * 0.15)
	expectStore := int64(float64(b.MaxMem) * 0.15)

	if b.StreamBuffersCap != expectStream {
		t.Errorf("StreamBuffersCap = %d, want ~%d", b.StreamBuffersCap, expectStream)
	}
	if b.DecodeBuffersCap != expectDecode {
		t.Errorf("DecodeBuffersCap = %d, want ~%d", b.DecodeBuffersCap, expectDecode)
	}
	if b.StoreBatchesCap != expectStore {
		t.Errorf("StoreBatchesCap = %d, want ~%d", b.StoreBatchesCap, expectStore)
	}
}

func TestNewBudgetMinimum(t *testing.T) {
	// Exactly 256 MB should succeed.
	b, err := NewBudget(256*1024*1024, 0, 1)
	if err != nil {
		t.Fatalf("NewBudget(256MB) should succeed: %v", err)
	}
	if b.MaxMem != 256*1024*1024 {
		t.Errorf("MaxMem = %d, want %d", b.MaxMem, 256*1024*1024)
	}
}

func TestNewBudgetMemTooLow(t *testing.T) {
	_, err := NewBudget(128*1024*1024, 0, 4)
	if err == nil {
		t.Fatal("NewBudget with 128MB should fail")
	}
	if !errors.Is(err, ErrMemTooLow) {
		t.Errorf("error = %v; want ErrMemTooLow", err)
	}
}

func TestNewBudgetWorkersInvalid(t *testing.T) {
	_, err := NewBudget(512*1024*1024, 0, 0)
	if err == nil {
		t.Fatal("NewBudget with 0 workers should fail")
	}
	if !errors.Is(err, ErrWorkersInvalid) {
		t.Errorf("error = %v; want ErrWorkersInvalid", err)
	}

	_, err = NewBudget(512*1024*1024, 0, -1)
	if err == nil {
		t.Fatal("NewBudget with -1 workers should fail")
	}
	if !errors.Is(err, ErrWorkersInvalid) {
		t.Errorf("error = %v; want ErrWorkersInvalid", err)
	}
}

func TestNewBudgetDiskUnlimited(t *testing.T) {
	b, err := NewBudget(512*1024*1024, 0, 2)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	if b.MaxDisk != 0 {
		t.Errorf("MaxDisk = %d, want 0 (unlimited)", b.MaxDisk)
	}
}

func TestNewBudgetDiskLimited(t *testing.T) {
	b, err := NewBudget(512*1024*1024, 10*1024*1024*1024, 2)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	if b.MaxDisk != 10*1024*1024*1024 {
		t.Errorf("MaxDisk = %d, want %d", b.MaxDisk, 10*1024*1024*1024)
	}
}

// Accountant
func TestAccountantReserveRelease(t *testing.T) {
	a := NewAccountant("test", 1000)

	if !a.Reserve(500) {
		t.Fatal("Reserve(500) should succeed")
	}
	if a.Used() != 500 {
		t.Errorf("Used = %d, want 500", a.Used())
	}

	if !a.Reserve(500) {
		t.Fatal("Reserve(500) should succeed (fills to cap)")
	}
	if a.Used() != 1000 {
		t.Errorf("Used = %d, want 1000", a.Used())
	}

	// Should fail: at cap.
	if a.Reserve(1) {
		t.Fatal("Reserve(1) should fail when at cap")
	}

	a.Release(200)
	if a.Used() != 800 {
		t.Errorf("Used = %d, want 800", a.Used())
	}

	if !a.Reserve(200) {
		t.Fatal("Reserve(200) should succeed after release")
	}
}

func TestAccountantReserveExceedsCap(t *testing.T) {
	a := NewAccountant("test", 100)

	// Single reservation exceeding cap.
	if a.Reserve(101) {
		t.Fatal("Reserve(101) should fail on cap 100")
	}
	if a.Used() != 0 {
		t.Errorf("Used = %d, want 0 after failed reserve", a.Used())
	}
}

func TestAccountantName(t *testing.T) {
	a := NewAccountant(CatStreamBuffers, 1024)
	if a.Name() != CatStreamBuffers {
		t.Errorf("Name = %q, want %q", a.Name(), CatStreamBuffers)
	}
}

func TestAccountantCap(t *testing.T) {
	a := NewAccountant("test", 4096)
	if a.Cap() != 4096 {
		t.Errorf("Cap = %d, want 4096", a.Cap())
	}
}

// TestAccountantConcurrent exercises Reserve and Release from many goroutines
// under the race detector. The invariant is that Used never exceeds Cap and
// ends at zero.
func TestAccountantConcurrent(t *testing.T) {
	const (
		cap          int64 = 10000
		goroutines         = 16
		opsPerWorker       = 1000
		chunkSize    int64 = 10
	)

	a := NewAccountant("concurrent", cap)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				if a.Reserve(chunkSize) {
					// Check invariant: Used should never exceed Cap.
					u := a.Used()
					if u > cap {
						t.Errorf("Used %d exceeds cap %d", u, cap)
					}
					a.Release(chunkSize)
				}
			}
		}()
	}

	wg.Wait()

	if a.Used() != 0 {
		t.Errorf("final Used = %d, want 0", a.Used())
	}
}

// TestAccountantConcurrentSaturation runs many goroutines that each try to
// reserve a large chunk, hold it briefly, and release it. This stresses the
// CAS loop under contention.
func TestAccountantConcurrentSaturation(t *testing.T) {
	const (
		cap        int64 = 1024
		goroutines       = 32
		iterations       = 500
		chunk      int64 = 128
	)

	a := NewAccountant("saturate", cap)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	reserved := make([]int64, goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if a.Reserve(chunk) {
					reserved[g] += chunk
					a.Release(chunk)
					reserved[g] -= chunk
				}
			}
		}()
	}

	wg.Wait()

	for g, r := range reserved {
		if r != 0 {
			t.Errorf("goroutine %d leaked %d bytes", g, r)
		}
	}
	if a.Used() != 0 {
		t.Errorf("final Used = %d, want 0", a.Used())
	}
}

// NewAccountants (per-category pools from Budget)
func TestNewAccountants(t *testing.T) {
	b, err := NewBudget(1024*1024*1024, 0, 4)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}

	accs := b.NewAccountants()
	categories := []string{CatStreamBuffers, CatDecodeBuffers, CatStoreBatches, CatHeadroom}
	for _, cat := range categories {
		a, ok := accs[cat]
		if !ok {
			t.Errorf("missing category %q", cat)
			continue
		}
		if a.Cap() <= 0 {
			t.Errorf("category %q has cap %d, want > 0", cat, a.Cap())
		}
		if a.Name() != cat {
			t.Errorf("category %q has name %q", cat, a.Name())
		}
	}

	// Sum of caps should equal MaxMem.
	var sum int64
	for _, a := range accs {
		sum += a.Cap()
	}
	if sum != b.MaxMem {
		t.Errorf("sum of pool caps %d != MaxMem %d", sum, b.MaxMem)
	}
}

// Shares add up correctly for various budget sizes
func TestSharesAddUp(t *testing.T) {
	sizes := []int64{
		256 * 1024 * 1024,
		512 * 1024 * 1024,
		1024 * 1024 * 1024,
		2 * 1024 * 1024 * 1024,
		4 * 1024 * 1024 * 1024,
	}
	for _, mem := range sizes {
		t.Run(FormatSize(mem), func(t *testing.T) {
			b, err := NewBudget(mem, 0, 4)
			if err != nil {
				t.Fatalf("NewBudget: %v", err)
			}
			sum := b.StreamBuffersCap + b.DecodeBuffersCap + b.StoreBatchesCap + b.HeadroomCap
			if sum != mem {
				t.Errorf("shares sum %d != MaxMem %d (diff %d)", sum, mem, int64(math.Abs(float64(sum-mem))))
			}
		})
	}
}

// Accountant satisfies the reassembly.Accountant interface shape

// accountantIface mirrors the interface defined in internal/reassembly to
// verify compatibility at compile time.
type accountantIface interface {
	Reserve(n int64) bool
	Release(n int64)
}

var _ accountantIface = (*Accountant)(nil)
