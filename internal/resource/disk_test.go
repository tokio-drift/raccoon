package resource

import (
	"sync"
	"testing"
)

func TestDiskCounterUnlimited(t *testing.T) {
	d := NewDiskCounter(0)

	if d.MaxDisk() != 0 {
		t.Errorf("MaxDisk = %d, want 0", d.MaxDisk())
	}
	if d.Exceeded() {
		t.Error("Exceeded() = true on empty unlimited counter, want false")
	}

	d.AddSpool(1000)
	if d.Spool() != 1000 {
		t.Errorf("Spool = %d, want 1000", d.Spool())
	}
	if d.Carved() != 0 {
		t.Errorf("Carved = %d, want 0", d.Carved())
	}
	if d.Total() != 1000 {
		t.Errorf("Total = %d, want 1000", d.Total())
	}
	if d.Exceeded() {
		t.Error("Exceeded() = true on unlimited counter after AddSpool, want false")
	}
	if d.WouldExceed(1000000) {
		t.Error("WouldExceed() = true on unlimited counter, want false")
	}

	d.AddCarved(2500)
	if d.Spool() != 1000 {
		t.Errorf("Spool = %d, want 1000", d.Spool())
	}
	if d.Carved() != 2500 {
		t.Errorf("Carved = %d, want 2500", d.Carved())
	}
	if d.Total() != 3500 {
		t.Errorf("Total = %d, want 3500", d.Total())
	}
	if d.Exceeded() {
		t.Error("Exceeded() = true on unlimited counter after AddCarved, want false")
	}

	d.Reset()
	if d.Total() != 0 || d.Spool() != 0 || d.Carved() != 0 {
		t.Errorf("after Reset: Spool=%d, Carved=%d, Total=%d", d.Spool(), d.Carved(), d.Total())
	}
}

func TestDiskCounterLimited(t *testing.T) {
	const limit = 1000
	d := NewDiskCounter(limit)

	if d.MaxDisk() != limit {
		t.Errorf("MaxDisk = %d, want %d", d.MaxDisk(), limit)
	}

	d.AddSpool(500)
	if d.Exceeded() {
		t.Errorf("Exceeded() = true at 500/%d, want false", limit)
	}
	if d.WouldExceed(499) {
		t.Errorf("WouldExceed(499) = true at 500/%d (sum 999), want false", limit)
	}
	if !d.WouldExceed(500) {
		t.Errorf("WouldExceed(500) = false at 500/%d (sum 1000), want true", limit)
	}

	d.AddCarved(499)
	if d.Total() != 999 {
		t.Errorf("Total = %d, want 999", d.Total())
	}
	if d.Exceeded() {
		t.Errorf("Exceeded() = true at 999/%d, want false", limit)
	}

	// Exactly reaching limit triggers Exceeded.
	d.AddCarved(1)
	if d.Total() != 1000 {
		t.Errorf("Total = %d, want 1000", d.Total())
	}
	if !d.Exceeded() {
		t.Errorf("Exceeded() = false at 1000/%d, want true", limit)
	}

	// Surpassing limit remains Exceeded.
	d.AddSpool(200)
	if d.Total() != 1200 {
		t.Errorf("Total = %d, want 1200", d.Total())
	}
	if !d.Exceeded() {
		t.Errorf("Exceeded() = false at 1200/%d, want true", limit)
	}

	// Decrement below limit clears Exceeded.
	d.AddSpool(-300)
	if d.Total() != 900 {
		t.Errorf("Total = %d, want 900", d.Total())
	}
	if d.Exceeded() {
		t.Errorf("Exceeded() = true at 900/%d, want false", limit)
	}
}

func TestBudgetNewDiskCounter(t *testing.T) {
	b, err := NewBudget(512*1024*1024, 10*1024*1024*1024, 4)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}

	d := b.NewDiskCounter()
	if d.MaxDisk() != b.MaxDisk {
		t.Errorf("d.MaxDisk() = %d, want %d", d.MaxDisk(), b.MaxDisk)
	}
}

func TestDiskCounterConcurrent(t *testing.T) {
	const (
		limit        int64 = 1000000
		goroutines         = 16
		opsPerWorker       = 1000
		chunkSize    int64 = 50
	)

	d := NewDiskCounter(limit)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				if g%2 == 0 {
					d.AddSpool(chunkSize)
				} else {
					d.AddCarved(chunkSize)
				}
				_ = d.Total()
				_ = d.Exceeded()
			}
		}()
	}

	wg.Wait()

	expectedSpool := int64(goroutines/2) * opsPerWorker * chunkSize
	expectedCarved := int64(goroutines/2) * opsPerWorker * chunkSize
	expectedTotal := expectedSpool + expectedCarved

	if d.Spool() != expectedSpool {
		t.Errorf("final Spool = %d, want %d", d.Spool(), expectedSpool)
	}
	if d.Carved() != expectedCarved {
		t.Errorf("final Carved = %d, want %d", d.Carved(), expectedCarved)
	}
	if d.Total() != expectedTotal {
		t.Errorf("final Total = %d, want %d", d.Total(), expectedTotal)
	}
	if d.Exceeded() != (expectedTotal >= limit) {
		t.Errorf("Exceeded() = %v, want %v", d.Exceeded(), expectedTotal >= limit)
	}
}
