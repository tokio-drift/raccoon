package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/resource"
	"github.com/tokio-drift/raccoon/internal/store"
)

// Benchmark100MB measures analysis throughput and resource consumption
// on the synthetic 100 MB capture (PLAN 13.2).
func Benchmark100MB(b *testing.B) {
	pcapPath := filepath.Join("..", "..", "testdata", "big", "big_100mb.pcap")
	if _, err := os.Stat(pcapPath); err != nil {
		b.Skip("testdata/big/big_100mb.pcap not found; run scripts/gen_big_pcap.go first")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tmpDir := b.TempDir()
		caseID := "20261028-120000-abcdef"
		c, err := casedir.Create(tmpDir, casedir.Options{
			ID:      caseID,
			PCAP:    pcapPath,
			Created: time.Now().UTC(),
		})
		if err != nil {
			b.Fatalf("casedir.Create: %v", err)
		}

		db, err := store.Open(c.DB())
		if err != nil {
			b.Fatalf("store.Open: %v", err)
		}

		budget, err := resource.NewBudget(2*1024*1024*1024, 0, 4)
		if err != nil {
			db.Close()
			b.Fatalf("NewBudget: %v", err)
		}

		b.StartTimer()
		res, err := Run(context.Background(), Options{
			PCAPPath:    pcapPath,
			Case:        c,
			Budget:      budget,
			Store:       db,
			Progress:    NewProgress(),
			MaxFileSize: limits.MaxCarveSize,
		})
		b.StopTimer()

		db.Close()
		if err != nil {
			b.Fatalf("Run: %v", err)
		}
		if res.Packets == 0 {
			b.Fatalf("expected packets > 0, got 0")
		}
	}
}
