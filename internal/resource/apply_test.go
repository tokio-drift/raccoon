package resource

import (
	"runtime/debug"
	"testing"
)

func TestApply(t *testing.T) {
	// Query current memory limit without modifying it.
	orig := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		debug.SetMemoryLimit(orig)
	})

	b, err := NewBudget(512*1024*1024, 0, 2)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}

	prev := Apply(b)
	if prev != orig {
		t.Errorf("Apply returned prev %d, want %d", prev, orig)
	}

	cur := debug.SetMemoryLimit(-1)
	if cur != b.MaxMem {
		t.Errorf("memory limit after Apply = %d, want %d", cur, b.MaxMem)
	}

	// Method syntax b.Apply()
	b2, err := NewBudget(1024*1024*1024, 0, 4)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	prev2 := b2.Apply()
	if prev2 != b.MaxMem {
		t.Errorf("b2.Apply returned prev %d, want %d", prev2, b.MaxMem)
	}
	cur2 := debug.SetMemoryLimit(-1)
	if cur2 != b2.MaxMem {
		t.Errorf("memory limit after b2.Apply = %d, want %d", cur2, b2.MaxMem)
	}

	// Nil budget
	if got := Apply(nil); got != -1 {
		t.Errorf("Apply(nil) = %d, want -1", got)
	}
}
