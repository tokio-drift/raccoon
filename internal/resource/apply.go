package resource

import (
	"runtime/debug"
)

// Apply applies the resource budget to the Go runtime by setting the soft
// memory limit via debug.SetMemoryLimit to budget.MaxMem. It returns the
// previously set memory limit.
// If budget is nil or budget.MaxMem <= 0, Apply does not modify the runtime
// limit and returns -1.
func Apply(budget *Budget) int64 {
	if budget == nil || budget.MaxMem <= 0 {
		return -1
	}
	return debug.SetMemoryLimit(budget.MaxMem)
}

// Apply applies the budget to the Go runtime. It is equivalent to
// resource.Apply(b).
func (b *Budget) Apply() int64 {
	return Apply(b)
}
