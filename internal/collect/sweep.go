//go:build linux

package collect

import (
	"context"
	"time"
)

type probeResult struct {
	Alive      []int
	Probed     int
	Complete   bool
	Unreliable bool
	StopReason string
}

func probeTasks(pidMax, maxProbes int, timeout time.Duration) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return probeTasksContext(ctx, pidMax, maxProbes, killExists)
}

// One worker bounds concurrent pressure on the host. The probe count is a hard
// limit, and cancellation is checked before each syscall. No signal is sent.
func probeTasksContext(ctx context.Context, pidMax, maxProbes int, exists func(int) bool) probeResult {
	var result probeResult
	for pid := 1; pid < pidMax; pid++ {
		if result.Probed >= maxProbes {
			result.StopReason = "probe budget reached"
			break
		}
		if err := ctx.Err(); err != nil {
			result.StopReason = err.Error()
			break
		}
		if exists(pid) {
			result.Alive = append(result.Alive, pid)
		}
		result.Probed++
	}
	result.Complete = result.Probed >= pidMax-1
	result.Unreliable = len(result.Alive) > 100000 && len(result.Alive)*4 > result.Probed
	return result
}
