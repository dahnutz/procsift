//go:build linux

package collect

import (
	"fmt"
	"path/filepath"
	"strconv"
)

// discoverFocused reads one process and at most eight parents.
// The rest of the host process list is not inventoried.
func (c *collector) discoverFocused(pid int) error {
	c.snap.Limits = append(c.snap.Limits, fmt.Sprintf("Follow-up scan inventories pid %d and at most eight observed parents. Selected host file, socket, module, shared-memory, and host-signal checks still run; other processes were not inventoried.", pid))
	seen := map[int]struct{}{}
	cur := pid
	for n := 0; n < 9 && cur > 0; n++ {
		if _, ok := seen[cur]; ok {
			break
		}
		seen[cur] = struct{}{}
		p, err := c.readProcess(cur)
		if err != nil {
			if cur == pid {
				return fmt.Errorf("pid %d: %w", pid, err)
			}
			c.issue(filepath.Join(c.proc, strconv.Itoa(cur)), err)
			break
		}
		p.Listed = true
		c.snap.Processes = append(c.snap.Processes, p)
		if p.PPID == 0 || p.PPID == cur {
			break
		}
		cur = p.PPID
	}
	return nil
}
