//go:build linux

package collect

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/dahnutz/procsift/internal/model"
)

const maxCorrelationCount = 16
const maxCorrelationTotal = 64 << 20

// correlateChangedFiles links altered critical utilities to live, dpkg-unlisted
// root images using full SHA-256 digests. It does not collect executable bytes.
func (c *collector) correlateChangedFiles() {
	changed := map[string][]string{}
	for _, file := range c.snap.FileChecks {
		if file.State == "mismatch" && file.SHA256 != "" {
			changed[file.SHA256] = append(changed[file.SHA256], file.Path)
		}
	}
	if len(changed) == 0 {
		return
	}
	cache := map[string]string{}
	var used int64
	count := 0
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if p.UID != 0 || p.Image == nil || p.Image.State != "unlisted" || p.StartTicks == 0 {
			continue
		}
		if count >= maxCorrelationCount || used >= maxCorrelationTotal {
			c.snap.Limits = append(c.snap.Limits, "Changed-file correlation stopped at 16 process images or 64 MiB; later root images remain uncorrelated.")
			break
		}
		count++
		path := filepath.Join(c.proc, strconv.Itoa(p.PID), "exe")
		dev, ino, _, size, err := statFollow(path)
		if err != nil {
			c.issue(path, err)
			continue
		}
		if size > maxImageBytes || size > maxCorrelationTotal-used {
			c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: path, State: "unavailable", Detail: "full-image correlation skipped at the 32 MiB per-image or 64 MiB total budget"})
			continue
		}
		key := fmt.Sprintf("%d:%d", dev, ino)
		sum, cached := cache[key]
		if !cached {
			var n int64
			var state string
			sum, n, state, err = hashFile(path, maxImageBytes)
			used += n
			if err != nil || state != "complete" || n != size {
				c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: path, State: "unavailable", Detail: "full-image correlation read was incomplete"})
				continue
			}
			cache[key] = sum
		}
		ticks, afterDev, afterIno, afterPID, ok := c.recheck(p.PID)
		if !ok || afterPID != p.PID || ticks != p.StartTicks || dev != afterDev || ino != afterIno {
			c.changed(path, "process identity changed during full-image correlation")
			continue
		}
		p.Image.SHA256 = sum
		p.Image.MatchedFiles = append(p.Image.MatchedFiles, changed[sum]...)
	}
}
