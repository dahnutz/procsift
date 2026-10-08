//go:build linux

package collect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/dahnutz/procsift/internal/explain"
	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/procfs"
)

const (
	maxImageBytes = 32 << 20
	maxImageTotal = 64 << 20
	maxImageCount = 64
)

type hashHit struct {
	sum  string
	n    int64
	full bool
	err  error
}

type hashBudget struct {
	bytes int64
	cache map[string]hashHit
}

func (c *collector) hashManifestFile(path string, budget *hashBudget) (string, int64, bool, error) {
	if budget.cache == nil {
		budget.cache = map[string]hashHit{}
	}
	if hit, ok := budget.cache[path]; ok {
		return hit.sum, hit.n, hit.full, hit.err
	}
	if budget.bytes >= maxImageTotal {
		hit := hashHit{err: explain.ErrHashBudget}
		budget.cache[path] = hit
		return "", 0, false, hit.err
	}
	sum, n, full, err := explain.MD5File(path, maxImageBytes)
	if n > 0 {
		budget.bytes += n
	}
	budget.cache[path] = hashHit{sum: sum, n: n, full: full, err: err}
	return sum, n, full, err
}

func (c *collector) checkImages(owned map[string]string, dbOK, pkgTrunc bool, manifests map[string]string, manTrunc bool) {
	if !dbOK && len(c.trusted) == 0 {
		c.snap.Limits = append(c.snap.Limits, "dpkg database was not readable. Package integrity and unpackaged-root checks are inconclusive.")
		return
	}
	seen := map[string]model.ImageCheck{}
	checked := 0
	var budget hashBudget
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if !explain.ShouldHashImage(p.UID, p.Exe, p.Kernel(), p.Zombie()) {
			continue
		}
		if !dbOK {
			if _, ok := c.trusted[p.Exe]; !ok {
				continue
			}
		}
		if checked >= maxImageCount {
			c.snap.Limits = append(c.snap.Limits, "Running-image checks stopped after 64 executables. Further images were not compared.")
			break
		}
		dev, ino, _, size, err := statFollow(filepath.Join(c.proc, strconv.Itoa(p.PID), "exe"))
		key := p.Exe
		if err == nil {
			key = fmt.Sprintf("%d:%d", dev, ino)
		}
		if prev, ok := seen[key]; ok {
			copy := prev
			p.Image = &copy
			continue
		}
		checked++
		item := c.oneImage(p, size, owned, pkgTrunc, manifests, manTrunc, &budget)
		seen[key] = item
		copy := item
		p.Image = &copy
	}
}

func (c *collector) oneImage(p *model.Process, size int64, owned map[string]string, pkgTrunc bool, manifests map[string]string, manTrunc bool, budget *hashBudget) model.ImageCheck {
	item := model.ImageCheck{Path: p.Exe, Size: size, Package: owned[p.Exe]}
	if _, ok := c.trusted[p.Exe]; ok {
		item.PackageSource = "local-manifest-supplied"
		if item.Package == "" {
			item.Package = "local-manifest"
		}
	}
	if item.Package == "" {
		if pkgTrunc {
			item.State = "inconclusive"
		} else {
			item.State = "unlisted"
		}
		return item
	}
	want, ok := manifests[p.Exe]
	if !ok {
		if manTrunc {
			item.State = "inconclusive"
		} else {
			item.State = "no-manifest"
		}
		return item
	}
	item.Manifest = want
	exePath := filepath.Join(c.proc, strconv.Itoa(p.PID), "exe")
	beforeDev, beforeIno, _, _, err := statFollow(exePath)
	if err != nil {
		item.State = hashStateFor(err)
		return item
	}
	sum, n, full, herr := c.hashManifestFile(exePath, budget)
	item.Bytes = n
	if errors.Is(herr, explain.ErrHashBudget) || (herr == nil && !full) {
		item.State = "skipped-size"
		item.Scope = "prefix"
		return item
	}
	if herr != nil {
		item.State = hashStateFor(herr)
		return item
	}
	afterTicks, afterDev, afterIno, afterPID, afterOK := c.recheck(p.PID)
	item.IdentityOK = afterOK && afterPID == p.PID && afterTicks == p.StartTicks && afterDev == beforeDev && afterIno == beforeIno
	if !item.IdentityOK {
		item.State = "changed"
		return item
	}
	item.MD5 = sum
	item.Scope = "full"
	if stringsEqualFold(sum, want) {
		item.State = "match"
	} else {
		item.State = "mismatch"
	}
	return item
}

func stringsEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func (c *collector) attachUnits() {
	cache := map[string]model.UnitLink{}
	n := 0
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if p.Service == "" || !unitCandidate(p) {
			continue
		}
		if n >= 32 {
			c.snap.Limits = append(c.snap.Limits, "Service-unit reads stopped after 32 processes. A missing unit file is inconclusive.")
			break
		}
		link, ok := cache[p.Service]
		if !ok {
			link = explain.ReadUnit(c.hostRoot, p.Service)
			cache[p.Service] = link
			n++
		}
		copy := link
		p.Unit = &copy
	}
}

func unitCandidate(p *model.Process) bool {
	if startupCandidate(p) {
		return true
	}
	if p.Image == nil {
		return false
	}
	switch p.Image.State {
	case "mismatch", "unlisted", "no-manifest":
		return true
	default:
		return false
	}
}

func (c *collector) readScanner() {
	base := filepath.Join(c.proc, "self")
	b, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return
	}
	st, err := procfs.ParseStatus(string(b))
	if err != nil {
		return
	}
	body, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return
	}
	ticks, ok := procfs.ParseStartTicks(string(body))
	if !ok || st.PID <= 0 {
		return
	}
	c.snap.Scanner = model.Scanner{
		PID:        st.PID,
		StartTicks: ticks,
		Exe:        readLink(filepath.Join(base, "exe")),
		Known:      true,
	}
}

func (c *collector) noteKthreadField() {
	if len(c.snap.Processes) == 0 {
		return
	}
	known := 0
	for _, p := range c.snap.Processes {
		if p.KthreadKnown {
			known++
		}
	}
	switch {
	case known == 0:
		c.snap.Limits = append(c.snap.Limits, "The Kthread status field was absent. The kernel-thread count is unknown. A missing executable link was not treated as a kernel thread.")
	case known < len(c.snap.Processes):
		c.snap.Limits = append(c.snap.Limits, fmt.Sprintf("The Kthread field was absent on %d processes. Those processes were not counted as kernel threads.", len(c.snap.Processes)-known))
	}
}
