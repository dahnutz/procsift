//go:build linux

package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dahnutz/procsift/internal/explain"
	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/procfs"
)

const maxExeHash = 4 << 20

const userHZ = 100

func (c *collector) enrichContext() {
	users, extra := loadUsers(c.hostRoot)
	c.snap.ExtraUID0 = extra
	btime := readBtime(c.proc)
	var pkgPaths []string
	pkgPaths = append(pkgPaths, explain.CriticalPaths()...)
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		p.Exe = explain.HostPath(c.hostRoot, p.Exe)
		if name, ok := users[p.UID]; ok {
			p.User = name
		}
		c.readIdentity(p)
		if p.StartTicks > 0 && btime > 0 {
			p.Started = time.Unix(btime+int64(p.StartTicks/userHZ), 0).UTC()
		}
		if isDeletedExe(p.Exe) {
			c.fillExeInfo(p)
			if p.ExeInfo != nil && !tempPath(p.Exe) {
				pkgPaths = append(pkgPaths, strings.TrimSuffix(p.Exe, " (deleted)"))
			}
		}
		c.fillDeletedMaps(p)
		for _, m := range p.DeletedMaps {
			if !tempPath(m.Path) {
				pkgPaths = append(pkgPaths, strings.TrimSuffix(m.Path, " (deleted)"))
			}
		}
		if explain.ShouldHashImage(p.UID, p.Exe, p.Kernel(), p.Zombie()) {
			pkgPaths = append(pkgPaths, p.Exe)
		}
	}
	owned, dbOK, truncated := explain.FindPackages(c.hostRoot, pkgPaths)
	if truncated {
		c.snap.Limits = append(c.snap.Limits, "Package-file search stopped at its read budget. Missing package ownership is inconclusive.")
	}
	manifests, manOK, manTrunc := explain.FindManifests(c.hostRoot, pkgPaths)
	if c.manifest != "" {
		local, err := explain.LoadTrustManifest(c.manifest)
		if err != nil {
			c.snap.Limits = append(c.snap.Limits, "Local supplied manifest was not applied: "+err.Error())
		} else {
			c.trusted = local
			for path, sum := range local {
				manifests[path] = sum
			}
			c.snap.Notes = append(c.snap.Notes, "A local manifest supplied hashes for selected paths. Comparisons use that file as a reference; its authenticity is not checked. dpkg is also a local reference.")
		}
	}
	if !manOK && dbOK {
		c.snap.Limits = append(c.snap.Limits, "dpkg md5sums were not readable. Manifest comparisons are inconclusive.")
	}
	if manTrunc {
		c.snap.Limits = append(c.snap.Limits, "Package manifest search stopped at its read budget. A missing hash is inconclusive.")
	}
	if dbOK && len(pkgPaths) > 0 {
		c.snap.Limits = append(c.snap.Limits, "Package names and manifests come from the local dpkg database. A match does not prove that database is trustworthy.")
	}
	txCache := map[string]struct {
		when time.Time
		ok   bool
	}{}
	hashes := &hashBudget{}
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if p.ExeInfo != nil {
			c.labelExe(p, owned, dbOK, manifests, txCache, hashes)
		}
		for j := range p.DeletedMaps {
			c.labelMap(p, &p.DeletedMaps[j], owned, dbOK, manifests, txCache, hashes)
		}
	}
	c.checkImages(owned, dbOK, truncated, manifests, manTrunc)
	c.attachPackageSources()
	c.checkCriticalFiles(owned, dbOK, truncated, manifests, manTrunc)
	c.correlateChangedFiles()
	c.attachStartup()
	c.attachUnits()
	c.observeHost()
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if p.ExeInfo != nil && p.ExeInfo.SHA256 != "" {
			p.ExeHash = p.ExeInfo.SHA256
			p.ExeHashScope = p.ExeInfo.HashScope
		}
		if p.Image != nil && p.Image.SHA256 != "" {
			p.ExeHash = p.Image.SHA256
			p.ExeHashScope = "full"
		} else if p.Image != nil && p.Image.Scope != "" && p.ExeHashScope == "" {
			p.ExeHashScope = p.Image.Scope
		}
	}
}

func (c *collector) readIdentity(p *model.Process) {
	base := filepath.Join(c.proc, strconv.Itoa(p.PID))
	if b, err := readLimited(filepath.Join(base, "stat"), 1<<16); usablePrefix(err) {
		if err != nil {
			c.issue(filepath.Join(base, "stat"), err)
		}
		if ticks, ok := procfs.ParseStartTicks(string(b)); ok {
			p.StartTicks = ticks
		}
		if tty, ok := procfs.ParseTTY(string(b)); ok {
			p.TTY = tty
			p.TTYKnown = true
		}
	} else {
		c.issue(filepath.Join(base, "stat"), err)
	}
	if dev, ino, _, _, err := statFollow(filepath.Join(base, "exe")); err == nil {
		p.ExeDev = explain.DevString(dev)
		p.ExeInode = ino
	}
	if b, err := readLimited(filepath.Join(base, "cgroup"), 8192); usablePrefix(err) {
		if err != nil {
			c.issue(filepath.Join(base, "cgroup"), err)
			b = completeLines(b)
		}
		p.Cgroup = string(b)
		p.Service = explain.ServiceFromCgroup(p.Cgroup)
	} else if !errors.Is(err, os.ErrNotExist) {
		c.issue(filepath.Join(base, "cgroup"), err)
	}
}

func (c *collector) fillExeInfo(p *model.Process) {
	info := &model.ExeIdentity{BootID: c.snap.BootID}
	exePath := filepath.Join(c.proc, strconv.Itoa(p.PID), "exe")
	dev, ino, nlink, size, err := statFollow(exePath)
	if err != nil {
		info.HashState = hashStateFor(err)
		info.Notes = append(info.Notes, "running image was not readable")
		c.issue(exePath, err)
	} else {
		info.Dev = explain.DevString(dev)
		info.Inode = ino
		info.NLink = nlink
		info.Size = size
		sum, n, state, herr := hashFile(exePath, maxExeHash)
		info.HashBytes = n
		info.HashState = state
		if herr != nil && state != "truncated" {
			c.issue(exePath, herr)
			info.Notes = append(info.Notes, "hash read failed")
		} else if state == "truncated" {
			info.Notes = append(info.Notes, fmt.Sprintf("hash covers the first %d bytes only", maxExeHash))
			c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: exePath, State: "truncated", Detail: "deleted executable hash was capped at 4 MiB"})
		}
		if state == "complete" || state == "truncated" {
			info.SHA256 = sum
			if state == "complete" && info.HashBytes == info.Size {
				info.HashScope = "full"
			} else {
				info.HashScope = "prefix"
			}
		}
	}
	afterTicks, afterDev, afterIno, afterPID, afterOK := c.recheck(p.PID)
	sameIno := err == nil && afterOK && afterDev == dev && afterIno == ino
	info.IdentityOK = err == nil && afterOK && afterPID == p.PID && afterTicks == p.StartTicks && sameIno
	if !info.IdentityOK {
		if info.SHA256 != "" {
			info.Notes = append(info.Notes, "process identity changed during the read; hash discarded")
		}
		info.SHA256 = ""
		info.HashState = "changed"
		c.changed(exePath, "pid, start tick, or executable inode changed while the deleted image was read")
	}
	clean := strings.TrimSuffix(p.Exe, " (deleted)")
	cur, curErr := statResult(explain.UnderRoot(c.hostRoot, clean))
	running := explain.FileView{OK: err == nil, Dev: info.Dev, Inode: info.Inode}
	info.Relation = explain.PathRelation(running, cur)
	if cur.OK {
		info.CurrentDev = cur.Dev
		info.CurrentInode = cur.Inode
	}
	if curErr != nil && !cur.Absent && !cur.Denied {
		info.Notes = append(info.Notes, "pathname stat failed")
		c.issue(clean, curErr)
	}
	p.ExeInfo = info
}

func (c *collector) recheck(pid int) (ticks, dev, ino uint64, gotPID int, ok bool) {
	base := filepath.Join(c.proc, strconv.Itoa(pid))
	st, err := readStatus(c.proc, pid)
	if err != nil {
		return 0, 0, 0, 0, false
	}
	b, err := readLimited(filepath.Join(base, "stat"), 1<<16)
	if err != nil {
		return 0, 0, 0, st.PID, false
	}
	ticks, ticksOK := procfs.ParseStartTicks(string(b))
	dev, ino, _, _, err = statFollow(filepath.Join(base, "exe"))
	if err != nil || !ticksOK {
		return ticks, 0, 0, st.PID, false
	}
	return ticks, dev, ino, st.PID, true
}

func (c *collector) fillDeletedMaps(p *model.Process) {
	for _, region := range p.Maps {
		if len(region.Perms) < 3 || region.Perms[2] != 'x' || !strings.HasSuffix(region.Path, " (deleted)") {
			continue
		}
		if strings.Contains(region.Path, "memfd:") {
			continue
		}
		item := model.DeletedMap{Path: explain.HostPath(c.hostRoot, region.Path), RunningInode: region.Inode}
		if dev, ok := explain.ParseMapDev(region.Dev); ok {
			item.RunningDev = dev
		}
		clean := strings.TrimSuffix(item.Path, " (deleted)")
		cur, _ := statResult(explain.UnderRoot(c.hostRoot, clean))
		running := explain.FileView{OK: item.RunningDev != "", Dev: item.RunningDev, Inode: item.RunningInode}
		item.Relation = explain.PathRelation(running, cur)
		if cur.OK {
			item.CurrentDev = cur.Dev
			item.CurrentInode = cur.Inode
		}
		p.DeletedMaps = append(p.DeletedMaps, item)
		if len(p.DeletedMaps) >= 32 {
			p.DeletedMaps = p.DeletedMaps[:32]
			break
		}
	}
}

func (c *collector) labelExe(p *model.Process, owned map[string]string, dbOK bool, manifests map[string]string, tx map[string]struct {
	when time.Time
	ok   bool
}, hashes *hashBudget) {
	info := p.ExeInfo
	clean := strings.TrimSuffix(p.Exe, " (deleted)")
	if !tempPath(p.Exe) {
		info.Package = owned[clean]
	}
	when, known := transaction(c.hostRoot, info.Package, tx)
	knownManifest, match := c.manifestMatch(clean, info.Package, info.Relation, manifests, hashes, &info.Notes)
	info.Label = explain.Explain(explain.ExplainInput{
		Path:              clean,
		Temp:              tempPath(p.Exe),
		Relation:          info.Relation,
		IdentityOK:        info.IdentityOK,
		PackageDBReadable: dbOK || tempPath(p.Exe),
		Package:           info.Package,
		Start:             p.Started,
		StartKnown:        !p.Started.IsZero(),
		Transaction:       when,
		TransactionKnown:  known,
		ManifestKnown:     knownManifest,
		ManifestMatch:     match,
	})
	if info.Relation == explain.PathReplaced && info.Package != "" && info.IdentityOK && !tempPath(p.Exe) && !known {
		info.Notes = append(info.Notes, "no dpkg transaction after the process start")
	}
}

func (c *collector) labelMap(p *model.Process, item *model.DeletedMap, owned map[string]string, dbOK bool, manifests map[string]string, tx map[string]struct {
	when time.Time
	ok   bool
}, hashes *hashBudget) {
	clean := strings.TrimSuffix(item.Path, " (deleted)")
	temp := tempPath(item.Path)
	if !temp {
		item.Package = owned[clean]
	}
	when, known := transaction(c.hostRoot, item.Package, tx)
	var notes []string
	knownManifest, match := c.manifestMatch(clean, item.Package, item.Relation, manifests, hashes, &notes)
	item.Label = explain.Explain(explain.ExplainInput{
		Path:              clean,
		Temp:              temp,
		Relation:          item.Relation,
		IdentityOK:        true,
		PackageDBReadable: dbOK || temp,
		Package:           item.Package,
		Start:             p.Started,
		StartKnown:        !p.Started.IsZero(),
		Transaction:       when,
		TransactionKnown:  known,
		ManifestKnown:     knownManifest,
		ManifestMatch:     match,
	})
}

func (c *collector) manifestMatch(clean, pkg, relation string, manifests map[string]string, hashes *hashBudget, notes *[]string) (known, match bool) {
	if relation != explain.PathReplaced || pkg == "" || tempPath(clean) {
		return false, false
	}
	want, ok := manifests[clean]
	if !ok {
		*notes = append(*notes, "package manifest hash was not available")
		return false, false
	}
	sum, _, full, err := c.hashManifestFile(explain.UnderRoot(c.hostRoot, clean), hashes)
	if err != nil || !full {
		if errors.Is(err, explain.ErrHashBudget) {
			*notes = append(*notes, "current file exceeds the manifest hash budget")
		} else if err != nil {
			*notes = append(*notes, "current file could not be hashed")
		}
		return false, false
	}
	return true, strings.EqualFold(sum, want)
}

func transaction(root, pkg string, cache map[string]struct {
	when time.Time
	ok   bool
}) (time.Time, bool) {
	if pkg == "" {
		return time.Time{}, false
	}
	if hit, ok := cache[pkg]; ok {
		return hit.when, hit.ok
	}
	when, ok := explain.LatestTransaction(root, pkg)
	cache[pkg] = struct {
		when time.Time
		ok   bool
	}{when, ok}
	return when, ok
}

func (c *collector) attachStartup() {
	var paths []string
	seen := map[string]struct{}{}
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if !startupCandidate(p) {
			continue
		}
		key := strings.TrimSuffix(p.Exe, " (deleted)")
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			paths = append(paths, key)
		}
	}
	if len(paths) > 64 {
		paths = paths[:64]
		c.snap.Limits = append(c.snap.Limits, "Startup search selected only the first 64 distinct process image paths.")
		c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: "startup search", State: "truncated", Detail: "paths beyond the first 64 were not searched"})
	}
	results, gaps := explain.FindStartupMany(c.hostRoot, paths)
	c.snap.Coverage = append(c.snap.Coverage, gaps...)
	partial := len(gaps) > 0
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if !startupCandidate(p) {
			continue
		}
		key := strings.TrimSuffix(p.Exe, " (deleted)")
		result, ok := results[key]
		if !ok {
			p.StartupStatus = "not-searched"
			p.StartupIncomplete = true
		} else {
			p.Startup = append(append([]model.StartupRef{}, result.Exact...), result.Names...)
			p.StartupStatus = result.Status
			p.StartupIncomplete = result.Status != "complete"
		}
	}
	if partial {
		c.snap.Limits = append(c.snap.Limits, "Startup-file search had unreadable, truncated, or budget-limited files. Exact matches stay visible. A missing match is inconclusive only for a path with no exact hit.")
	}
}

func startupCandidate(p *model.Process) bool {
	if p.Kernel() || p.Zombie() || p.Exe == "" {
		return false
	}
	if isDeletedExe(p.Exe) || tempPath(p.Exe) || strings.Contains(p.Exe, "memfd:") {
		return true
	}
	if p.Image != nil {
		if p.Image.PackageSource == "snap-mount-observed" {
			return false
		}
		switch p.Image.State {
		case "unlisted", "mismatch", "no-manifest":
			return true
		}
	}
	_, _, _, _, ok := explain.Masquerade(*p)
	return ok
}

func isDeletedExe(path string) bool {
	return strings.HasSuffix(path, " (deleted)")
}

func tempPath(path string) bool {
	p := strings.TrimSuffix(path, " (deleted)")
	for _, pre := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/var/run/shm/", "/run/user/"} {
		if p == strings.TrimSuffix(pre, "/") || strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func hashFile(path string, max int) (sum string, n int64, state string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, hashStateFor(err), err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return "", int64(len(buf)), hashStateFor(err), err
	}
	state = "complete"
	if len(buf) > max {
		buf = buf[:max]
		state = "truncated"
	}
	digest := sha256.Sum256(buf)
	return hex.EncodeToString(digest[:]), int64(len(buf)), state, nil
}

func hashStateFor(err error) string {
	if err == nil {
		return "complete"
	}
	if errors.Is(err, os.ErrPermission) {
		return "denied"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "unavailable"
	}
	return "error"
}

func statFollow(path string) (dev, ino, nlink uint64, size int64, err error) {
	var st syscall.Stat_t
	if err = syscall.Stat(path, &st); err != nil {
		return 0, 0, 0, 0, err
	}
	return st.Dev, st.Ino, uint64(st.Nlink), st.Size, nil
}

func statResult(path string) (explain.FileView, error) {
	var st syscall.Stat_t
	err := syscall.Stat(path, &st)
	if err == nil {
		return explain.FileView{OK: true, Dev: explain.DevString(st.Dev), Inode: st.Ino}, nil
	}
	view := explain.FileView{}
	if errors.Is(err, os.ErrNotExist) {
		view.Absent = true
	}
	if errors.Is(err, os.ErrPermission) {
		view.Denied = true
	}
	return view, err
}

func loadUsers(root string) (map[int]string, []string) {
	out := map[int]string{}
	var extra []string
	seen := map[string]struct{}{}
	b, err := os.ReadFile(explain.UnderRoot(root, "/etc/passwd"))
	if err != nil {
		return out, nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		uid, err := strconv.Atoi(parts[2])
		if err != nil || name == "" {
			continue
		}
		if _, ok := out[uid]; !ok {
			out[uid] = name
		}
		if uid == 0 && name != "root" {
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				extra = append(extra, name)
			}
		}
	}
	return out, extra
}

func readBtime(proc string) int64 {
	b, err := os.ReadFile(filepath.Join(proc, "stat"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "btime ") {
			n, err := strconv.ParseInt(strings.TrimPrefix(line, "btime "), 10, 64)
			if err == nil {
				return n
			}
		}
	}
	return 0
}
