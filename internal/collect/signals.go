//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dahnutz/procsift/internal/explain"
	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/procfs"
)

func (c *collector) observeHost() {
	c.readPreload()
	c.readBPF()
	c.noteRPM()
	c.noteLateThreads()
	c.noteUnownedLibs()
}

func (c *collector) readPreload() {
	b, err := readLimited(explainPath(c.hostRoot, "/etc/ld.so.preload"), 4096)
	if err != nil {
		if !os.IsNotExist(err) {
			c.issue(explainPath(c.hostRoot, "/etc/ld.so.preload"), err)
		}
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(c.snap.PreloadPaths) >= 16 {
			c.snap.Limits = append(c.snap.Limits, "ld.so.preload listing stopped at 16 paths.")
			break
		}
		c.snap.PreloadPaths = append(c.snap.PreloadPaths, line)
	}
}

func explainPath(root, abs string) string {
	if root == "" || root == "/" {
		return abs
	}
	return filepath.Join(root, strings.TrimPrefix(abs, "/"))
}

func (c *collector) readBPF() {
	c.snap.BPFUnprivileged = "unknown"
	sysctl := filepath.Join(c.proc, "sys", "kernel", "unprivileged_bpf_disabled")
	b, err := os.ReadFile(sysctl)
	if err == nil {
		switch strings.TrimSpace(string(b)) {
		case "0":
			c.snap.BPFUnprivileged = "enabled"
		default:
			c.snap.BPFUnprivileged = "disabled"
		}
	} else {
		c.issue(sysctl, err)
	}
	root := filepath.Join(c.sys, "fs", "bpf")
	info, err := os.Lstat(root)
	if err != nil {
		c.snap.BPFTree = "unavailable"
		c.issue(root, err)
		return
	}
	if !info.IsDir() {
		c.snap.BPFTree = "missing"
		c.snap.Limits = append(c.snap.Limits, "Pinned BPF path is not a directory. An empty pin list is not a clean result.")
		return
	}
	c.snap.BPFTree = "readable"
	n := 0
	partial := false
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			c.issue(path, err)
			partial = true
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if n >= 200 {
			c.snap.Limits = append(c.snap.Limits, "BPF pin inventory stopped at 200 names.")
			return errStopWalk
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		c.snap.BPFPins = append(c.snap.BPFPins, rel)
		n++
		return nil
	})
	if walkErr != nil && walkErr != errStopWalk {
		c.issue(root, walkErr)
		partial = true
	}
	if partial {
		c.snap.BPFTree = "partial"
	}
}

func (c *collector) noteRPM() {
	for _, rel := range []string{"/usr/lib/sysimage/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm", "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/var/lib/rpm"} {
		path := explainPath(c.hostRoot, rel)
		if _, err := os.Stat(path); err == nil {
			c.snap.RPMState = "unavailable"
			c.snap.Limits = append(c.snap.Limits, "An RPM database is present and was not parsed. RPM ownership stays unavailable rather than a match.")
			return
		} else if !os.IsNotExist(err) {
			c.snap.RPMState = "unavailable"
			c.issue(path, err)
			return
		}
	}
	c.snap.RPMState = "absent"
}

func (c *collector) readRawSockets() {
	for _, name := range []string{"raw", "raw6", "packet"} {
		path := filepath.Join(c.proc, "net", name)
		body, err := readLimited(path, 1<<20)
		if err != nil {
			c.issue(path, err)
			continue
		}
		rows := procfs.ParseNet(name, string(body))
		if len(c.snap.Sockets)+len(rows) > 8000 {
			c.snap.Limits = append(c.snap.Limits, "Raw and packet socket reads stopped at the socket cap.")
			break
		}
		c.snap.Sockets = append(c.snap.Sockets, rows...)
	}
}

func (c *collector) noteLateThreads() {
	const maxThreads = 48
	checked := 0
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if !startupCandidate(p) || p.StartTicks == 0 {
			continue
		}
		if checked >= 32 {
			c.snap.Limits = append(c.snap.Limits, "Late-thread checks stopped after 32 processes.")
			return
		}
		checked++
		dir := filepath.Join(c.proc, strconv.Itoa(p.PID), "task")
		entries, err := os.ReadDir(dir)
		if err != nil {
			c.issue(dir, err)
			continue
		}
		if len(entries) > maxThreads {
			c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: dir, State: "truncated", Detail: "thread walk stopped at 48 tasks"})
			entries = entries[:maxThreads]
		}
		for _, e := range entries {
			tid, err := strconv.Atoi(e.Name())
			if err != nil || tid == p.PID {
				continue
			}
			body, err := readLimited(filepath.Join(dir, e.Name(), "stat"), 1<<16)
			if err != nil {
				continue
			}
			ticks, ok := procfs.ParseStartTicks(string(body))
			if !ok {
				continue
			}
			comm := threadComm(string(body))
			if len(p.LateThreads) >= 8 {
				break
			}
			late := ticks > p.StartTicks && ticks-p.StartTicks >= 6000
			disguised := kernelStyleComm(comm) && !p.Kernel()
			if late || disguised {
				note := e.Name() + " comm " + comm
				if late {
					note += " start " + strconv.FormatUint(ticks, 10)
				}
				if disguised {
					note += " kernel-style comm"
				}
				p.LateThreads = append(p.LateThreads, note)
			}
		}
	}
}

func kernelStyleComm(comm string) bool {
	comm = strings.TrimSpace(comm)
	return strings.HasPrefix(comm, "[") && strings.HasSuffix(comm, "]") && len(comm) > 2
}

func (c *collector) noteUnownedLibs() {
	if _, err := os.Stat(explainPath(c.hostRoot, "/var/lib/dpkg/info")); err != nil {
		c.snap.Limits = append(c.snap.Limits, "Mapped library ownership is inconclusive because the dpkg database was not readable.")
		return
	}
	type want struct {
		pid  int
		path string
		kind string
	}
	var paths []string
	var items []want
	checked := 0
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if p.Image == nil || p.Image.Package == "" || p.Image.Package == "local-manifest" {
			continue
		}
		if checked >= 16 {
			c.snap.Limits = append(c.snap.Limits, "Mapped-library ownership checks stopped after 16 packaged processes.")
			break
		}
		checked++
		n := 0
		for _, r := range p.Maps {
			if n >= 8 {
				break
			}
			if len(r.Perms) < 3 || r.Perms[2] != 'x' {
				continue
			}
			path := strings.TrimSuffix(r.Path, " (deleted)")
			if path == "" || strings.HasPrefix(path, "[") || path == p.Exe || !strings.Contains(path, ".so") {
				continue
			}
			kind := ""
			if strings.HasSuffix(r.Path, " (deleted)") {
				kind = "deleted"
			} else if tempPath(path) {
				kind = "temporary"
			} else {
				kind = "file"
			}
			if kind == "deleted" && maintainedMap(p, r.Path) {
				continue
			}
			items = append(items, want{pid: p.PID, path: path, kind: kind})
			if kind == "file" {
				paths = append(paths, path)
			}
			n++
		}
	}
	owned, dbOK, truncated := explain.FindPackages(c.hostRoot, paths)
	if !dbOK || truncated {
		c.snap.Limits = append(c.snap.Limits, "Mapped library ownership is inconclusive because the package search was incomplete.")
		return
	}
	byPID := map[int]*model.Process{}
	for i := range c.snap.Processes {
		byPID[c.snap.Processes[i].PID] = &c.snap.Processes[i]
	}
	for _, item := range items {
		p := byPID[item.pid]
		if p == nil || len(p.UnownedLibs) >= 8 {
			continue
		}
		if item.kind == "file" {
			if pkg := owned[item.path]; pkg != "" {
				continue
			}
			p.UnownedLibs = append(p.UnownedLibs, "unlisted "+item.path)
			continue
		}
		p.UnownedLibs = append(p.UnownedLibs, item.kind+" "+item.path)
	}
}

func maintainedMap(p *model.Process, path string) bool {
	for _, item := range p.DeletedMaps {
		if item.Path == path && item.Label == explain.LabelMaintenance {
			return true
		}
	}
	return false
}

func (c *collector) notePackageSources() {
	c.snap.Notes = append(c.snap.Notes,
		"Package source dpkg: observed. A local match is not independent integrity proof.",
		"Package source snap: observed only when a squashfs mount is visible under /snap. The mounted image is not verified.",
	)
	switch c.snap.RPMState {
	case "unavailable":
		c.snap.Notes = append(c.snap.Notes, "Package source rpm: unavailable. The database is present and was not parsed.")
	case "absent":
		c.snap.Notes = append(c.snap.Notes, "Package source rpm: absent.")
	default:
		c.snap.Notes = append(c.snap.Notes, "Package source rpm: unavailable.")
	}
	if len(c.trusted) == 0 {
		c.snap.Notes = append(c.snap.Notes, "Package source local manifest: not supplied.")
	} else {
		c.snap.Notes = append(c.snap.Notes, "Package source local manifest: supplied for selected paths; authenticity not checked.")
	}
}

func threadComm(stat string) string {
	i := strings.Index(stat, "(")
	j := strings.LastIndex(stat, ")")
	if i < 0 || j <= i {
		return ""
	}
	return stat[i+1 : j]
}

type stopWalk string

func (s stopWalk) Error() string { return string(s) }

const errStopWalk stopWalk = "stop"
