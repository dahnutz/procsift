//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/procfs"
)

// noteNamespaces records per-process network-namespace and map_files state.
// A missing or unreadable view stays a stated limit. It is not a clean result.
func (c *collector) noteNamespaces() {
	rootNS := readLink(filepath.Join(c.proc, "1", "ns", "net"))
	inodes := map[uint64]struct{}{}
	for _, sock := range c.snap.Sockets {
		inodes[sock.Inode] = struct{}{}
	}
	checked := 0
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if c.onlyPID == 0 && !startupCandidate(p) {
			p.NetNSView = "unchecked"
			p.MapFiles = "unchecked"
			continue
		}
		if checked >= 32 {
			c.snap.Limits = append(c.snap.Limits, "Namespace and map_files checks stopped after 32 processes.")
			return
		}
		checked++
		c.noteNetNS(p, rootNS, inodes)
		c.noteMapFiles(p)
	}
}

func (c *collector) noteNetNS(p *model.Process, rootNS string, rootInodes map[uint64]struct{}) {
	nsPath := filepath.Join(c.proc, strconv.Itoa(p.PID), "ns", "net")
	target, err := os.Readlink(nsPath)
	switch {
	case err != nil && os.IsNotExist(err):
		p.NetNSView = "missing"
		c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: nsPath, State: "unavailable", Detail: "network namespace link is missing"})
		return
	case err != nil && os.IsPermission(err):
		p.NetNSView = "denied"
		c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: nsPath, State: "denied", Detail: "network namespace link was not readable"})
		return
	case err != nil:
		p.NetNSView = "missing"
		c.issue(nsPath, err)
		return
	}
	if rootNS != "" && target == rootNS {
		p.NetNSView = "same"
		return
	}
	table := filepath.Join(c.proc, strconv.Itoa(p.PID), "net", "tcp")
	body, err := readLimited(table, 1<<20)
	if err != nil {
		if os.IsPermission(err) {
			p.NetNSView = "denied"
			c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: table, State: "denied", Detail: "network namespace socket table was not readable"})
			return
		}
		if os.IsNotExist(err) {
			p.NetNSView = "missing"
			c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: table, State: "unavailable", Detail: "network namespace socket table is missing"})
			return
		}
		p.NetNSView = "missing"
		c.issue(table, err)
		return
	}
	extra := 0
	for _, row := range procfs.ParseNet("tcp", string(body)) {
		if _, ok := rootInodes[row.Inode]; !ok {
			extra++
		}
	}
	if extra > 0 {
		p.NetNSView = "changed"
		return
	}
	p.NetNSView = "same"
}

func (c *collector) noteMapFiles(p *model.Process) {
	dir := filepath.Join(c.proc, strconv.Itoa(p.PID), "map_files")
	entries, err := os.ReadDir(dir)
	switch {
	case err != nil && os.IsNotExist(err):
		p.MapFiles = "missing"
		p.MapFilesDetail = "map_files directory is missing"
		c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: dir, State: "unavailable", Detail: p.MapFilesDetail})
		return
	case err != nil && os.IsPermission(err):
		p.MapFiles = "denied"
		p.MapFilesDetail = "map_files directory was not readable"
		c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: dir, State: "denied", Detail: p.MapFilesDetail})
		return
	case err != nil:
		p.MapFiles = "missing"
		c.issue(dir, err)
		return
	}
	if len(entries) > 32 {
		entries = entries[:32]
		c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: dir, State: "truncated", Detail: "map_files walk stopped at 32 entries"})
	}
	state := "readable"
	for _, e := range entries {
		link := filepath.Join(dir, e.Name())
		target, err := os.Readlink(link)
		if err != nil {
			if os.IsNotExist(err) {
				state = worseMap(state, "missing")
				p.MapFilesDetail = e.Name() + " is missing"
			} else if os.IsPermission(err) {
				state = worseMap(state, "denied")
				p.MapFilesDetail = e.Name() + " was not readable"
			}
			continue
		}
		_, ino, _, _, err := statFollow(link)
		if err != nil {
			if os.IsNotExist(err) {
				state = worseMap(state, "missing")
				p.MapFilesDetail = e.Name() + " backing file is missing"
			}
			continue
		}
		clean := strings.TrimSuffix(target, " (deleted)")
		for _, r := range p.Maps {
			if r.Inode == 0 || strings.TrimSuffix(r.Path, " (deleted)") != clean {
				continue
			}
			if ino != r.Inode {
				p.MapFiles = "changed"
				p.MapFilesDetail = clean + " inode differs from the mapped file"
				return
			}
		}
	}
	p.MapFiles = state
}

func worseMap(cur, next string) string {
	rank := map[string]int{"readable": 0, "missing": 1, "denied": 2, "changed": 3}
	if rank[next] > rank[cur] {
		return next
	}
	return cur
}
