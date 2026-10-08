//go:build linux

package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/dahnutz/procsift/internal/model"
)

// comparePages is opt-in. It compares at most four 16-byte executable page
// headers per selected process with the exact map_files backing inode.
func (c *collector) comparePages() {
	c.snap.Notes = append(c.snap.Notes, "Deeper page compare is enabled. A difference can come from JIT, a debugger, or a runtime. Compared bytes are not stored or executed.")
	checked := 0
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if p.Kernel() || !p.MapsOK {
			continue
		}
		if checked >= 16 {
			c.snap.Limits = append(c.snap.Limits, "Page compare stopped after 16 processes.")
			return
		}
		checked++
		c.compareProcessPages(p)
	}
}

func (c *collector) compareProcessPages(p *model.Process) {
	base := filepath.Join(c.proc, strconv.Itoa(p.PID))
	beforeTicks, beforeDev, beforeIno, gotPID, ok := c.recheck(p.PID)
	if !ok || gotPID != p.PID || beforeTicks != p.StartTicks || (p.ExeInode != 0 && p.ExeInode != beforeIno) {
		c.deepIssue(base, "changed", "process identity could not be established before page comparison")
		return
	}
	memPath := filepath.Join(base, "mem")
	mem, err := os.Open(memPath)
	if err != nil {
		c.deepIssue(memPath, stateFor(err), "process memory was not compared")
		return
	}
	defer mem.Close()
	n := 0
	for _, region := range p.Maps {
		if n >= 4 || len(p.PageDiffs) >= 4 {
			break
		}
		if len(region.Perms) < 3 || region.Perms[2] != 'x' || region.Inode == 0 || region.End <= region.Start || region.End-region.Start < 16 {
			continue
		}
		path := strings.TrimSuffix(region.Path, " (deleted)")
		if path == "" || strings.HasPrefix(path, "[") {
			continue
		}
		n++
		mapLink := filepath.Join(base, "map_files", fmt.Sprintf("%x-%x", region.Start, region.End))
		mapDev, mapIno, _, _, err := statFollow(mapLink)
		if err != nil {
			c.deepIssue(mapLink, stateFor(err), "mapped file identity was not available")
			continue
		}
		if mapIno != region.Inode {
			c.deepIssue(mapLink, "changed", "mapped inode no longer agrees with the process map")
			continue
		}
		file, err := os.Open(mapLink)
		if err != nil {
			c.deepIssue(mapLink, stateFor(err), "mapped file was not readable")
			continue
		}
		openedDev, openedIno, _, _, openErr := statFile(file)
		if openErr != nil || openedDev != mapDev || openedIno != mapIno {
			_ = file.Close()
			c.deepIssue(mapLink, "changed", "mapped file changed while opening")
			continue
		}
		memBuf := make([]byte, 16)
		_, memErr := mem.ReadAt(memBuf, int64(region.Start))
		fileBuf := make([]byte, 16)
		_, fileErr := file.ReadAt(fileBuf, int64(region.Offset))
		_ = file.Close()
		if memErr != nil {
			c.deepIssue(memPath, stateFor(memErr), "executable page was not readable")
			continue
		}
		if fileErr != nil {
			c.deepIssue(mapLink, stateFor(fileErr), "mapped file bytes were not readable")
			continue
		}
		afterTicks, afterDev, afterIno, afterPID, afterOK := c.recheck(p.PID)
		endDev, endIno, _, _, endErr := statFollow(mapLink)
		if !afterOK || afterPID != p.PID || afterTicks != beforeTicks || afterDev != beforeDev || afterIno != beforeIno || endErr != nil || endDev != mapDev || endIno != mapIno {
			c.deepIssue(mapLink, "changed", "process or mapped file identity changed during comparison")
			return
		}
		if string(memBuf) != string(fileBuf) {
			p.PageDiffs = append(p.PageDiffs, path+" first 16 bytes differ from its mapped inode")
		}
	}
}

func (c *collector) deepIssue(source, state, detail string) {
	c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: source, State: state, Detail: detail})
}

func statFile(f *os.File) (dev, ino, nlink uint64, size int64, err error) {
	info, err := f.Stat()
	if err != nil {
		return 0, 0, 0, 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, 0, fmt.Errorf("file stat is not a Linux stat")
	}
	return st.Dev, st.Ino, uint64(st.Nlink), st.Size, nil
}

func stateFor(err error) string {
	if os.IsPermission(err) {
		return "denied"
	}
	if os.IsNotExist(err) {
		return "unavailable"
	}
	return "error"
}
