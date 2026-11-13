//go:build linux

package collect

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/procfs"
	"github.com/dahnutz/procsift/internal/safeio"
)

func (c *collector) loadObjects() {
	if mods, ok := readModules(c.proc); ok {
		c.snap.ModulesOK = true
		c.snap.Modules = mods
	}
	if names, loadable, ok := readSysfs(c.sys); ok {
		c.snap.SysfsOK = true
		c.snap.SysfsNames = names
		c.snap.SysfsLoadable = loadable
	}
	if b, err := os.ReadFile(filepath.Join(c.proc, "sysvipc", "shm")); err == nil {
		c.snap.SysV = procfs.ParseSysVSHM(string(b))
	} else {
		c.snap.Notes = append(c.snap.Notes, "System V shared-memory table was not readable.")
	}
	files, issues, err := readDevShm(c.devshm)
	c.snap.Coverage = append(c.snap.Coverage, issues...)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.snap.Limits = append(c.snap.Limits, "/dev/shm is not present, so POSIX shared-memory files were not inventoried.")
		} else {
			c.snap.Limits = append(c.snap.Limits, "Could not read /dev/shm, so POSIX shared-memory files were not inventoried.")
		}
	} else {
		c.snap.DevShm = files
	}
	var tablesOK bool
	c.snap.Sockets, tablesOK = c.readSockets()
	refNS := readLink(filepath.Join(c.proc, "self", "ns", "net"))
	c.markNet(refNS)
	c.snap.NetIncomplete = c.snap.NetIncomplete || !tablesOK || c.snap.ProcessIncomplete
	if !c.snap.NetIncomplete {
		c.confirmNetwork(refNS)
	}
}

func readModules(proc string) ([]model.Module, bool) {
	b, err := os.ReadFile(filepath.Join(proc, "modules"))
	if err != nil {
		return nil, false
	}
	return procfs.ParseModules(string(b)), true
}

func readSysfs(sys string) (map[string]struct{}, []string, bool) {
	ents, err := os.ReadDir(filepath.Join(sys, "module"))
	if err != nil {
		return nil, nil, false
	}
	names := make(map[string]struct{}, len(ents))
	var loadable []string
	for _, e := range ents {
		name := e.Name()
		names[name] = struct{}{}
		base := filepath.Join(sys, "module", name)
		if fileExists(filepath.Join(base, "initstate")) ||
			fileExists(filepath.Join(base, "refcnt")) ||
			fileExists(filepath.Join(base, "coresize")) ||
			fileExists(filepath.Join(base, "sections")) {
			loadable = append(loadable, name)
		}
	}
	sort.Strings(loadable)
	return names, loadable, true
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readDevShm(dir string) ([]model.DevShmFile, []model.ReadIssue, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var out []model.DevShmFile
	var issues []model.ReadIssue
	if len(ents) > maxDevShmEntries {
		ents = ents[:maxDevShmEntries]
		issues = append(issues, model.ReadIssue{Source: dir, State: "truncated", Detail: fmt.Sprintf("/dev/shm listing stopped at %d entries", maxDevShmEntries)})
	}
	for _, e := range ents {
		path := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			issues = append(issues, model.ReadIssue{Source: path, State: readState(err), Detail: err.Error()})
			continue
		}
		if !info.Mode().IsRegular() {
			if entry, ok := specialDevShm(path, e.Name(), info); ok {
				out = append(out, entry)
			}
			continue
		}
		opened, magic, err := inspectDevShm(path)
		if err != nil {
			issues = append(issues, model.ReadIssue{Source: path, State: readState(err), Detail: err.Error()})
		}
		if opened == nil {
			if errors.Is(err, safeio.ErrNotRegular) {
				// Replaced after the listing; record what is there now.
				if now, lerr := os.Lstat(path); lerr == nil {
					if entry, ok := specialDevShm(path, e.Name(), now); ok {
						out = append(out, entry)
					}
				}
				continue
			}
			// The file could not be opened (for example, another user's file
			// without root). Keep the directory metadata so the mode bits still
			// reach the analyzer; only the magic is unknown.
			opened = info
		}
		out = append(out, model.DevShmFile{
			Name:       e.Name(),
			Size:       opened.Size(),
			Executable: opened.Mode().Perm()&0111 != 0,
			Magic:      magic,
			Kind:       "file",
		})
	}
	return out, issues, nil
}

// maxDevShmEntries caps the /dev/shm directory walk.
const maxDevShmEntries = 4096

// specialDevShm describes a non-regular /dev/shm entry without opening it.
// Directories are not listed.
func specialDevShm(path, name string, info os.FileInfo) (model.DevShmFile, bool) {
	entry := model.DevShmFile{Name: name}
	switch mode := info.Mode(); {
	case mode&os.ModeSymlink != 0:
		entry.Kind = "symlink"
		entry.Target, _ = os.Readlink(path)
	case mode&os.ModeNamedPipe != 0:
		entry.Kind = "fifo"
	case mode&os.ModeSocket != 0:
		entry.Kind = "socket"
	case mode&os.ModeDevice != 0:
		entry.Kind = "device"
	default:
		return entry, false
	}
	return entry, true
}

func inspectDevShm(path string) (os.FileInfo, string, error) {
	f, info, err := safeio.OpenRegular(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	buf := make([]byte, 4)
	n, err := f.Read(buf)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return info, procfs.ClassifyMagic(buf[:n]), err
}

// Every socket table shares one byte cap and one row cap. The row cap is per
// table, so a flood of TCP sockets cannot push raw or packet sockets out of
// the inventory.
const maxSocketTableBytes = 32 << 20

// maxSocketTableRows is a variable so tests can lower it.
var maxSocketTableRows = 65536

func (c *collector) readSockets() ([]model.Socket, bool) {
	specs := []struct{ proto, name string }{
		{"tcp", "tcp"},
		{"tcp6", "tcp6"},
		{"udp", "udp"},
		{"udp6", "udp6"},
	}
	var out []model.Socket
	complete := true
	for _, spec := range specs {
		proto := spec.proto
		rows, ok := c.readSocketTable(filepath.Join(c.proc, "net", spec.name), func(body string) []model.Socket {
			return procfs.ParseNet(proto, body)
		})
		complete = complete && ok
		out = append(out, rows...)
	}
	return out, complete
}

// readSocketTable reads one /proc/net table. A truncated read keeps its
// complete rows. ok is false when any part of the table was not inventoried.
func (c *collector) readSocketTable(path string, parse func(string) []model.Socket) ([]model.Socket, bool) {
	b, err := readLimited(path, maxSocketTableBytes)
	ok := true
	if err != nil {
		c.issue(path, err)
		ok = false
		if !errors.Is(err, errTruncated) {
			return nil, false
		}
		b = completeLines(b)
	}
	body := string(b)
	rows := parse(body)
	if !c.noteUnparsed(path, body, len(rows)) {
		ok = false
	}
	if len(rows) > maxSocketTableRows {
		rows = rows[:maxSocketTableRows]
		c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: path, State: "truncated", Detail: fmt.Sprintf("socket table stopped at %d rows", maxSocketTableRows)})
		ok = false
	}
	return rows, ok
}

// noteUnparsed records a table that has data rows but yielded none, so a
// kernel format change cannot silently empty the inventory. It returns false
// when that happened.
func (c *collector) noteUnparsed(path, body string, parsed int) bool {
	if parsed > 0 || dataLines(body) == 0 {
		return true
	}
	c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: path, State: "unavailable", Detail: filepath.Base(path) + ": no rows parsed; format not recognized"})
	return false
}

// dataLines counts non-empty lines after the header line.
func dataLines(body string) int {
	n := 0
	header := true
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if header {
			header = false
			continue
		}
		n++
	}
	return n
}

func (c *collector) markNet(refNS string) {
	c.snap.SocketOwner = map[uint64]int{}
	incomplete := refNS == ""
	if refNS == "" {
		c.snap.Limits = append(c.snap.Limits, "The scanner's network namespace could not be identified; socket ownership checks are inconclusive.")
	}
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if p.Exited {
			continue
		}
		// A descriptor can be inherited or passed across namespaces. Keep
		// references from every visible process, regardless of its current netns.
		if !p.FDComplete {
			incomplete = true
			continue
		}
		for _, ino := range p.SocketInodes {
			if _, ok := c.snap.SocketOwner[ino]; !ok {
				c.snap.SocketOwner[ino] = p.PID
			}
		}
	}
	c.snap.NetIncomplete = incomplete
}
