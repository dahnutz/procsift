//go:build linux

package collect

import (
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/procfs"
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
	files, err := readDevShm(c.devshm)
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

func readDevShm(dir string) ([]model.DevShmFile, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []model.DevShmFile
	for _, e := range ents {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		magic := ""
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err == nil {
			buf := make([]byte, 4)
			n, _ := f.Read(buf)
			f.Close()
			magic = procfs.ClassifyMagic(buf[:n])
		}
		out = append(out, model.DevShmFile{
			Name:       e.Name(),
			Size:       info.Size(),
			Executable: info.Mode().Perm()&0111 != 0,
			Magic:      magic,
		})
	}
	return out, nil
}

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
		path := filepath.Join(c.proc, "net", spec.name)
		b, err := readLimited(path, 32<<20)
		if err != nil {
			c.issue(path, err)
			complete = false
			continue
		}
		out = append(out, procfs.ParseNet(spec.proto, string(b))...)
	}
	return out, complete
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
