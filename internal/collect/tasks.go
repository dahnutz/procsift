//go:build linux

package collect

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/dahnutz/procsift/internal/analyze"
	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/procfs"
)

func (c *collector) discover() error {
	listed, err := listPIDs(c.proc)
	if err != nil {
		return err
	}
	final := listed
	extra := map[int]struct{}{}
	if c.sweep && c.real && c.pidMax >= 2 {
		last := c.pidMax - 1
		c.logf("probing tasks in pid space 1..%d", last)
		probe := probeTasks(c.pidMax, c.sweepMaxProbes, c.sweepTimeout)
		alive, bad := probe.Alive, probe.Unreliable
		c.snap.SweepProbed = probe.Probed
		c.snap.SweepComplete = probe.Complete && c.pidMax == c.snap.PIDMax
		if !probe.Complete {
			c.snap.Limits = append(c.snap.Limits, fmt.Sprintf("PID sweep stopped after %d IDs (%s); unprobed IDs are unknown.", probe.Probed, probe.StopReason))
		}
		c.snap.SweepUsed = true
		c.snap.TasksSeen = len(alive)
		c.snap.ProbeBad = bad
		if bad {
			c.snap.Limits = append(c.snap.Limits, "The pid probe reported an implausible number of live tasks and was ignored.")
		} else {
			if again, err := listPIDs(c.proc); err == nil {
				final = union(final, again)
			}
			var hiddenCand, ghostCand []int
			for _, pid := range alive {
				if _, ok := final[pid]; ok {
					continue
				}
				if procExists(filepath.Join(c.proc, strconv.Itoa(pid))) {
					hiddenCand = append(hiddenCand, pid)
				} else {
					ghostCand = append(ghostCand, pid)
				}
			}
			if again, err := listPIDs(c.proc); err == nil {
				final = union(final, again)
			}
			extra = c.confirmUnlisted(hiddenCand, ghostCand, final)
		}
	}
	pids := mapKeys(final)
	for pid := range extra {
		if _, ok := final[pid]; !ok {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	c.logf("reading %d processes", len(pids))
	for _, pid := range pids {
		p, err := c.readProcess(pid)
		if err != nil {
			base := filepath.Join(c.proc, strconv.Itoa(pid))
			if processGone(base, err) {
				c.snap.ExitedDuringScan++
				c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: base, State: "exited", Detail: "process directory disappeared"})
			} else {
				c.snap.ProcessIncomplete = true
				c.issue(filepath.Join(base, "status"), err)
			}
			continue
		}
		_, p.Listed = final[pid]
		c.snap.Processes = append(c.snap.Processes, p)
	}
	return nil
}

func (c *collector) confirmUnlisted(hiddenCand, ghostCand []int, listed map[int]struct{}) map[int]struct{} {
	extra := map[int]struct{}{}
	for _, pid := range ghostCand {
		dir := filepath.Join(c.proc, strconv.Itoa(pid))
		if procExists(dir) {
			hiddenCand = append(hiddenCand, pid)
			continue
		}
		if !killExists(pid) {
			continue
		}
		c.snap.Ghosts = append(c.snap.Ghosts, model.Ghost{PID: pid})
	}
	sort.Slice(c.snap.Ghosts, func(i, j int) bool { return c.snap.Ghosts[i].PID < c.snap.Ghosts[j].PID })

	seen := map[int]struct{}{}
	for _, pid := range hiddenCand {
		if _, ok := listed[pid]; ok {
			continue
		}
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		st, err := readStatus(c.proc, pid)
		if err != nil {
			continue
		}
		kind := analyze.ClassifyTask(false, true, true, st.PID, st.TGID, true)
		switch kind {
		case analyze.TaskHidden:
			extra[st.PID] = struct{}{}
		case analyze.TaskThread:
			if st.TGID > 0 {
				if _, ok := listed[st.TGID]; !ok {
					extra[st.TGID] = struct{}{}
				}
			}
		}
	}
	return extra
}

func (c *collector) readProcess(pid int) (model.Process, error) {
	base := filepath.Join(c.proc, strconv.Itoa(pid))
	st, err := readStatus(c.proc, pid)
	if err != nil {
		return model.Process{}, err
	}
	p := model.Process{
		PID:          st.PID,
		TGID:         st.TGID,
		PPID:         st.PPID,
		Name:         st.Name,
		State:        st.State,
		Threads:      st.Threads,
		UID:          st.UID,
		VmRSSKiB:     st.VmRSSKiB,
		Kthread:      st.Kthread,
		KthreadKnown: st.KthreadKnown,
		TracerPID:    st.TracerPID,
		Exe:          readLink(filepath.Join(base, "exe")),
		Cwd:          readLink(filepath.Join(base, "cwd")),
		NetNS:        readLink(filepath.Join(base, "ns", "net")),
	}
	if cmd, err := readLimited(filepath.Join(base, "cmdline"), 4096); usablePrefix(err) {
		if err != nil {
			c.issue(filepath.Join(base, "cmdline"), err)
			cmd = completeNUL(cmd)
		}
		p.Cmdline = procfs.NormalizeCmdline(cmd)
	} else {
		c.issue(filepath.Join(base, "cmdline"), err)
	}
	if env, err := readLimited(filepath.Join(base, "environ"), 1<<20); usablePrefix(err) {
		if err != nil {
			c.issue(filepath.Join(base, "environ"), err)
			env = completeNUL(env)
		}
		p.LDPreload, p.LDAudit, p.LDLibrary = procfs.InterestingEnv(env)
	} else {
		c.issue(filepath.Join(base, "environ"), err)
	}
	c.readMaps(&p, base)
	c.readFDs(&p, base)
	return p, nil
}

func readStatus(proc string, pid int) (procfs.Status, error) {
	b, err := readLimited(filepath.Join(proc, strconv.Itoa(pid), "status"), 1<<20)
	if err != nil {
		return procfs.Status{}, err
	}
	return procfs.ParseStatus(string(b))
}

func (c *collector) readMaps(p *model.Process, base string) {
	b, err := readLimited(filepath.Join(base, "maps"), 8<<20)
	if err != nil && !errors.Is(err, errTruncated) {
		c.snap.MapsUnreadable++
		if errors.Is(err, os.ErrPermission) {
			c.snap.MapsDenied++
		}
		if processGone(base, err) {
			c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: filepath.Join(base, "maps"), State: "exited", Detail: "process directory disappeared before maps could be read"})
		} else {
			c.issue(filepath.Join(base, "maps"), err)
		}
		return
	}
	if err != nil {
		c.snap.MapsUnreadable++
		c.issue(filepath.Join(base, "maps"), err)
		b = completeLines(b)
	}
	p.Maps = procfs.ParseMaps(string(b))
	p.MapsOK = true
	if !c.readMagic || p.Kernel() {
		return
	}
	if denied := c.annotateMagic(p); denied {
		c.snap.MagicDenied++
	}
}

func (c *collector) annotateMagic(p *model.Process) bool {
	need := false
	for i := range p.Maps {
		if magicCandidate(p.Maps[i]) {
			need = true
			break
		}
	}
	if !need || c.magicLeft <= 0 {
		return false
	}
	f, err := os.Open(filepath.Join(c.proc, strconv.Itoa(p.PID), "mem"))
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return true
		}
		return false
	}
	defer f.Close()
	buf := make([]byte, 16)
	reads := 0
	for i := range p.Maps {
		if !magicCandidate(p.Maps[i]) {
			continue
		}
		if reads >= 24 || c.magicLeft <= 0 {
			break
		}
		if p.Maps[i].Start > uint64(math.MaxInt64) {
			continue
		}
		n, err := f.ReadAt(buf[:16], int64(p.Maps[i].Start))
		reads++
		c.magicLeft--
		if n < 2 {
			continue
		}
		_ = err
		p.Maps[i].Magic = procfs.ClassifyMagic(buf[:n])
	}
	return false
}

func magicCandidate(r model.Region) bool {
	if r.Path != "" || r.Size() < 4096 || len(r.Perms) < 3 || r.Perms[2] != 'x' {
		return false
	}
	return true
}

func (c *collector) readFDs(p *model.Process, base string) {
	const maxFDs = 8192
	dir := filepath.Join(base, "fd")
	p.FDComplete = false
	f, err := os.Open(dir)
	if err != nil {
		p.Exited = processGone(base, err)
		if !p.Exited {
			c.issue(dir, err)
		} else {
			c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: dir, State: "exited", Detail: "process directory disappeared before file descriptors could be read"})
		}
		return
	}
	// Keep the directory open while reading links. On /proc/self/fd this
	// prevents our own enumeration descriptor from becoming a false failure.
	defer f.Close()
	entries, err := f.ReadDir(maxFDs + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		c.issue(dir, err)
		return
	}
	p.FDComplete = len(entries) <= maxFDs
	if !p.FDComplete {
		entries = entries[:maxFDs]
		c.issue(dir, errTruncated)
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		target, err := os.Readlink(path)
		if err != nil {
			p.FDComplete = false
			c.issue(path, err)
			continue
		}
		if e.Name() == "0" {
			p.Stdin = target
		}
		if ino, ok := procfs.SocketInode(target); ok {
			p.SocketInodes = append(p.SocketInodes, ino)
		}
		if memfdTarget(target) && len(p.MemfdFDs) < 16 {
			p.MemfdFDs = append(p.MemfdFDs, target)
		}
		if sensitiveFD(target) && len(p.SensitiveFDs) < 8 {
			p.SensitiveFDs = append(p.SensitiveFDs, e.Name()+" -> "+target)
		}
	}
}

func sensitiveFD(target string) bool {
	t := strings.TrimSuffix(target, " (deleted)")
	switch {
	case strings.Contains(t, "docker.sock"),
		strings.Contains(t, "containerd.sock"),
		strings.Contains(t, "crio.sock"),
		strings.Contains(t, "ssh-agent"),
		t == "/etc/shadow",
		strings.HasSuffix(t, "/shadow"):
		return true
	default:
		return false
	}
}

func memfdTarget(path string) bool {
	return strings.Contains(strings.TrimSuffix(path, " (deleted)"), "memfd:")
}

func listPIDs(proc string) (map[int]struct{}, error) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	out := make(map[int]struct{})
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		out[pid] = struct{}{}
	}
	return out, nil
}

func union(a, b map[int]struct{}) map[int]struct{} {
	out := make(map[int]struct{}, len(a)+len(b))
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}

func mapKeys(m map[int]struct{}) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func procExists(path string) bool {
	var st syscall.Stat_t
	return syscall.Stat(path, &st) == nil
}

func killExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, syscall.Signal(0))
	return err == nil || err == syscall.EPERM
}

func readLimited(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return b[:max], errTruncated
	}
	return b, nil
}

func readLink(path string) string {
	s, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return s
}
