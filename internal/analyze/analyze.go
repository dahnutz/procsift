package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

const wxMediumMin = 1 << 20 // 1 MiB

// Analyze turns a snapshot into findings. Inventory stays on the snapshot;
// only anomalies are returned here.
func Analyze(s *model.Snapshot) []model.Finding {
	if s == nil {
		return nil
	}
	var out []model.Finding
	out = append(out, taskFindings(s)...)
	out = append(out, fileFindings(s)...)
	for i := range s.Processes {
		p := &s.Processes[i]
		out = append(out, processFindings(p)...)
		out = append(out, memoryFindings(p)...)
		out = append(out, imageFindings(p)...)
		out = append(out, contextFindings(s, p)...)
		out = append(out, processSignalFindings(s, p)...)
	}
	out = append(out, accountFindings(s)...)
	out = append(out, hostFindings(s)...)
	out = append(out, moduleFindings(s)...)
	out = append(out, ipcFindings(s)...)
	out = append(out, netFindings(s)...)
	markScanner(s, out)
	sort.Slice(out, func(i, j int) bool {
		ri := model.SeverityRank(out[i].Severity)
		rj := model.SeverityRank(out[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

func taskFindings(s *model.Snapshot) []model.Finding {
	var out []model.Finding
	ghosts := append([]model.Ghost(nil), s.Ghosts...)
	sort.Slice(ghosts, func(i, j int) bool { return ghosts[i].PID < ghosts[j].PID })
	if len(ghosts) > 40 {
		ev := make([]string, 0, 40)
		for i := 0; i < 40 && i < len(ghosts); i++ {
			ev = append(ev, fmt.Sprintf("pid %d", ghosts[i].PID))
		}
		out = append(out, model.Finding{
			Rule:     "PROC-HIDDEN-TASK",
			Severity: model.SevHigh,
			Category: "process",
			Summary:  fmt.Sprintf("%d tasks answer a pid probe but have no /proc directory", len(ghosts)),
			Detail:   "Each pid returned success or EPERM from kill(pid, 0) and still had no /proc/pid directory on a second check. The first 40 pids are listed.",
			Evidence: ev,
		})
	} else {
		for _, g := range ghosts {
			out = append(out, model.Finding{
				Rule:     "PROC-HIDDEN-TASK",
				Severity: model.SevHigh,
				Category: "process",
				PID:      g.PID,
				Subject:  fmt.Sprintf("pid %d", g.PID),
				Summary:  fmt.Sprintf("pid %d is visible to kill(pid, 0) but has no /proc directory", g.PID),
				Detail:   "Directory listing and a direct lookup both missed this task id. Confirmed with a second probe.",
			})
		}
	}

	ghostSet := map[int]struct{}{}
	for _, g := range s.Ghosts {
		ghostSet[g.PID] = struct{}{}
	}
	for _, p := range s.Processes {
		if p.PPID <= 1 {
			continue
		}
		if _, ok := ghostSet[p.PPID]; !ok {
			continue
		}
		out = append(out, model.Finding{
			Rule:     "PROC-PARENT-HIDDEN",
			Severity: model.SevMedium,
			Category: "process",
			PID:      p.PID,
			Process:  p.Name,
			Summary:  fmt.Sprintf("parent pid %d is a hidden task", p.PPID),
			Detail:   "The parent answers a pid probe but has no /proc directory.",
			Evidence: []string{fmt.Sprintf("ppid %d", p.PPID)},
		})
	}
	return out
}

func processFindings(p *model.Process) []model.Finding {
	var out []model.Finding
	if !p.Listed && !p.Kernel() && !p.Zombie() && p.TGID == p.PID {
		out = append(out, model.Finding{
			Rule:     "PROC-HIDDEN-READDIR",
			Severity: model.SevHigh,
			Category: "process",
			PID:      p.PID,
			Process:  p.Name,
			Summary:  "thread-group leader is missing from the /proc directory listing",
			Detail:   "The /proc/pid directory opens directly and status shows a group leader, but repeated directory reads did not list it.",
			Evidence: []string{fmt.Sprintf("pid %d tgid %d name %s", p.PID, p.TGID, p.Name)},
		})
	}
	if p.Kernel() || p.Zombie() {
		return out
	}
	switch {
	case isMemfd(p.Exe):
		out = append(out, exeFinding("PROC-MEMFD-EXE", model.SevHigh, p, "executable is an anonymous memfd", "The process image is a memory file descriptor, not a file on disk.", p.Exe))
	case isDeleted(p.Exe):
		summary := "executable was deleted and is still running"
		detail := "The /proc/pid/exe symlink points at a deleted inode."
		evidence := []string{p.Exe}
		if p.ExeInfo != nil {
			summary = fmt.Sprintf("executable was deleted and is still running; %s; %s", p.ExeInfo.Relation, p.ExeInfo.Label)
			detail = "The running image was measured separately from whatever is now at the old pathname. The label explains the observation and does not remove it."
			evidence = dossierEvidence(p)
		}
		out = append(out, model.Finding{
			Rule:     "PROC-DELETED-EXE",
			Severity: model.SevHigh,
			Category: "process",
			PID:      p.PID,
			Process:  p.Name,
			Summary:  summary,
			Detail:   detail,
			Evidence: evidence,
		})
	case isFDExe(p.Exe):
		out = append(out, exeFinding("PROC-FD-EXE", model.SevHigh, p, "executable is a /proc file descriptor", "The process was started from a file descriptor path rather than a stable filesystem path.", p.Exe))
	case isTempPath(p.Exe):
		out = append(out, exeFinding("PROC-TEMP-EXE", model.SevMedium, p, "executable lives under a temporary or shared-memory path", "Binaries launched from these directories are a common staging location.", p.Exe))
	}
	if p.LDPreload != "" {
		out = append(out, model.Finding{
			Rule:     "PROC-LD-PRELOAD",
			Severity: model.SevMedium,
			Category: "process",
			PID:      p.PID,
			Process:  p.Name,
			Summary:  "LD_PRELOAD is set",
			Detail:   "An injected library is loaded ahead of the normal dynamic linker search.",
			Evidence: []string{"LD_PRELOAD=" + p.LDPreload},
		})
	}
	if p.LDAudit != "" {
		out = append(out, model.Finding{
			Rule:     "PROC-LD-AUDIT",
			Severity: model.SevMedium,
			Category: "process",
			PID:      p.PID,
			Process:  p.Name,
			Summary:  "LD_AUDIT is set",
			Detail:   "The dynamic linker will load an audit module into this process.",
			Evidence: []string{"LD_AUDIT=" + p.LDAudit},
		})
	}
	if isTempPath(p.LDLibrary) || containsTemp(p.LDLibrary) {
		out = append(out, model.Finding{
			Rule:     "PROC-LD-LIBRARY",
			Severity: model.SevMedium,
			Category: "process",
			PID:      p.PID,
			Process:  p.Name,
			Summary:  "LD_LIBRARY_PATH includes a temporary or shared-memory directory",
			Evidence: []string{"LD_LIBRARY_PATH=" + p.LDLibrary},
		})
	}
	if p.TracerPID > 0 {
		out = append(out, model.Finding{
			Rule:     "PROC-TRACED",
			Severity: model.SevLow,
			Category: "process",
			PID:      p.PID,
			Process:  p.Name,
			Summary:  fmt.Sprintf("process is being traced by pid %d", p.TracerPID),
			Detail:   "A tracer can be a debugger or a process injecting code through ptrace.",
		})
	}
	if len(p.MemfdFDs) > 0 && !isMemfd(p.Exe) {
		out = append(out, model.Finding{
			Rule:     "PROC-MEMFD-FD",
			Severity: model.SevLow,
			Category: "process",
			PID:      p.PID,
			Process:  p.Name,
			Summary:  "process holds a memfd file descriptor",
			Detail:   "A memory file is open. Toolkits use this for ordinary buffers. It is raised only as context unless the memfd is the executable image or an executable mapping.",
			Evidence: capEv(p.MemfdFDs),
		})
	}
	return out
}

func containsTemp(pathList string) bool {
	if pathList == "" {
		return false
	}
	for _, part := range strings.Split(pathList, ":") {
		if isTempPath(part) {
			return true
		}
	}
	return false
}

func exeFinding(rule, sev string, p *model.Process, summary, detail, evidence string) model.Finding {
	return model.Finding{
		Rule:     rule,
		Severity: sev,
		Category: "process",
		PID:      p.PID,
		Process:  p.Name,
		Summary:  summary,
		Detail:   detail,
		Evidence: []string{evidence},
	}
}

func memoryFindings(p *model.Process) []model.Finding {
	if p.Kernel() || p.Zombie() || !p.MapsOK {
		return nil
	}
	var deleted, memfd, temp, heap, stack, fileWX, anonExec, embedded, scripts []string
	var wx []string
	var largest uint64
	fileless := isMemfd(p.Exe) || isDeleted(p.Exe) || isFDExe(p.Exe)

	for _, r := range p.Maps {
		if r.Size() == 0 {
			continue
		}
		ev := fmt.Sprintf("%x-%x %s %s size=%d", r.Start, r.End, r.Perms, dispPath(r.Path), r.Size())
		exec := permExec(r.Perms)
		wxRegion := exec && permWrite(r.Perms)
		if specialRegion(r.Path) {
			continue
		}
		switch {
		case exec && isDeleted(r.Path):
			deleted = append(deleted, deletedMapLine(p, r.Path, ev))
		case exec && isMemfd(r.Path):
			memfd = append(memfd, ev)
		case r.Magic == "elf" || r.Magic == "mz":
			embedded = append(embedded, ev+" magic="+r.Magic)
		case r.Magic == "shebang":
			scripts = append(scripts, ev)
		case exec && isHeap(r.Path):
			heap = append(heap, ev)
		case exec && isStack(r.Path):
			stack = append(stack, ev)
		case exec && isTempPath(r.Path):
			temp = append(temp, ev)
		case wxRegion && r.Path == "":
			wx = append(wx, ev)
			if r.Size() > largest {
				largest = r.Size()
			}
		case wxRegion:
			fileWX = append(fileWX, ev)
		case exec && r.Path == "" && r.Size() >= 4096:
			anonExec = append(anonExec, ev)
		}
	}

	var out []model.Finding
	out = append(out, regionFinding("MEM-DELETED-EXEC", model.SevHigh, "memory", p, "executable mapping is marked deleted", "A mapped executable file no longer has a directory entry.", deleted)...)
	out = append(out, regionFinding("MEM-MEMFD", model.SevHigh, "memory", p, "executable mapping is a memfd", "Anonymous executable memory is backed by a memory file descriptor.", memfd)...)
	out = append(out, regionFinding("MEM-EMBEDDED-IMAGE", model.SevHigh, "memory", p, "anonymous executable mapping starts with an ELF or PE header", "The first bytes of the mapping look like a file image loaded in memory.", embedded)...)
	out = append(out, regionFinding("MEM-EMBEDDED-SCRIPT", model.SevMedium, "memory", p, "anonymous executable mapping starts with a script header", "", scripts)...)
	out = append(out, regionFinding("MEM-HEAP-EXEC", model.SevMedium, "memory", p, "heap is executable", "", heap)...)
	out = append(out, regionFinding("MEM-STACK-EXEC", model.SevMedium, "memory", p, "stack is executable", "", stack)...)
	out = append(out, regionFinding("MEM-TEMP-EXEC", model.SevMedium, "memory", p, "executable mapping comes from a temporary or shared-memory path", "", temp)...)
	out = append(out, regionFinding("MEM-WX-FILE", model.SevLow, "memory", p, "file-backed mapping is writable and executable", "", fileWX)...)
	out = append(out, regionFinding("MEM-ANON-EXEC", model.SevLow, "memory", p, "anonymous mapping is executable", "The mapping is executable, not writable, and has no file path.", anonExec)...)

	if len(wx) > 0 {
		sev := model.SevLow
		detail := "Anonymous writable and executable memory. A known runtime stays low. A region of at least 1 MiB in another program is medium. A fileless image raises this to high."
		switch {
		case fileless:
			sev = model.SevHigh
			detail = "Anonymous writable and executable memory in a process whose image is deleted, a memfd, or a file descriptor."
		case !jitHost(p.Exe) && largest >= wxMediumMin:
			sev = model.SevMedium
			detail = "The largest anonymous writable and executable region is at least 1 MiB and the executable is not a known JIT runtime."
		}
		exe := p.Exe
		if exe == "" {
			exe = "(unreadable)"
		}
		evidence := append([]string{"exe " + exe}, capEv(wx)...)
		out = append(out, model.Finding{
			Rule:     "MEM-WX-ANON",
			Severity: sev,
			Category: "memory",
			PID:      p.PID,
			Process:  p.Name,
			Summary:  fmt.Sprintf("%d anonymous writable+executable region(s), largest %d bytes", len(wx), largest),
			Detail:   detail,
			Evidence: evidence,
		})
	}
	return out
}

func regionFinding(rule, sev, cat string, p *model.Process, summary, detail string, evidence []string) []model.Finding {
	if len(evidence) == 0 {
		return nil
	}
	return []model.Finding{{
		Rule:     rule,
		Severity: sev,
		Category: cat,
		PID:      p.PID,
		Process:  p.Name,
		Summary:  summary,
		Detail:   detail,
		Evidence: capEv(evidence),
	}}
}

func moduleFindings(s *model.Snapshot) []model.Finding {
	if !s.ModulesOK || !s.SysfsOK {
		return nil
	}
	var out []model.Finding
	seen := map[string]struct{}{}
	var unsigned, oot, prop []string
	for _, m := range s.Modules {
		seen[m.Name] = struct{}{}
		if _, ok := s.SysfsNames[m.Name]; !ok {
			out = append(out, model.Finding{
				Rule:     "MOD-NO-SYSFS",
				Severity: model.SevHigh,
				Category: "module",
				Subject:  m.Name,
				Summary:  fmt.Sprintf("module %s is in /proc/modules but not in /sys/module", m.Name),
				Detail:   "A loaded module normally has a sysfs directory. A missing directory can mean the sysfs view was altered.",
				Evidence: []string{fmt.Sprintf("state %s address %s taints %s", m.State, m.Address, m.Taints)},
			})
		}
		switch {
		case strings.Contains(m.Taints, "E"):
			unsigned = append(unsigned, m.Name)
		default:
			if strings.Contains(m.Taints, "O") {
				oot = append(oot, m.Name)
			}
			if strings.Contains(m.Taints, "P") {
				prop = append(prop, m.Name)
			}
		}
	}
	for _, name := range s.SysfsLoadable {
		if _, ok := seen[name]; ok {
			continue
		}
		out = append(out, model.Finding{
			Rule:     "MOD-NO-PROC",
			Severity: model.SevHigh,
			Category: "module",
			Subject:  name,
			Summary:  fmt.Sprintf("module %s looks loadable in sysfs but is absent from /proc/modules", name),
			Detail:   "The sysfs entry has loadable-module files (initstate, refcnt, coresize, or sections) that built-in modules do not have.",
		})
	}
	out = append(out, nameListFinding("MOD-UNSIGNED", model.SevMedium, "unsigned kernel module(s) loaded", unsigned)...)
	out = append(out, nameListFinding("MOD-OUT-OF-TREE", model.SevLow, "out-of-tree kernel module(s) loaded", oot)...)
	out = append(out, nameListFinding("MOD-PROPRIETARY", model.SevLow, "proprietary kernel module(s) loaded", prop)...)
	return out
}

func nameListFinding(rule, sev, summary string, names []string) []model.Finding {
	if len(names) == 0 {
		return nil
	}
	return []model.Finding{{
		Rule:     rule,
		Severity: sev,
		Category: "module",
		Summary:  fmt.Sprintf("%d %s", len(names), summary),
		Evidence: capEv(names),
	}}
}

func ipcFindings(s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, seg := range s.SysV {
		if seg.Nattch == 0 && seg.Size > 0 {
			out = append(out, model.Finding{
				Rule:     "IPC-ORPHAN-SHM",
				Severity: model.SevLow,
				Category: "ipc",
				Subject:  fmt.Sprintf("shmid %d", seg.ID),
				Summary:  fmt.Sprintf("SysV segment %d has no attachments and still occupies %d bytes", seg.ID, seg.Size),
				Detail:   "A detached segment remains in RAM until it is removed.",
			})
		}
		if seg.Perms&0111 != 0 {
			out = append(out, model.Finding{
				Rule:     "IPC-SHM-EXEC",
				Severity: model.SevMedium,
				Category: "ipc",
				Subject:  fmt.Sprintf("shmid %d", seg.ID),
				Summary:  fmt.Sprintf("SysV segment %d permissions include execute", seg.ID),
				Evidence: []string{fmt.Sprintf("mode %#o size %d", seg.Perms, seg.Size)},
			})
		}
	}
	for _, f := range s.DevShm {
		if f.Magic == "" && !f.Executable {
			continue
		}
		sev := model.SevMedium
		bits := []string{}
		if f.Executable {
			bits = append(bits, "executable bit")
		}
		if f.Magic != "" {
			bits = append(bits, f.Magic+" header")
		}
		out = append(out, model.Finding{
			Rule:     "IPC-DEVSHM-FILE",
			Severity: sev,
			Category: "ipc",
			Subject:  f.Name,
			Summary:  fmt.Sprintf("/dev/shm/%s has %s", f.Name, strings.Join(bits, " and ")),
			Detail:   "Shared-memory files are a common place to stage a payload.",
			Evidence: []string{fmt.Sprintf("size %d", f.Size)},
		})
	}
	return out
}

func netFindings(s *model.Snapshot) []model.Finding {
	if s.NetIncomplete {
		return nil
	}
	var out []model.Finding
	for _, sock := range s.NetOrphans {
		if sock.Inode == 0 {
			continue
		}
		if _, ok := s.SocketOwner[sock.Inode]; ok {
			continue
		}
		// TIME_WAIT and CLOSE have no userspace owner.
		if sock.StateID == 6 || sock.StateID == 7 {
			continue
		}
		ev := fmt.Sprintf("%s %s %s -> %s inode %d uid %d", sock.Proto, sock.State, sock.Local, sock.Remote, sock.Inode, sock.UID)
		switch {
		case sock.Proto == "udp" || sock.Proto == "udp6":
			if sock.StateID != 1 {
				continue
			}
			out = append(out, model.Finding{
				Rule:     "NET-ORPHAN-UDP",
				Severity: model.SevMedium,
				Category: "network",
				Subject:  fmt.Sprintf("inode %d", sock.Inode),
				Summary:  "connected UDP socket was not attributed in two observations",
				Detail:   "The same socket was present before and after a fresh descriptor census, with no visible owner in either census. This is an observation, not proof of concealment.",
				Evidence: []string{ev},
			})
		case sock.StateID == 1 || sock.StateID == 10:
			out = append(out, model.Finding{
				Rule:     "NET-ORPHAN-SOCKET",
				Severity: model.SevMedium,
				Category: "network",
				Subject:  fmt.Sprintf("inode %d", sock.Inode),
				Summary:  fmt.Sprintf("%s socket in state %s was not attributed in two observations", sock.Proto, sock.State),
				Detail:   "No visible owner was found in two descriptor censuses. Kernel-held sockets, namespace visibility, and changes between reads can also explain this observation; concealment is not established.",
				Evidence: []string{ev},
			})
		default:
			out = append(out, model.Finding{
				Rule:     "NET-ORPHAN-SOCKET",
				Severity: model.SevMedium,
				Category: "network",
				Subject:  fmt.Sprintf("inode %d", sock.Inode),
				Summary:  fmt.Sprintf("%s socket in state %s was not attributed in two observations", sock.Proto, sock.State),
				Evidence: []string{ev},
			})
		}
	}
	return out
}

func capEv(in []string) []string {
	if len(in) <= 8 {
		return append([]string(nil), in...)
	}
	out := append([]string(nil), in[:8]...)
	out = append(out, fmt.Sprintf("+%d more", len(in)-8))
	return out
}
