package analyze

import (
	"path/filepath"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

func hostFindings(s *model.Snapshot) []model.Finding {
	var out []model.Finding
	if len(s.PreloadPaths) > 0 || s.PreloadTruncated {
		ev := append([]string(nil), s.PreloadPaths...)
		if s.PreloadTruncated {
			ev = append(ev, "ld.so.preload exceeds the 4 KiB read limit; remaining entries were not inspected")
		}
		out = append(out, model.Finding{
			Rule: "HOST-LD-PRELOAD", Severity: model.SevMedium, Category: "process",
			Summary:  "ld.so.preload contains entries or exceeds the read limit",
			Detail:   "The file was read only to list paths, at most 4 KiB. A preload path is an observation. This is separate from LD_PRELOAD in a process environment.",
			Evidence: ev,
		})
	}
	if s.BPFUnprivileged == "enabled" {
		out = append(out, model.Finding{
			Rule: "HOST-BPF-UNPRIV", Severity: model.SevLow, Category: "kernel",
			Summary: "unprivileged BPF is enabled",
			Detail:  "The sysctl was read. No BPF program was loaded or attached. An observability agent can also use BPF.",
		})
	}
	if len(s.BPFPins) > 0 {
		ev := append([]string(nil), s.BPFPins...)
		if len(ev) > 16 {
			ev = append(ev[:16], "additional pin names omitted")
		}
		out = append(out, model.Finding{
			Rule: "HOST-BPF-PIN", Severity: model.SevInfo, Category: "kernel",
			Summary:  "pinned BPF objects are visible",
			Detail:   "Names come from /sys/fs/bpf. A pin is an inventory entry, not a hostile module. No program was loaded or attached.",
			Evidence: ev,
		})
	}
	out = append(out, socketTableFindings(s)...)
	return out
}

func processSignalFindings(s *model.Snapshot, p *model.Process) []model.Finding {
	if p.Kernel() || p.Zombie() {
		return nil
	}
	var out []model.Finding
	out = append(out, shellFinding(s, p)...)
	out = append(out, sensitiveFinding(p)...)
	out = append(out, lateThreadFinding(p)...)
	out = append(out, unownedLibFinding(p)...)
	out = append(out, namespaceFindings(p)...)
	out = append(out, pageFindings(p)...)
	return out
}

func shellFinding(s *model.Snapshot, p *model.Process) []model.Finding {
	if !isInterpreter(p) || !strings.HasPrefix(p.Stdin, "socket:") || !p.TTYKnown || p.TTY != 0 {
		return nil
	}
	ev := []string{"stdin " + p.Stdin, "tty 0", "uid " + itoa(p.UID)}
	if p.PPID != 0 {
		ev = append(ev, "ppid "+itoa(p.PPID))
	}
	for _, line := range socketLines(s, p) {
		ev = append(ev, line)
	}
	return []model.Finding{{
		Rule: "PROC-SOCKET-SHELL", Severity: model.SevMedium, Category: "process",
		PID: p.PID, Process: p.Name,
		Summary:  "shell or interpreter has a socket for standard input and no terminal",
		Detail:   "An interactive shell with a terminal is not this finding. Endpoints are the sockets already attributed to the process. Nothing was contacted.",
		Evidence: capEv(ev),
	}}
}

func sensitiveFinding(p *model.Process) []model.Finding {
	if len(p.SensitiveFDs) == 0 {
		return nil
	}
	return []model.Finding{{
		Rule: "PROC-SENSITIVE-FD", Severity: model.SevLow, Category: "process",
		PID: p.PID, Process: p.Name,
		Summary:  "process holds a container, agent, or shadow descriptor",
		Detail:   "The descriptor path was recorded. The socket, file, and any memfd body were not read.",
		Evidence: append([]string(nil), p.SensitiveFDs...),
	}}
}

func lateThreadFinding(p *model.Process) []model.Finding {
	if len(p.LateThreads) == 0 {
		return nil
	}
	return []model.Finding{{
		Rule: "PROC-LATE-THREAD", Severity: model.SevLow, Category: "process",
		PID: p.PID, Process: p.Name,
		Summary:  "a thread started long after its leader or uses a kernel-style name",
		Detail:   "The check covers selected processes and at most 48 tasks. A large set of threads that share the leader's age is not a finding by count.",
		Evidence: append([]string(nil), p.LateThreads...),
	}}
}

func unownedLibFinding(p *model.Process) []model.Finding {
	if len(p.UnownedLibs) == 0 {
		return nil
	}
	sev := model.SevLow
	for _, line := range p.UnownedLibs {
		if strings.HasPrefix(line, "temporary ") || strings.HasPrefix(line, "deleted ") {
			sev = model.SevMedium
		}
	}
	return []model.Finding{{
		Rule: "PROC-UNOWNED-LIB", Severity: sev, Category: "process",
		PID: p.PID, Process: p.Name,
		Summary:  "a mapped library is temporary, deleted, or absent from the process package",
		Detail:   "A library owned by another package is not flagged for its name. A missing package database stays inconclusive and does not produce this finding.",
		Evidence: append([]string(nil), p.UnownedLibs...),
	}}
}

func namespaceFindings(p *model.Process) []model.Finding {
	var out []model.Finding
	switch p.NetNSView {
	case "changed", "foreign", "denied", "missing", "truncated":
		out = append(out, model.Finding{
			Rule: "PROC-NETNS", Severity: model.SevLow, Category: "network",
			PID: p.PID, Process: p.Name,
			Summary:  "process network namespace is " + p.NetNSView,
			Detail:   "same means the namespace link matched the scanner. foreign means it differed but no extra TCP inode was seen. missing, denied, and truncated are coverage gaps. changed means the namespace socket table had an inode absent from the scanner table. No endpoint was contacted.",
			Evidence: []string{"state " + p.NetNSView},
		})
	}
	switch p.MapFiles {
	case "changed", "denied", "missing":
		detail := p.MapFilesDetail
		if detail == "" {
			detail = "state " + p.MapFiles
		}
		out = append(out, model.Finding{
			Rule: "PROC-MAP-FILES", Severity: model.SevLow, Category: "process",
			PID: p.PID, Process: p.Name,
			Summary:  "executable backing through map_files is " + p.MapFiles,
			Detail:   "missing, denied, and changed are distinct. A readable directory with matching inodes is not a finding.",
			Evidence: []string{detail},
		})
	}
	return out
}

func pageFindings(p *model.Process) []model.Finding {
	if len(p.PageDiffs) == 0 {
		return nil
	}
	return []model.Finding{{
		Rule: "MEM-PAGE-MISMATCH", Severity: model.SevMedium, Category: "memory",
		PID: p.PID, Process: p.Name,
		Summary:  "the first 16 bytes of an executable mapping differ from its backing file",
		Detail:   "This check runs only with -deep and does not inspect later bytes where a hook may sit. JIT, debuggers, and runtimes can also produce a difference. Compared bytes are not stored or executed.",
		Evidence: append([]string(nil), p.PageDiffs...),
	}}
}

func socketTableFindings(s *model.Snapshot) []model.Finding {
	var raw, meta []model.Finding
	for _, sock := range s.Sockets {
		owner, owned := s.SocketOwner[sock.Inode]
		who := "unowned"
		var proc *model.Process
		if owned {
			who = "pid " + itoa(owner)
			for i := range s.Processes {
				if s.Processes[i].PID == owner {
					proc = &s.Processes[i]
					who = "pid " + itoa(owner) + " " + proc.Name
					break
				}
			}
		}
		line := sock.Proto + " " + sock.State + " " + sock.Local + " -> " + sock.Remote + " " + who
		switch sock.Proto {
		case "raw", "raw6", "packet":
			f := model.Finding{
				Rule: "NET-RAW-SOCKET", Severity: model.SevLow, Category: "network",
				Summary:  "raw or packet socket is present",
				Detail:   "A local sniffer can hold this socket. The finding names the owner when the descriptor census attributed it, and says unowned otherwise. Nothing was contacted.",
				Evidence: []string{line},
			}
			if proc != nil {
				f.PID = proc.PID
				f.Process = proc.Name
			} else {
				f.Subject = who
			}
			raw = append(raw, f)
		}
		if strings.Contains(sock.Remote, "169.254.169.254") {
			f := model.Finding{
				Rule: "NET-METADATA", Severity: model.SevLow, Category: "network",
				Summary:  "connection remote address is the cloud metadata address",
				Detail:   "The address was read from the socket table. The tool does not contact it. The instance metadata client can look like this.",
				Evidence: []string{line},
			}
			if proc != nil {
				f.PID = proc.PID
				f.Process = proc.Name
			} else {
				f.Subject = who
			}
			meta = append(meta, f)
		}
	}
	if len(raw) > 8 {
		raw = append(raw[:8], model.Finding{
			Rule: "NET-RAW-SOCKET", Severity: model.SevLow, Category: "network",
			Summary: "additional raw or packet sockets were omitted",
			Detail:  "The inventory stopped after 8 rows.",
		})
	}
	return append(raw, meta...)
}

func isInterpreter(p *model.Process) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSuffix(p.Exe, " (deleted)")))
	switch base {
	case "sh", "bash", "dash", "zsh", "ksh", "fish", "ash", "busybox",
		"python", "python2", "python3", "perl", "ruby", "php", "node",
		"nc", "ncat", "netcat":
		return true
	}
	switch strings.ToLower(p.Name) {
	case "sh", "bash", "dash", "zsh", "ksh", "fish", "python", "python3", "perl", "ruby":
		return true
	}
	return false
}

func socketLines(s *model.Snapshot, p *model.Process) []string {
	if s == nil {
		return nil
	}
	by := map[uint64]model.Socket{}
	for _, sock := range s.Sockets {
		if _, ok := by[sock.Inode]; !ok {
			by[sock.Inode] = sock
		}
	}
	var lines []string
	for _, ino := range p.SocketInodes {
		sock, ok := by[ino]
		if !ok {
			continue
		}
		lines = append(lines, sock.Proto+" "+sock.State+" "+sock.Local+" -> "+sock.Remote)
	}
	return lines
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
