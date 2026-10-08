package explain

import (
	"path/filepath"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

// Service titles compared with the executable. This is not a list of safe programs.
var serviceTitles = map[string]struct{}{
	"sshd": {}, "nginx": {}, "apache2": {}, "httpd": {}, "cron": {}, "crond": {},
	"systemd": {}, "systemd-logind": {}, "dbus-daemon": {}, "rsyslogd": {},
	"auditd": {}, "snmpd": {},
}

func isInterpreter(base string) bool {
	base = strings.ToLower(base)
	switch base {
	case "sh", "bash", "dash", "python", "python3", "perl", "ruby", "node", "nodejs", "php":
		return true
	}
	for _, pre := range []string{"python", "perl", "ruby", "php"} {
		if strings.HasPrefix(base, pre) {
			return true
		}
	}
	return false
}

func kernelStyle(name string) bool {
	return len(name) >= 3 && strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]")
}

func commTruncation(comm, exeBase string) bool {
	if comm == "" || exeBase == "" {
		return false
	}
	return strings.HasPrefix(exeBase, comm) && (comm == exeBase || len(comm) >= 15)
}

// Masquerade reports a title that disagrees with the executable.
// ok is false when the fields have a routine explanation, such as a truncated comm
// or an interpreter retitled to its own script name.
func Masquerade(p model.Process) (rule, summary, detail string, evidence []string, ok bool) {
	if p.Kernel() || p.Zombie() || p.Exe == "" {
		return "", "", "", nil, false
	}
	exeBase := filepath.Base(stripDeletedLocal(p.Exe))
	comm := strings.TrimSpace(p.Name)
	if comm == "" || commTruncation(comm, exeBase) || comm == exeBase {
		return "", "", "", nil, false
	}
	script := scriptArg(p.Cmdline)
	if script != "" && filepath.Base(script) == comm && !isServiceTitle(comm) {
		return "", "", "", nil, false
	}
	evidence = []string{
		"comm " + comm,
		"exe " + p.Exe,
		"kthread " + kthreadWord(p),
		"ppid " + itoa(uint64(p.PPID)),
	}
	if p.Service != "" {
		evidence = append(evidence, "service "+p.Service)
	}
	if p.Cmdline != "" {
		evidence = append(evidence, "cmd "+p.Cmdline)
	}
	if kernelStyle(comm) {
		return "PROC-KTHREAD-MASQ",
			"userspace executable is displayed with a kernel-thread title",
			"The comm field looks like a kernel thread, the kernel did not mark the task as a kernel thread, and an executable path is present. The mismatch is the observation.",
			evidence, true
	}
	if isServiceTitle(comm) && (isInterpreter(exeBase) || isTempLocal(p.Exe)) {
		return "PROC-TITLE-MASQ",
			"displayed name is a service title and the executable is not that service",
			"An interpreter or a temporary path is using a familiar service name. Wrappers can retitle themselves. This report does not treat the name as proof of the executable.",
			evidence, true
	}
	return "", "", "", nil, false
}

func kthreadWord(p model.Process) string {
	if !p.KthreadKnown {
		return "unknown"
	}
	return boolWord(p.Kthread)
}

func isServiceTitle(name string) bool {
	_, ok := serviceTitles[strings.ToLower(name)]
	return ok
}

func scriptArg(cmdline string) string {
	fields := strings.Fields(cmdline)
	if len(fields) < 2 {
		return ""
	}
	if strings.HasPrefix(fields[1], "/") || strings.HasPrefix(fields[1], "./") {
		return fields[1]
	}
	return ""
}

func stripDeletedLocal(path string) string {
	return strings.TrimSuffix(path, " (deleted)")
}

func isTempLocal(path string) bool {
	p := stripDeletedLocal(path)
	for _, pre := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/var/run/shm/", "/run/user/"} {
		if p == strings.TrimSuffix(pre, "/") || strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// Lineage walks parents, including the process itself, and stops at pid 0/1 or a cycle.
func Lineage(byPID map[int]model.Process, pid, max int) []string {
	if max <= 0 {
		max = 8
	}
	var lines []string
	seen := map[int]struct{}{}
	for hops := 0; hops < max && pid > 1; hops++ {
		if _, ok := seen[pid]; ok {
			lines = append(lines, "cycle at pid "+itoa(uint64(pid)))
			break
		}
		seen[pid] = struct{}{}
		p, ok := byPID[pid]
		if !ok {
			lines = append(lines, "pid "+itoa(uint64(pid))+" not in the snapshot")
			break
		}
		exe := p.Exe
		if exe == "" {
			exe = "-"
		}
		lines = append(lines, "pid "+itoa(uint64(p.PID))+" ppid "+itoa(uint64(p.PPID))+" uid "+itoa(uint64(p.UID))+" "+p.Name+" exe "+exe)
		pid = p.PPID
	}
	if pid == 1 {
		if p, ok := byPID[1]; ok {
			if _, dup := seen[1]; !dup {
				exe := p.Exe
				if exe == "" {
					exe = "-"
				}
				lines = append(lines, "pid 1 ppid "+itoa(uint64(p.PPID))+" uid "+itoa(uint64(p.UID))+" "+p.Name+" exe "+exe)
			}
		}
	}
	return lines
}
