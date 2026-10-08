package explain

import (
	"sort"
	"strings"
)

// trustPaths are executables the scan hashes when they are running.
// Membership means the path is checked. It does not mean the path is trusted.
var trustPaths = map[string]struct{}{
	"/bin/su": {}, "/usr/bin/su": {},
	"/bin/sudo": {}, "/usr/bin/sudo": {},
	"/usr/bin/pkexec": {},
	"/bin/login":      {}, "/usr/bin/login": {},
	"/usr/bin/passwd": {},
	"/usr/sbin/sshd":  {}, "/usr/bin/ssh": {},
	"/bin/bash": {}, "/usr/bin/bash": {}, "/bin/sh": {}, "/usr/bin/sh": {}, "/bin/dash": {}, "/usr/bin/dash": {},
	"/bin/ls": {}, "/usr/bin/ls": {}, "/bin/ps": {}, "/usr/bin/ps": {},
	"/usr/bin/find": {}, "/usr/bin/ss": {}, "/bin/ss": {}, "/usr/bin/netstat": {}, "/bin/netstat": {},
	"/usr/bin/curl": {}, "/usr/bin/wget": {},
	"/usr/bin/lsof":    {},
	"/usr/bin/crontab": {}, "/usr/sbin/cron": {}, "/usr/sbin/crond": {},
	"/usr/bin/systemctl": {}, "/bin/systemctl": {},
	"/usr/bin/python3": {}, "/usr/bin/python": {},
}

// CriticalPaths is the fixed, bounded on-disk utility set. It does not imply trust.
func CriticalPaths() []string {
	out := make([]string, 0, len(trustPaths))
	for path := range trustPaths {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// IsTrustPath reports whether a still-linked executable path is in the bounded check set.
func IsTrustPath(path string) bool {
	_, ok := trustPaths[path]
	return ok
}

// ShouldHashImage reports whether a live process is in the bounded integrity set:
// uid 0, or a trust-critical path. Deleted, memfd, and file-descriptor images are excluded.
func ShouldHashImage(uid int, exe string, kernel, zombie bool) bool {
	if kernel || zombie {
		return false
	}
	if exe == "" || strings.HasSuffix(exe, " (deleted)") {
		return false
	}
	if strings.Contains(exe, "memfd:") {
		return false
	}
	if strings.HasPrefix(exe, "/proc/") && strings.Contains(exe, "/fd/") {
		return false
	}
	return uid == 0 || IsTrustPath(exe)
}
