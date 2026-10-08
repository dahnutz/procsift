package analyze

import (
	"path/filepath"
	"strings"
)

func stripDeleted(path string) string {
	return strings.TrimSuffix(path, " (deleted)")
}

func isDeleted(path string) bool {
	return path != "" && strings.HasSuffix(path, " (deleted)")
}

func isMemfd(path string) bool {
	p := stripDeleted(path)
	return strings.HasPrefix(p, "/memfd:") || strings.HasPrefix(p, "memfd:") || strings.Contains(p, "/memfd:")
}

func isFDExe(path string) bool {
	p := stripDeleted(path)
	return strings.HasPrefix(p, "/proc/") && strings.Contains(p, "/fd/")
}

func isTempPath(path string) bool {
	p := stripDeleted(path)
	if p == "" {
		return false
	}
	prefixes := []string{
		"/tmp/",
		"/var/tmp/",
		"/dev/shm/",
		"/run/shm/",
		"/var/run/shm/",
		"/run/user/",
	}
	for _, pre := range prefixes {
		base := strings.TrimSuffix(pre, "/")
		if p == base || strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func isHeap(path string) bool { return path == "[heap]" }

func isStack(path string) bool {
	return path == "[stack]" || strings.HasPrefix(path, "[stack:")
}

func specialRegion(path string) bool {
	switch path {
	case "[vdso]", "[vvar]", "[vsyscall]", "[uprobes]", "[sigpage]", "[vectors]", "[vvar_vclock]":
		return true
	default:
		return false
	}
}

func permExec(perms string) bool {
	return len(perms) >= 3 && perms[2] == 'x'
}

func permWrite(perms string) bool {
	return len(perms) >= 2 && perms[1] == 'w'
}

// jitHost is true for runtimes that commonly create writable executable pages.
// This only lowers the severity of anonymous W+X findings. It does not hide a
// deleted executable, a memfd, or an embedded ELF or PE header.
func jitHost(exe string) bool {
	base := strings.ToLower(filepath.Base(stripDeleted(exe)))
	switch base {
	case "node", "nodejs", "java", "javaw", "deno", "bun", "d8",
		"ruby", "mono", "dotnet", "pwsh", "powershell",
		"chrome", "chromium", "chromium-browser", "firefox", "firefox-esr", "thunderbird",
		"electron", "code", "cursor", "beam.smp", "dart", "luajit",
		"qemu-system-x86_64", "qemu-x86_64", "qemu-system-aarch64":
		return true
	}
	for _, pre := range []string{"python", "ruby", "perl", "php", "lua"} {
		if strings.HasPrefix(base, pre) {
			return true
		}
	}
	return false
}

func dispPath(path string) string {
	if path == "" {
		return "[anonymous]"
	}
	return path
}
