package explain

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

// StartupBudget bounds how much of cron, systemd, and init is read.
type StartupBudget struct {
	Files int
	Bytes int
	Hit   bool
}

const (
	maxStartupFiles = 2000
	maxStartupBytes = 8 << 20
	maxFileRead     = 48 << 10
)

var startupDirs = []struct {
	rel  string
	kind string
}{
	{"etc/init.d", "init"},
	{"run/systemd/generator.early", "systemd-generated"},
	{"run/systemd/generator", "systemd-generated"},
	{"run/systemd/generator.late", "systemd-generated"},
	{"etc/systemd/system", "systemd"},
	{"lib/systemd/system", "systemd"},
	{"usr/lib/systemd/system", "systemd"},
	{"etc/crontab", "cron"},
	{"etc/cron.d", "cron"},
	{"etc/cron.hourly", "cron"},
	{"etc/cron.daily", "cron"},
	{"etc/cron.weekly", "cron"},
	{"etc/cron.monthly", "cron"},
	{"var/spool/cron", "cron"},
	{"etc/rc.local", "init"},
	{"etc/systemd/user", "systemd-user"},
}

// StartupResult reports each target's hits and whether the shared search
// finished. A partial search never proves absence of persistence.
type StartupResult struct {
	Exact  []model.StartupRef
	Names  []model.StartupRef
	Status string
}

// FindStartupMany reads each startup file once for every selected executable.
// This prevents an early process from consuming the entire scan budget before
// a later process's path is considered.
func FindStartupMany(root string, paths []string) (map[string]StartupResult, []model.ReadIssue) {
	results := map[string]StartupResult{}
	for _, path := range paths {
		path = strings.TrimSuffix(path, " (deleted)")
		if path == "" {
			continue
		}
		if _, skip := genericExe[path]; skip {
			continue
		}
		results[path] = StartupResult{Status: "complete"}
	}
	if len(results) == 0 {
		return results, nil
	}
	budget := StartupBudget{}
	stopped := false
	var gaps []model.ReadIssue
	for _, dir := range startupLocations(root) {
		if budget.Files >= maxStartupFiles || budget.Bytes >= maxStartupBytes {
			stopped = true
			break
		}
		info, err := os.Lstat(dir.path)
		if err != nil {
			continue
		}
		visit := func(path string, isDir bool) error {
			if isDir {
				return nil
			}
			info, statErr := os.Lstat(path)
			if statErr != nil || !info.Mode().IsRegular() {
				return nil
			}
			if budget.Files >= maxStartupFiles || budget.Bytes >= maxStartupBytes {
				stopped = true
				return errStop
			}
			budget.Files++
			file, err := os.Open(path)
			if err != nil {
				gaps = append(gaps, model.ReadIssue{Source: path, State: "denied", Detail: "startup file was not readable"})
				return nil
			}
			body, readErr := io.ReadAll(io.LimitReader(file, maxFileRead+1))
			_ = file.Close()
			if readErr != nil {
				gaps = append(gaps, model.ReadIssue{Source: path, State: "error", Detail: "startup file read failed"})
				return nil
			}
			if len(body) > maxFileRead {
				gaps = append(gaps, model.ReadIssue{Source: path, State: "truncated", Detail: "startup file exceeded 48 KiB; only the first bytes were searched"})
				body = body[:maxFileRead]
			}
			budget.Bytes += len(body)
			text := string(body)
			fileBase := filepath.Base(path)
			for target, result := range results {
				base := filepath.Base(target)
				nameHit := fileBase == base || fileBase == base+".service" || fileBase == base+".timer" || fileBase == base+".sh"
				if len(result.Exact) < 8 && strings.Contains(text, target) {
					result.Exact = append(result.Exact, model.StartupRef{Kind: dir.kind, File: path, Match: "exact-path", Line: firstLineContaining(text, target)})
				} else if nameHit && len(result.Names) < 3 {
					result.Names = append(result.Names, model.StartupRef{Kind: dir.kind, File: path, Match: "name", Line: fileBase})
				}
				results[target] = result
			}
			return nil
		}
		if !info.IsDir() {
			_ = visit(dir.path, false)
		} else {
			_ = filepath.WalkDir(dir.path, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				return visit(path, entry.IsDir())
			})
		}
		if stopped {
			break
		}
	}
	if budget.Files >= maxStartupFiles || budget.Bytes >= maxStartupBytes {
		stopped = true
	}
	if stopped {
		for path, result := range results {
			if len(result.Exact) == 0 {
				result.Status = "partial-budget"
			}
			results[path] = result
		}
		gaps = append(gaps, model.ReadIssue{Source: "startup search", State: "truncated", Detail: "shared startup budget stopped the search; missing matches are inconclusive only for paths with no exact hit"})
	} else if len(gaps) > 0 {
		for path, result := range results {
			if len(result.Exact) == 0 {
				result.Status = "inconclusive"
			}
			results[path] = result
		}
	}
	return results, gaps
}

type startupLoc struct {
	path string
	kind string
}

func startupLocations(root string) []startupLoc {
	out := make([]startupLoc, 0, len(startupDirs)+8)
	for _, dir := range startupDirs {
		out = append(out, startupLoc{path: filepath.Join(root, dir.rel), kind: dir.kind})
	}
	out = append(out, startupLoc{path: filepath.Join(root, "root", ".config", "systemd", "user"), kind: "systemd-user"})
	home := filepath.Join(root, "home")
	entries, err := os.ReadDir(home)
	if err != nil {
		return out
	}
	n := 0
	for _, e := range entries {
		if n >= 64 || !e.IsDir() {
			continue
		}
		n++
		out = append(out, startupLoc{
			path: filepath.Join(home, e.Name(), ".config", "systemd", "user"),
			kind: "systemd-user",
		})
	}
	return out
}

var genericExe = map[string]struct{}{
	"/bin/sh": {}, "/bin/bash": {}, "/bin/dash": {},
	"/usr/bin/sh": {}, "/usr/bin/bash": {}, "/usr/bin/dash": {},
	"/usr/bin/python": {}, "/usr/bin/python3": {}, "/usr/bin/perl": {},
	"/usr/bin/ruby": {}, "/usr/bin/node": {}, "/usr/bin/php": {},
}

// FindStartup looks for an executable path in startup files.
// exact-path hits are lines containing the path. name hits are filenames only.
// A hit is not evidence that this process was started from that file.
func FindStartup(root, exePath string, budget *StartupBudget) (exact, names []model.StartupRef, truncated bool) {
	if budget == nil {
		budget = &StartupBudget{}
	}
	path := strings.TrimSuffix(exePath, " (deleted)")
	if path == "" {
		return nil, nil, false
	}
	if _, skip := genericExe[path]; skip {
		return nil, nil, false
	}
	base := filepath.Base(path)
	for _, dir := range startupLocations(root) {
		if budget.Files >= maxStartupFiles || budget.Bytes >= maxStartupBytes {
			return exact, names, true
		}
		full := dir.path
		info, err := os.Lstat(full)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			ex, nm, stop := scanStartupFile(full, dir.kind, path, base, budget)
			exact = append(exact, ex...)
			names = append(names, nm...)
			if stop {
				return exact, names, true
			}
			continue
		}
		_ = filepath.WalkDir(full, func(name string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if budget.Files >= maxStartupFiles || budget.Bytes >= maxStartupBytes {
				truncated = true
				return errStop
			}
			ex, nm, stop := scanStartupFile(name, dir.kind, path, base, budget)
			exact = append(exact, ex...)
			names = append(names, nm...)
			if stop {
				truncated = true
				return errStop
			}
			if len(exact) >= 8 && len(names) >= 3 {
				return errStop
			}
			return nil
		})
	}
	if len(exact) > 8 {
		exact = exact[:8]
	}
	if len(names) > 3 {
		names = names[:3]
	}
	return exact, names, truncated || budget.Files >= maxStartupFiles || budget.Bytes >= maxStartupBytes
}

func scanStartupFile(name, kind, path, base string, budget *StartupBudget) (exact, names []model.StartupRef, stop bool) {
	budget.Files++
	fileBase := filepath.Base(name)
	nameHit := fileBase == base || fileBase == base+".service" || fileBase == base+".timer" || fileBase == base+".sh"
	f, err := os.Open(name)
	if err != nil {
		if nameHit {
			names = append(names, model.StartupRef{Kind: kind, File: name, Match: "name", Line: fileBase})
		}
		return nil, names, false
	}
	defer f.Close()
	buf := make([]byte, maxFileRead+1)
	n, _ := f.Read(buf)
	if n > maxFileRead {
		n = maxFileRead
		stop = false
	}
	budget.Bytes += n
	text := string(buf[:n])
	if strings.Contains(text, path) {
		line := firstLineContaining(text, path)
		exact = append(exact, model.StartupRef{Kind: kind, File: name, Match: "exact-path", Line: line})
	} else if nameHit {
		// A filename hit is the weaker observation. The same file's exact
		// path line already covers it.
		names = append(names, model.StartupRef{Kind: kind, File: name, Match: "name", Line: fileBase})
	}
	if budget.Bytes >= maxStartupBytes {
		stop = true
	}
	return exact, names, stop
}

func firstLineContaining(text, needle string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			line = strings.TrimSpace(line)
			if len(line) > 180 {
				return line[:177] + "..."
			}
			return line
		}
	}
	return ""
}

type stopErr struct{}

func (stopErr) Error() string { return "stop" }

var errStop = stopErr{}
