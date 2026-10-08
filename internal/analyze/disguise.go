package analyze

import (
	"path/filepath"
	"strings"

	"github.com/dahnutz/procsift/internal/explain"
	"github.com/dahnutz/procsift/internal/model"
)

// contextualDisguise requires corroborating context, not just an unusual name.
// The result is a triage observation and never an attribution or malware verdict.
func contextualDisguise(s *model.Snapshot, p *model.Process) []model.Finding {
	if p.Kernel() || p.Zombie() || p.Exe == "" {
		return nil
	}
	if s != nil && s.Scanner.Known && p.PID == s.Scanner.PID && p.StartTicks == s.Scanner.StartTicks {
		return nil
	}
	clean := strings.TrimSuffix(p.Exe, " (deleted)")
	base := filepath.Base(clean)
	var reasons []string
	if p.UID == 0 && p.Image != nil && p.Image.State == "unlisted" && p.Image.PackageSource != "snap-mount-observed" {
		if strings.HasPrefix(clean, "/etc/") && (p.Service != "" || hasExactStartup(p)) {
			reasons = append(reasons, "unlisted root executable under /etc with service or startup context")
		}
		if (p.Service != "" || hasExactStartup(p) || len(p.Image.MatchedFiles) > 0) && unusualServicePath(clean) {
			reasons = append(reasons, "service-like executable name at an unexpected path")
		}
	}
	if isDeleted(p.Exe) && p.ExeInfo != nil && p.ExeInfo.Label == explain.LabelUnexplained {
		fields := strings.Fields(p.Cmdline)
		if len(fields) > 0 {
			title := filepath.Base(fields[0])
			if title != "" && title != base && title != p.Name {
				reasons = append(reasons, "deleted image uses a different command-line title")
			}
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	ev := []string{"exe " + p.Exe, "comm " + p.Name, "cmd " + p.Cmdline}
	if p.Service != "" {
		ev = append(ev, "service "+p.Service)
	}
	ev = append(ev, reasons...)
	return []model.Finding{{
		Rule: "PROC-CONTEXT-DISGUISE", Severity: model.SevMedium, Category: "process",
		PID: p.PID, Process: p.Name,
		Summary:  "process identity and execution context warrant review",
		Detail:   "The combined path, title, package, and service observations are unusual. A custom service or retitled process can be legitimate; this is not a name-only malware verdict.",
		Evidence: ev,
	}}
}

func unusualServicePath(path string) bool {
	base := strings.TrimPrefix(strings.ToLower(filepath.Base(path)), ".")
	switch base {
	case "sshd":
		return path != "/usr/sbin/sshd" && path != "/sbin/sshd"
	case "getty", "agetty":
		for _, expected := range []string{"/sbin/getty", "/usr/sbin/getty", "/bin/getty", "/usr/bin/getty", "/sbin/agetty", "/usr/sbin/agetty"} {
			if path == expected {
				return false
			}
		}
		return true
	}
	return false
}
