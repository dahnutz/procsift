package analyze

import (
	"fmt"
	"strings"

	"github.com/dahnutz/procsift/internal/explain"
	"github.com/dahnutz/procsift/internal/model"
)

func imageFindings(p *model.Process) []model.Finding {
	if p.Image == nil || p.Kernel() || p.Zombie() {
		return nil
	}
	img := p.Image
	var related []model.Finding
	if len(img.MatchedFiles) > 0 {
		ev := []string{"running image sha256 " + img.SHA256}
		for _, path := range img.MatchedFiles {
			ev = append(ev, "same full hash as changed utility "+path)
		}
		related = append(related, model.Finding{
			Rule: "PROC-FILE-MATCH", Severity: model.SevMedium, Category: "process",
			PID: p.PID, Process: p.Name,
			Summary:  "running root image matches a utility that differs from its package manifest",
			Detail:   "Full SHA-256 hashes match. This links the images; the local package manifest is not independently trusted and the match does not establish intent.",
			Evidence: ev,
		})
	}
	switch img.State {
	case "mismatch":
		return append(related, model.Finding{
			Rule: "PROC-PKG-MISMATCH", Severity: model.SevMedium, Category: "process",
			PID: p.PID, Process: p.Name,
			Summary: "running image does not match the package manifest",
			Detail:  "The MD5 of the running executable differs from the local dpkg md5sums entry. That database is the reference and is not independently trusted. The path still exists.",
			Evidence: []string{
				"path " + img.Path,
				"package " + emptyPkg(img.Package),
				fmt.Sprintf("md5 %s manifest %s scope %s bytes %d", emptyPkg(img.MD5), emptyPkg(img.Manifest), emptyPkg(img.Scope), img.Bytes),
				fmt.Sprintf("identity-stable %s", yesNo(img.IdentityOK)),
			},
		})
	case "unlisted":
		if p.UID != 0 && !explain.IsTrustPath(img.Path) {
			return nil
		}
		if img.PackageSource == "snap-mount-observed" {
			return append(related, model.Finding{
				Rule: "PROC-PKG-OTHER-SOURCE", Severity: model.SevLow, Category: "process",
				PID: p.PID, Process: p.Name,
				Summary:  "executable is absent from dpkg and lies on an observed Snap mount",
				Detail:   "A squashfs mount under /snap was observed. This explains why dpkg does not list the path; it does not verify the mounted image or declare the process safe.",
				Evidence: []string{"path " + img.Path, "package source snap mount observed; integrity unverified"},
			})
		}
		rule := "PROC-PKG-UNLISTED"
		sev := model.SevLow
		summary := "executable path is not listed by a package"
		if p.UID == 0 {
			rule = "PROC-UNPACKAGED-ROOT"
			sev = model.SevMedium
			summary = "root process executable is not listed by a package"
		}
		return append(related, model.Finding{
			Rule: rule, Severity: sev, Category: "process",
			PID: p.PID, Process: p.Name,
			Summary:  summary,
			Detail:   unpackagedDetail(p),
			Evidence: unpackagedEvidence(p, img),
		})
	case "no-manifest":
		return append(related, model.Finding{
			Rule: "PROC-PKG-NOMANIFEST", Severity: model.SevLow, Category: "process",
			PID: p.PID, Process: p.Name,
			Summary:  "package lists this path but no manifest hash was found",
			Detail:   "Without a manifest hash the comparison is inconclusive. This is not a mismatch.",
			Evidence: []string{"path " + img.Path, "package " + emptyPkg(img.Package)},
		})
	default:
		return related
	}
}

func unpackagedDetail(p *model.Process) string {
	if isTempPath(p.Exe) {
		return "The executable is under temporary or shared-memory storage and no dpkg package lists it."
	}
	if hasExactStartup(p) {
		return "No dpkg package lists this executable. A startup file names the path, which is consistent with a locally installed service and is not a clearance."
	}
	if p.Service != "" {
		return "No dpkg package lists this executable. It is a member of a service cgroup. Membership is not a clearance."
	}
	return "No dpkg package lists this executable."
}

func unpackagedEvidence(p *model.Process, img *model.ImageCheck) []string {
	user := p.User
	if user == "" {
		user = "-"
	}
	svc := p.Service
	if svc == "" {
		svc = "none"
	}
	ev := []string{
		"path " + img.Path,
		fmt.Sprintf("uid %d user %s", p.UID, user),
		"package none",
		"service " + svc,
	}
	for _, hit := range p.Startup {
		if hit.Match == "exact-path" {
			ev = append(ev, "startup "+hit.Kind+" "+hit.File)
			break
		}
	}
	return ev
}

func hasExactStartup(p *model.Process) bool {
	for _, hit := range p.Startup {
		if hit.Match == "exact-path" {
			return true
		}
	}
	return false
}

func accountFindings(s *model.Snapshot) []model.Finding {
	if s == nil || len(s.ExtraUID0) == 0 {
		return nil
	}
	ev := make([]string, 0, len(s.ExtraUID0))
	for _, name := range s.ExtraUID0 {
		ev = append(ev, "uid 0 account "+name)
	}
	return []model.Finding{{
		Rule: "PROC-EXTRA-UID0", Severity: model.SevMedium, Category: "process",
		Summary:  "an account other than root has uid 0",
		Detail:   "The passwd name and uid were read. The password field was not copied. An extra uid 0 account is an observation, not a verdict.",
		Evidence: ev,
	}}
}

func markScanner(s *model.Snapshot, findings []model.Finding) {
	if s == nil || !s.Scanner.Known {
		return
	}
	ticks := map[int]uint64{}
	for _, p := range s.Processes {
		ticks[p.PID] = p.StartTicks
	}
	for i := range findings {
		if findings[i].PID == 0 || findings[i].PID != s.Scanner.PID {
			continue
		}
		if ticks[findings[i].PID] != s.Scanner.StartTicks {
			continue
		}
		findings[i].Origin = "scanner_self"
	}
}

func emptyPkg(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
