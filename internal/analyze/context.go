package analyze

import (
	"fmt"
	"strings"

	"github.com/dahnutz/procsift/internal/explain"
	"github.com/dahnutz/procsift/internal/model"
)

func dossierEvidence(p *model.Process) []string {
	boot := ""
	if p.ExeInfo != nil {
		boot = p.ExeInfo.BootID
	}
	return explain.DossierLines(boot, *p, p.ExeInfo)
}

func deletedMapLine(p *model.Process, path, ev string) string {
	for _, item := range p.DeletedMaps {
		if item.Path != path {
			continue
		}
		pkg := item.Package
		if pkg == "" {
			pkg = "none"
		}
		return fmt.Sprintf("%s relation %s label %s package %s", ev, item.Relation, item.Label, pkg)
	}
	return ev
}

func contextFindings(s *model.Snapshot, p *model.Process) []model.Finding {
	if p.Kernel() || p.Zombie() {
		return nil
	}
	var out []model.Finding
	if rule, summary, detail, evidence, ok := explain.Masquerade(*p); ok {
		out = append(out, model.Finding{
			Rule: rule, Severity: model.SevMedium, Category: "process",
			PID: p.PID, Process: p.Name, Summary: summary, Detail: detail, Evidence: evidence,
		})
	}
	out = append(out, contextualDisguise(s, p)...)
	if !needsJoins(p) {
		return out
	}
	out = append(out, lineageFinding(s, p)...)
	out = append(out, socketFinding(s, p)...)
	out = append(out, startupFindings(p)...)
	out = append(out, unitFinding(p)...)
	return out
}

func needsJoins(p *model.Process) bool {
	if isDeleted(p.Exe) || isMemfd(p.Exe) || isFDExe(p.Exe) || isTempPath(p.Exe) || !p.Listed {
		return true
	}
	if p.LDPreload != "" || p.LDAudit != "" || len(p.DeletedMaps) > 0 || len(p.Startup) > 0 {
		return true
	}
	if p.Image != nil {
		switch p.Image.State {
		case "mismatch", "unlisted", "no-manifest":
			return true
		}
	}
	_, _, _, _, ok := explain.Masquerade(*p)
	return ok
}

func lineageFinding(s *model.Snapshot, p *model.Process) []model.Finding {
	by := map[int]model.Process{}
	for _, other := range s.Processes {
		by[other.PID] = other
	}
	lines := explain.Lineage(by, p.PID, 8)
	if len(lines) == 0 {
		return nil
	}
	return []model.Finding{{
		Rule:     "PROC-LINEAGE",
		Severity: model.SevLow,
		Category: "process",
		PID:      p.PID,
		Process:  p.Name,
		Summary:  "parent chain for this process",
		Detail:   "Parents are listed as observed in this snapshot. A missing parent is not by itself a hidden process.",
		Evidence: lines,
	}}
}

func socketFinding(s *model.Snapshot, p *model.Process) []model.Finding {
	if !p.FDComplete {
		return []model.Finding{{
			Rule:     "PROC-SOCKETS",
			Severity: model.SevLow,
			Category: "network",
			PID:      p.PID,
			Process:  p.Name,
			Summary:  "sockets owned by this process were not fully readable",
			Detail:   "The file-descriptor table was incomplete, so an empty connection list would not mean the process has no sockets.",
			Evidence: []string{"netns " + emptyNet(p.NetNS)},
		}}
	}
	byInode := map[uint64]model.Socket{}
	for _, sock := range s.Sockets {
		if _, ok := byInode[sock.Inode]; !ok {
			byInode[sock.Inode] = sock
		}
	}
	var lines []string
	for _, ino := range p.SocketInodes {
		sock, ok := byInode[ino]
		if !ok {
			lines = append(lines, fmt.Sprintf("inode %d descriptor only; not in the scanned socket tables netns %s", ino, emptyNet(p.NetNS)))
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %s %s -> %s inode %d netns %s", sock.Proto, sock.State, sock.Local, sock.Remote, sock.Inode, emptyNet(p.NetNS)))
	}
	if len(lines) == 0 {
		return nil
	}
	return []model.Finding{{
		Rule:     "PROC-SOCKETS",
		Severity: model.SevLow,
		Category: "network",
		PID:      p.PID,
		Process:  p.Name,
		Summary:  "sockets whose file descriptors belong to this process",
		Detail:   "Endpoints come from the socket table entry with the same inode. A descriptor that is missing from that table is listed separately and is not a confirmed connection.",
		Evidence: capEv(lines),
	}}
}

func startupFindings(p *model.Process) []model.Finding {
	var exact, names []string
	for _, hit := range p.Startup {
		line := hit.Kind + " " + hit.File
		if hit.Line != "" {
			line += " " + hit.Line
		}
		if hit.Match == "exact-path" {
			exact = append(exact, line)
		} else {
			names = append(names, line)
		}
	}
	var out []model.Finding
	if len(exact) > 0 {
		detail := "A startup file contains this executable path. That is a separate observation, not confirmation that this process was launched from the file."
		if p.StartupIncomplete {
			detail += " The startup search also stopped early, so this list can be incomplete."
		}
		out = append(out, model.Finding{
			Rule: "PROC-STARTUP", Severity: model.SevLow, Category: "process",
			PID: p.PID, Process: p.Name,
			Summary: "startup file contains this executable path",
			Detail:  detail, Evidence: capEv(exact),
		})
	}
	if len(names) > 0 {
		out = append(out, model.Finding{
			Rule: "PROC-STARTUP-NAME", Severity: model.SevLow, Category: "process",
			PID: p.PID, Process: p.Name,
			Summary:  "startup filename resembles this executable name",
			Detail:   "The match is the filename only. It does not show that the file starts this process.",
			Evidence: capEv(names),
		})
	}
	if p.StartupIncomplete {
		out = append(out, model.Finding{
			Rule: "PROC-STARTUP-INCOMPLETE", Severity: model.SevInfo, Category: "process",
			PID: p.PID, Process: p.Name,
			Summary:  "startup search was incomplete for this process",
			Detail:   "A missing startup reference cannot be interpreted as absence of persistence.",
			Evidence: []string{"state " + p.StartupStatus},
		})
	}
	return out
}

func unitFinding(p *model.Process) []model.Finding {
	if p.Unit == nil || p.Unit.Service == "" {
		return nil
	}
	u := p.Unit
	ev := []string{"cgroup " + u.Service, "journal " + u.Journal}
	if u.UnitFile == "" {
		ev = append(ev, "unit file not found")
	} else {
		ev = append(ev, "unit "+u.UnitFile)
		for _, line := range u.ExecStart {
			ev = append(ev, "ExecStart "+line)
		}
	}
	if u.TimerFile != "" {
		ev = append(ev, "timer "+u.TimerFile+" "+u.TimerLine)
	}
	return []model.Finding{{
		Rule: "PROC-UNIT", Severity: model.SevLow, Category: "process",
		PID: p.PID, Process: p.Name,
		Summary:  "service membership and unit configuration are separate from a recorded launch",
		Detail:   "Cgroup membership and the unit file are configuration. This scan does not read the journal, so it does not claim the timer started this process.",
		Evidence: capEv(ev),
	}}
}

func emptyNet(ns string) string {
	if strings.TrimSpace(ns) == "" {
		return "-"
	}
	return ns
}
