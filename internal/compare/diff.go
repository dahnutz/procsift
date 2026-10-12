// Package compare diffs two scans of the same host and boot.
package compare

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

// Change is one difference between an older report and a newer one.
type Change struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail,omitempty"`
}

// Result separates observations from evidence that warrants a failing diff.
type Result struct {
	ProcessChanges []Change `json:"process_changes,omitempty"`
	SocketChanges  []Change `json:"socket_changes,omitempty"`
	FindingChanges []Change `json:"finding_changes,omitempty"`
	VersionNote    string   `json:"version_note,omitempty"`
	ScopeIssue     string   `json:"scope_issue,omitempty"`
	HostEvidence   int      `json:"host_evidence"`
	Uncertain      int      `json:"uncertain"`
}

// Rules first available in 0.5. Their first appearance after an upgrade is
// scanner coverage, not by itself evidence that the host changed.
var addedRules = map[string]struct{}{
	"PROC-SOCKET-SHELL": {}, "PROC-SENSITIVE-FD": {}, "PROC-LATE-THREAD": {},
	"PROC-UNOWNED-LIB": {}, "PROC-NETNS": {}, "PROC-MAP-FILES": {},
	"MEM-PAGE-MISMATCH": {}, "HOST-LD-PRELOAD": {}, "HOST-BPF-PIN": {},
	"HOST-BPF-UNPRIV": {}, "NET-RAW-SOCKET": {}, "NET-METADATA": {},
}

// Diff compares two reports. It refuses to assign host changes across boots
// or hosts, and treats scan-created or short-lived observations separately.
func Diff(older, newer model.Report) Result {
	var result Result
	if older.Version != newer.Version {
		result.VersionNote = fmt.Sprintf("scanner version %s then %s", empty(older.Version), empty(newer.Version))
	}
	if older.Host.BootID == "" || newer.Host.BootID == "" {
		result.ScopeIssue = "both reports need a boot ID before host changes can be compared"
		return result
	}
	if older.Host.BootID != newer.Host.BootID {
		result.ScopeIssue = "reports are from different boots"
		return result
	}
	if older.Host.Hostname != "" && newer.Host.Hostname != "" && older.Host.Hostname != newer.Host.Hostname {
		result.ScopeIssue = "reports name different hosts"
		return result
	}
	if older.Host.EUID != newer.Host.EUID {
		result.ScopeIssue = "reports were collected with different privileges"
		return result
	}
	if older.ScanOptions == nil || newer.ScanOptions == nil {
		result.ScopeIssue = "scan options are missing from one or both reports; rerun both scans with the current version"
		return result
	}
	if older.MinSeverity == "" || older.MinSeverity != newer.MinSeverity {
		result.ScopeIssue = "reports use different or unknown -min-severity settings"
		return result
	}
	if older.ScanOptions.Manifest != "" && older.ScanOptions.ManifestSHA256 == "" || newer.ScanOptions.Manifest != "" && newer.ScanOptions.ManifestSHA256 == "" {
		result.ScopeIssue = "the supplied manifest could not be identified in both reports"
		return result
	}
	if *older.ScanOptions != *newer.ScanOptions {
		result.ScopeIssue = "reports use different scan options"
		return result
	}
	if older.ScanOptions.Sweep && older.Host.PIDMax != newer.Host.PIDMax {
		result.ScopeIssue = "reports probed different PID spaces"
		return result
	}
	result.ProcessChanges = diffProcesses(older, newer)
	result.SocketChanges = diffSockets(older, newer)
	result.FindingChanges = diffFindings(older, newer)
	for _, group := range [][]Change{result.ProcessChanges, result.SocketChanges, result.FindingChanges} {
		for _, change := range group {
			switch change.Kind {
			case "uncertain", "pid-reuse":
				result.Uncertain++
			case "host-evidence", "changed-image":
				result.HostEvidence++
			}
		}
	}
	return result
}

func diffProcesses(older, newer model.Report) []Change {
	if len(older.Processes) == 0 || len(newer.Processes) == 0 {
		return []Change{{Kind: "uncertain", Subject: "processes", Detail: "one report has no process inventory"}}
	}
	oldByPID := map[int]model.ProcessView{}
	for _, p := range older.Processes {
		if !selfProcess(older, p) {
			oldByPID[p.PID] = p
		}
	}
	newByPID := map[int]model.ProcessView{}
	for _, p := range newer.Processes {
		if !selfProcess(newer, p) {
			newByPID[p.PID] = p
		}
	}
	var out []Change
	for pid, p := range newByPID {
		prev, ok := oldByPID[pid]
		if !ok {
			out = append(out, Change{Kind: "observed", Subject: fmt.Sprintf("pid %d", pid), Detail: "present only in the newer process inventory"})
			continue
		}
		switch relate(prev, p) {
		case "same":
		case "pid-reuse":
			out = append(out, Change{Kind: "pid-reuse", Subject: fmt.Sprintf("pid %d", pid), Detail: "same PID, different start tick; not the same process"})
		case "changed-image":
			out = append(out, Change{Kind: "changed-image", Subject: fmt.Sprintf("pid %d", pid), Detail: "same process instance, executable identity or full hash changed"})
		default:
			out = append(out, Change{Kind: "uncertain", Subject: fmt.Sprintf("pid %d", pid), Detail: "process start or executable identity is incomplete"})
		}
	}
	for pid := range oldByPID {
		if _, ok := newByPID[pid]; !ok {
			out = append(out, Change{Kind: "observed", Subject: fmt.Sprintf("pid %d", pid), Detail: "present only in the older process inventory"})
		}
	}
	sortChanges(out)
	return out
}

func diffSockets(older, newer model.Report) []Change {
	oldSet := socketSet(older)
	newSet := socketSet(newer)
	var out []Change
	for key := range newSet {
		if _, ok := oldSet[key]; !ok {
			out = append(out, Change{Kind: "observed", Subject: key, Detail: "socket visible only in the newer snapshot; short-lived traffic is common"})
		}
	}
	for key := range oldSet {
		if _, ok := newSet[key]; !ok {
			out = append(out, Change{Kind: "observed", Subject: key, Detail: "socket visible only in the older snapshot; short-lived traffic is common"})
		}
	}
	sortChanges(out)
	return out
}

func socketSet(rep model.Report) map[string]struct{} {
	out := map[string]struct{}{}
	for _, sock := range rep.Sockets {
		if sock.PID != 0 && sock.PID == rep.ScannerPID {
			continue
		}
		out[sockKey(sock)] = struct{}{}
	}
	return out
}

func diffFindings(older, newer model.Report) []Change {
	oldSet := map[string]struct{}{}
	oldBase := map[string][]uint64{}
	for _, f := range older.Findings {
		if !selfFinding(older, f) {
			oldSet[findingKey(older, f)] = struct{}{}
			oldBase[findingBase(f)] = append(oldBase[findingBase(f)], processTicks(older, f.PID))
		}
	}
	newSet := map[string]struct{}{}
	var out []Change
	for _, f := range newer.Findings {
		if selfFinding(newer, f) {
			continue
		}
		key := findingKey(newer, f)
		newSet[key] = struct{}{}
		if _, ok := oldSet[key]; ok {
			continue
		}
		if prior, ok := oldBase[findingBase(f)]; ok && (processTicks(newer, f.PID) == 0 || containsZero(prior)) {
			out = append(out, Change{Kind: "uncertain", Subject: key, Detail: "the process start tick is missing from one report"})
			continue
		}
		if newRuleInUpgrade(older.Version, newer.Version, f.Rule) {
			out = append(out, Change{Kind: "new-rule", Subject: key, Detail: "new scanner coverage; verify the finding before attributing a host change"})
			continue
		}
		kind := "observed"
		if model.AtLeast(f.Severity, model.SevMedium) {
			kind = "host-evidence"
		}
		out = append(out, Change{Kind: kind, Subject: key, Detail: "finding visible only in the newer snapshot"})
	}
	for _, f := range older.Findings {
		if selfFinding(older, f) {
			continue
		}
		key := findingKey(older, f)
		if _, ok := newSet[key]; !ok {
			out = append(out, Change{Kind: "observed", Subject: key, Detail: "finding visible only in the older snapshot"})
		}
	}
	sortChanges(out)
	return out
}

func newRuleInUpgrade(oldVersion, newVersion, rule string) bool {
	_, added := addedRules[rule]
	return added && strings.HasPrefix(newVersion, "0.5.") && !strings.HasPrefix(oldVersion, "0.5.")
}

func selfProcess(rep model.Report, p model.ProcessView) bool {
	if rep.ScannerPID > 0 && p.PID == rep.ScannerPID {
		return rep.ScannerTicks == 0 || p.StartTicks == 0 || p.StartTicks == rep.ScannerTicks
	}
	for _, f := range rep.Findings {
		if f.Origin == "scanner_self" && f.PID == p.PID {
			return true
		}
	}
	return false
}

func selfFinding(rep model.Report, f model.Finding) bool {
	return f.Origin == "scanner_self" || rep.ScannerPID > 0 && f.PID == rep.ScannerPID
}

func relate(older, newer model.ProcessView) string {
	if older.StartTicks != 0 && newer.StartTicks != 0 && older.StartTicks != newer.StartTicks {
		return "pid-reuse"
	}
	if older.StartTicks == 0 || newer.StartTicks == 0 {
		return "uncertain"
	}
	oldImage := older.ExeDev != "" && older.ExeInode != 0
	newImage := newer.ExeDev != "" && newer.ExeInode != 0
	if oldImage != newImage {
		return "uncertain"
	}
	if !oldImage { // Same boot, PID and start tick; neither report has an image.
		return "same"
	}
	if older.ExeDev != newer.ExeDev || older.ExeInode != newer.ExeInode {
		return "changed-image"
	}
	if older.ExeHashScope != "" && newer.ExeHashScope != "" && older.ExeHashScope != newer.ExeHashScope {
		return "uncertain"
	}
	if older.ExeHash != "" && newer.ExeHash != "" && older.ExeHash != newer.ExeHash {
		return "changed-image"
	}
	return "same"
}

func sockKey(s model.SocketView) string {
	return strings.Join([]string{s.Proto, s.Local, s.Remote, s.State, fmt.Sprintf("%d", s.Inode)}, " ")
}

func findingBase(f model.Finding) string {
	return fmt.Sprintf("%s pid %d %s", f.Rule, f.PID, f.Subject)
}

func findingKey(rep model.Report, f model.Finding) string {
	key := findingBase(f)
	if f.PID != 0 {
		if ticks := processTicks(rep, f.PID); ticks != 0 {
			key += fmt.Sprintf(" start %d", ticks)
		}
	}
	return key
}

func processTicks(rep model.Report, pid int) uint64 {
	for _, p := range rep.Processes {
		if p.PID == pid {
			return p.StartTicks
		}
	}
	return 0
}

func containsZero(ticks []uint64) bool {
	for _, tick := range ticks {
		if tick == 0 {
			return true
		}
	}
	return false
}

func sortChanges(rows []Change) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Subject == rows[j].Subject {
			return rows[i].Kind < rows[j].Kind
		}
		return rows[i].Subject < rows[j].Subject
	})
}

func empty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
