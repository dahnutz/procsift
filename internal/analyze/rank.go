package analyze

import (
	"sort"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

// Rank builds a first-action list from findings. Scanner-origin findings stay
// out of this list and keep their original severity. The score is a fixed
// weight, not a verdict.
func Rank(s *model.Snapshot, findings []model.Finding) []model.Attention {
	if s == nil {
		return nil
	}
	type acc struct {
		pid                   int
		name, subject         string
		score                 int
		level                 string
		why, alt              []string
		maintenance, stronger bool
	}
	by := map[int]*acc{}
	var host []model.Attention
	var changedFiles []string
	for _, f := range findings {
		if f.Origin == "scanner_self" {
			continue
		}
		if f.PID == 0 {
			if f.Rule == "FILE-PKG-MISMATCH" {
				changedFiles = append(changedFiles, f.Subject)
			}
			if f.Rule == "PROC-EXTRA-UID0" {
				host = append(host, model.Attention{
					Subject: "uid 0 account",
					Score:   50,
					Level:   "observed",
					Why:     append([]string(nil), f.Evidence...),
					Alternatives: []string{
						"An administrative account can be intentional. The password field was not read.",
					},
				})
			}
			continue
		}
		row := by[f.PID]
		if row == nil {
			row = &acc{pid: f.PID, name: f.Process, level: "observed"}
			by[f.PID] = row
		}
		if row.name == "" {
			row.name = f.Process
		}
		switch f.Rule {
		case "PROC-DELETED-EXE":
			row.score += 50
			row.why = append(row.why, "deleted executable")
			if strings.Contains(f.Summary, "unexplained") {
				row.score += 20
				row.why = append(row.why, "no corroborated update")
			}
			if strings.Contains(f.Summary, "maintenance corroborated") {
				row.maintenance = true
				row.alt = append(row.alt, "A package transaction and a matching manifest explain the replacement. The deleted-image finding stays.")
			}
			if evidenceHasTemp(f.Evidence) {
				row.score += 25
				row.why = append(row.why, "temporary path")
				row.stronger = true
			}
		case "PROC-MEMFD-EXE":
			row.score += 70
			row.why = append(row.why, "memfd executable")
			row.stronger = true
		case "PROC-PKG-MISMATCH":
			row.score += 60
			row.why = append(row.why, "package manifest mismatch")
			row.stronger = true
			row.alt = append(row.alt, "The local package database may itself have been changed.")
		case "PROC-FILE-MATCH":
			row.score += 65
			row.why = append(row.why, "full image hash matches changed utility")
			row.stronger = true
			row.alt = append(row.alt, "Matching bytes connect the images; the package database remains a local reference.")
		case "PROC-UNPACKAGED-ROOT":
			row.score += 45
			row.why = append(row.why, "unpackaged root executable")
			row.stronger = true
			if strings.Contains(f.Detail, "temporary") {
				row.score += 10
				row.why = append(row.why, "temporary path")
			}
			if strings.Contains(f.Detail, "locally installed") {
				row.alt = append(row.alt, "A startup file names this path. That is local installation evidence, not a clearance.")
			}
		case "PROC-PKG-OTHER-SOURCE":
			row.score += 5
			row.why = append(row.why, "dpkg-unlisted on observed Snap mount")
			row.alt = append(row.alt, "The mounted image was not independently verified.")
		case "PROC-KTHREAD-MASQ", "PROC-TITLE-MASQ":
			row.score += 40
			row.why = append(row.why, "title mismatch")
			row.stronger = true
			row.alt = append(row.alt, "A wrapper can change the displayed name. The mismatch is not a verdict.")
		case "PROC-SOCKET-SHELL":
			row.score += 35
			row.why = append(row.why, "socket shell without a terminal")
			row.stronger = true
		case "PROC-LATE-THREAD":
			row.score += 15
			row.why = append(row.why, "late or disguised thread")
		case "PROC-SENSITIVE-FD":
			row.score += 10
			row.why = append(row.why, "sensitive descriptor")
			row.alt = append(row.alt, "The descriptor path was recorded. Its contents were not read.")
		case "MEM-PAGE-MISMATCH":
			row.score += 30
			row.why = append(row.why, "executable page differs from the file")
			row.alt = append(row.alt, "JIT, debuggers, and runtimes can change executable pages.")
		case "PROC-UNOWNED-LIB":
			row.score += 20
			row.why = append(row.why, "unowned mapped library")
		case "PROC-CONTEXT-DISGUISE":
			row.score += 25
			row.why = append(row.why, "identity and execution context differ")
			row.alt = append(row.alt, "Custom services and changed process titles can be legitimate.")
		case "PROC-SOCKETS":
			if confirmedSocket(f.Evidence) {
				row.score += 30
				row.why = append(row.why, "confirmed socket")
			}
		case "PROC-STARTUP":
			row.score += 20
			row.why = append(row.why, "startup path")
			row.alt = append(row.alt, "A startup line is not proof this process was launched from that file.")
		case "PROC-STARTUP-NAME":
			row.score += 5
			row.why = append(row.why, "startup filename")
		case "PROC-UNIT":
			row.score += 5
			row.why = append(row.why, "service cgroup")
			row.alt = append(row.alt, "Unit text is configuration. The journal was not read.")
		case "PROC-PKG-UNLISTED", "PROC-PKG-NOMANIFEST":
			row.score += 10
			row.why = append(row.why, "package evidence inconclusive")
			row.level = "inconclusive"
		}
	}
	if len(changedFiles) > 0 {
		why := append([]string(nil), changedFiles...)
		if len(why) > 5 {
			why = append(why[:5], "additional changed paths in Findings")
		}
		host = append(host, model.Attention{
			Subject: "changed critical utilities", Score: 80, Level: "observed",
			Why:          why,
			Alternatives: []string{"The local dpkg manifest is a reference and may itself have been changed."},
		})
	}
	var rows []model.Attention
	for _, row := range by {
		if row.score <= 0 {
			continue
		}
		level := row.level
		if row.maintenance && !row.stronger {
			level = "corroborated"
		}
		if level == "" {
			level = "observed"
		}
		rows = append(rows, model.Attention{
			PID:          row.pid,
			Process:      row.name,
			Score:        row.score,
			Level:        level,
			Why:          row.why,
			Alternatives: row.alt,
		})
	}
	rows = append(rows, host...)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return rows[i].PID < rows[j].PID
	})
	if len(rows) > 5 {
		rows = rows[:5]
	}
	return rows
}

func evidenceHasTemp(ev []string) bool {
	for _, line := range ev {
		for _, pre := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"} {
			if strings.Contains(line, pre) {
				return true
			}
		}
	}
	return false
}

func confirmedSocket(ev []string) bool {
	for _, line := range ev {
		if strings.Contains(line, "->") && !strings.Contains(line, "descriptor only") && !strings.Contains(line, "not fully readable") {
			return true
		}
	}
	return false
}
