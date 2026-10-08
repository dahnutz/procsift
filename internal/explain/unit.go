package explain

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

// ReadUnit reads a systemd unit and a sibling timer when a service name is known.
// The journal is never read. A timer file is configuration, not proof of a launch.
func ReadUnit(root, service string) model.UnitLink {
	link := model.UnitLink{Service: service, Journal: "not collected"}
	if service == "" || !strings.HasSuffix(service, ".service") {
		return link
	}
	dirs := []string{
		filepath.Join(root, "etc", "systemd", "system"),
		filepath.Join(root, "run", "systemd", "system"),
		filepath.Join(root, "lib", "systemd", "system"),
		filepath.Join(root, "usr", "lib", "systemd", "system"),
		filepath.Join(root, "run", "systemd", "generator.early"),
		filepath.Join(root, "run", "systemd", "generator"),
		filepath.Join(root, "run", "systemd", "generator.late"),
		filepath.Join(root, "etc", "systemd", "user"),
		filepath.Join(root, "root", ".config", "systemd", "user"),
	}
	var unitPath string
	for _, dir := range dirs {
		candidate := filepath.Join(dir, service)
		if _, err := os.Stat(candidate); err == nil {
			unitPath = candidate
			break
		}
	}
	if unitPath == "" {
		return link
	}
	link.UnitFile = unitPath
	body := readUnitText(unitPath)
	link.ExecStart = execStarts(body)
	timerName := strings.TrimSuffix(service, ".service") + ".timer"
	timerPath := filepath.Join(filepath.Dir(unitPath), timerName)
	if text := readUnitText(timerPath); text != "" {
		link.TimerFile = timerPath
		link.TimerLine = timerRelation(text, service)
	}
	return link
}

func readUnitText(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, maxFileRead)
	n, _ := f.Read(buf)
	if n == 0 {
		return ""
	}
	return string(buf[:n])
}

func execStarts(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		val := strings.TrimPrefix(line, "ExecStart=")
		val = strings.TrimPrefix(val, "-")
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		if len(val) > 180 {
			val = val[:177] + "..."
		}
		out = append(out, val)
		if len(out) >= 4 {
			break
		}
	}
	return out
}

func timerRelation(text, service string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Unit=") && strings.Contains(line, service) {
			return line
		}
	}
	if strings.Contains(text, service) {
		return "mentions " + service
	}
	return "sibling timer file; no Unit= line for this service"
}
