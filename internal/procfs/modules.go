package procfs

import (
	"strconv"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

// ParseModules reads /proc/modules. Dependencies may contain commas, so the
// state token (Live, Loading, Unloading) anchors the line.
func ParseModules(text string) []model.Module {
	var out []model.Module
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		stateIdx := -1
		for i, tok := range f {
			switch tok {
			case "Live", "Loading", "Unloading":
				stateIdx = i
			}
		}
		if stateIdx < 3 || stateIdx+1 >= len(f) {
			continue
		}
		size, _ := strconv.ParseUint(f[1], 10, 64)
		ref, _ := strconv.Atoi(f[2])
		taint := ""
		if stateIdx+2 < len(f) {
			taint = strings.Trim(f[stateIdx+2], "()")
		}
		out = append(out, model.Module{
			Name:    f[0],
			Size:    size,
			Refcnt:  ref,
			State:   f[stateIdx],
			Address: f[stateIdx+1],
			Taints:  taint,
		})
	}
	return out
}
