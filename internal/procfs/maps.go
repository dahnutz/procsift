package procfs

import (
	"strconv"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

// ParseMaps converts a /proc/pid/maps body into regions.
// The pathname is kept intact, including spaces and the kernel's " (deleted)" suffix.
func ParseMaps(text string) []model.Region {
	var out []model.Region
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if r, ok := parseMapLine(line); ok {
			out = append(out, r)
		}
	}
	return out
}

func parseMapLine(line string) (model.Region, bool) {
	fields := make([]string, 0, 5)
	rest := line
	for len(fields) < 5 {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			break
		}
		i := strings.IndexAny(rest, " \t")
		if i < 0 {
			fields = append(fields, rest)
			rest = ""
			break
		}
		fields = append(fields, rest[:i])
		rest = rest[i:]
	}
	if len(fields) < 5 {
		return model.Region{}, false
	}
	addrs := strings.SplitN(fields[0], "-", 2)
	if len(addrs) != 2 {
		return model.Region{}, false
	}
	start, err1 := strconv.ParseUint(addrs[0], 16, 64)
	end, err2 := strconv.ParseUint(addrs[1], 16, 64)
	off, err3 := strconv.ParseUint(fields[2], 16, 64)
	inode, err4 := strconv.ParseUint(fields[4], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || end < start {
		return model.Region{}, false
	}
	return model.Region{
		Start:  start,
		End:    end,
		Perms:  fields[1],
		Offset: off,
		Dev:    fields[3],
		Inode:  inode,
		Path:   strings.TrimSpace(rest),
	}, true
}
