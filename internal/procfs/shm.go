package procfs

import (
	"strconv"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

// ParseSysVSHM reads /proc/sysvipc/shm. Permission bits are octal in that file.
func ParseSysVSHM(text string) []model.SysVShm {
	var header []string
	var index map[string]int
	var out []model.SysVShm
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if header == nil {
			header = f
			index = map[string]int{}
			for i, h := range header {
				index[h] = i
			}
			continue
		}
		perms, _ := strconv.ParseUint(field(f, index, "perms"), 8, 32)
		key, _ := strconv.ParseInt(field(f, index, "key"), 10, 64)
		size, _ := strconv.ParseUint(field(f, index, "size"), 10, 64)
		out = append(out, model.SysVShm{
			Key:    key,
			ID:     atoi(field(f, index, "shmid")),
			Perms:  uint32(perms),
			Size:   size,
			CPID:   atoi(field(f, index, "cpid")),
			LPID:   atoi(field(f, index, "lpid")),
			Nattch: atoi(field(f, index, "nattch")),
		})
	}
	return out
}

func field(f []string, index map[string]int, name string) string {
	i, ok := index[name]
	if !ok || i < 0 || i >= len(f) {
		return ""
	}
	return f[i]
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
