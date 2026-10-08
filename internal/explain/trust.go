package explain

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadTrustManifest reads a local md5sums-style file.
// Each line is 32 hex digits, two spaces, and an absolute path.
// The file is a supplied reference. It is not fetched from the network.
func LoadTrustManifest(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lines := 0
	for sc.Scan() {
		lines++
		if lines > 4000 {
			return out, fmt.Errorf("manifest stopped at 4000 paths")
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sum, file, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 32 || !strings.HasPrefix(file, "/") {
			return nil, fmt.Errorf("manifest line %d is not an md5sums entry", lines)
		}
		for _, c := range sum {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return nil, fmt.Errorf("manifest line %d has a non-hex digest", lines)
			}
		}
		out[file] = strings.ToLower(sum)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
