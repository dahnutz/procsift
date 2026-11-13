package explain

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// ReadTrustManifest parses a local md5sums-style file from r.
// Each line is 32 hex digits, two spaces, and an absolute path.
// The file is a supplied reference. It is not fetched from the network.
// On success it also returns the SHA-256 of the exact bytes that were parsed,
// so a report can identify the reference it actually used. The caller opens
// the file, so it controls how (see collect's use of safeio).
func ReadTrustManifest(r io.Reader) (map[string]string, string, error) {
	h := sha256.New()
	out := map[string]string{}
	sc := bufio.NewScanner(io.TeeReader(r, h))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lines := 0
	for sc.Scan() {
		lines++
		if lines > 4000 {
			return out, "", fmt.Errorf("manifest stopped at 4000 paths")
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sum, file, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 32 || !strings.HasPrefix(file, "/") {
			return nil, "", fmt.Errorf("manifest line %d is not an md5sums entry", lines)
		}
		for _, c := range sum {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return nil, "", fmt.Errorf("manifest line %d has a non-hex digest", lines)
			}
		}
		out[file] = strings.ToLower(sum)
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	// The scanner read to EOF, so the hash covers the whole file as parsed.
	return out, hex.EncodeToString(h.Sum(nil)), nil
}
