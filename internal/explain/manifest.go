package explain

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxManifestFile = 32 << 20

// FindManifests maps absolute paths to lowercase MD5 hex from dpkg md5sums files.
// available is false when the dpkg info directory cannot be read.
func FindManifests(root string, paths []string) (sums map[string]string, available, truncated bool) {
	want := map[string]struct{}{}
	for _, p := range paths {
		p = strings.TrimSuffix(p, " (deleted)")
		if p != "" {
			want[p] = struct{}{}
		}
	}
	sums = map[string]string{}
	if len(want) == 0 {
		return sums, true, false
	}
	dir := filepath.Join(root, "var", "lib", "dpkg", "info")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return sums, false, false
	}
	readBytes := 0
	files := 0
	for _, e := range entries {
		if len(want) == 0 {
			break
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".md5sums") || e.IsDir() {
			continue
		}
		files++
		if files > maxListFiles || readBytes >= maxListBytes {
			return sums, true, true
		}
		body, n, err := readCap(filepath.Join(dir, name), 1<<20)
		readBytes += n
		if err != nil {
			continue
		}
		for _, line := range strings.Split(body, "\n") {
			path, sum, ok := parseMD5Line(line)
			if !ok {
				continue
			}
			if _, needed := want[path]; !needed {
				continue
			}
			sums[path] = sum
			delete(want, path)
		}
	}
	return sums, true, files > maxListFiles || readBytes >= maxListBytes
}

func parseMD5Line(line string) (path, sum string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	i := strings.IndexAny(line, " \t")
	if i != 32 {
		return "", "", false
	}
	sum = strings.ToLower(line[:i])
	if !hex32(sum) {
		return "", "", false
	}
	path = strings.TrimSpace(line[i:])
	if path == "" {
		return "", "", false
	}
	if strings.HasPrefix(path, "./") {
		path = path[1:]
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path, sum, true
}

func hex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// ErrHashBudget means the file is larger than the caller allowed.
var ErrHashBudget = errors.New("file exceeds hash budget")

// MD5File hashes path, stopping at max bytes. full is true only when the entire file was read.
func MD5File(path string, max int64) (sum string, n int64, full bool, err error) {
	if max <= 0 {
		max = maxManifestFile
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, false, err
	}
	if info.Size() > max {
		return "", 0, false, ErrHashBudget
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, false, err
	}
	defer f.Close()
	h := md5.New()
	n, err = io.Copy(h, io.LimitReader(f, max+1))
	if err != nil {
		return "", n, false, err
	}
	if n > max || (info.Size() >= 0 && n != info.Size()) {
		return "", n, false, ErrHashBudget
	}
	return hex.EncodeToString(h.Sum(nil)), n, true, nil
}
