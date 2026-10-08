package explain

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxListFiles = 8000
	maxListBytes = 32 << 20
	maxLogBytes  = 2 << 20
)

// FindPackages maps cleaned pathnames to dpkg package names.
// dbOK is false when the dpkg info directory cannot be read.
// truncated is true when the file or byte budget stopped the scan early.
func FindPackages(root string, paths []string) (owned map[string]string, dbOK, truncated bool) {
	want := map[string]struct{}{}
	for _, p := range paths {
		p = strings.TrimSuffix(p, " (deleted)")
		if p != "" {
			want[p] = struct{}{}
		}
	}
	owned = map[string]string{}
	if len(want) == 0 {
		return owned, true, false
	}
	dir := filepath.Join(root, "var", "lib", "dpkg", "info")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return owned, false, false
	}
	dbOK = true
	readBytes := 0
	files := 0
	for _, e := range entries {
		if len(want) == 0 {
			break
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".list") || e.IsDir() {
			continue
		}
		files++
		if files > maxListFiles || readBytes >= maxListBytes {
			return owned, true, true
		}
		body, n, err := readCap(filepath.Join(dir, name), 1<<20)
		readBytes += n
		if err != nil {
			continue
		}
		pkg := strings.TrimSuffix(name, ".list")
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if _, ok := want[line]; ok {
				owned[line] = pkg
				delete(want, line)
			}
		}
	}
	return owned, true, files > maxListFiles || readBytes >= maxListBytes
}

// LatestTransaction returns the newest dpkg.log timestamp for a package name.
// The package name may include an architecture suffix in the log.
func LatestTransaction(root, pkg string) (time.Time, bool) {
	if pkg == "" {
		return time.Time{}, false
	}
	name := pkg
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	body, _, err := readTail(filepath.Join(root, "var", "log", "dpkg.log"), maxLogBytes)
	if err != nil {
		return time.Time{}, false
	}
	var latest time.Time
	found := false
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		logged := fields[3]
		loggedName := logged
		if i := strings.IndexByte(loggedName, ':'); i >= 0 {
			loggedName = loggedName[:i]
		}
		if loggedName != name {
			continue
		}
		ts, err := time.ParseInLocation("2006-01-02 15:04:05", fields[0]+" "+fields[1], time.UTC)
		if err != nil {
			continue
		}
		if !found || ts.After(latest) {
			latest = ts
			found = true
		}
	}
	return latest, found
}

func readCap(path string, max int) (string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	buf := make([]byte, max)
	n, err := f.Read(buf)
	if n == 0 && err != nil {
		return "", 0, err
	}
	return string(buf[:n]), n, nil
}

func readTail(path string, max int) (string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	size := info.Size()
	start := int64(0)
	if size > int64(max) {
		start = size - int64(max)
	}
	buf := make([]byte, size-start)
	n, err := f.ReadAt(buf, start)
	if n == 0 && err != nil {
		return "", 0, err
	}
	return string(buf[:n]), n, nil
}
