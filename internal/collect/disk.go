//go:build linux

package collect

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/dahnutz/procsift/internal/explain"
	"github.com/dahnutz/procsift/internal/model"
)

const maxDiskTotal = 64 << 20

// checkCriticalFiles checks a fixed utility set, including commands that are
// idle during the scan. Missing files and incomplete package metadata are not
// called mismatches. No utility is executed.
func (c *collector) checkCriticalFiles(owned map[string]string, dbOK, pkgTrunc bool, manifests map[string]string, manTrunc bool) {
	if !dbOK && len(c.trusted) == 0 {
		c.snap.Limits = append(c.snap.Limits, "On-disk utility checks were inconclusive because dpkg metadata was unavailable.")
		return
	}
	var used int64
	for _, path := range explain.CriticalPaths() {
		if !dbOK {
			if _, ok := c.trusted[path]; !ok {
				c.snap.FileChecks = append(c.snap.FileChecks, model.FileCheck{Path: path, State: "inconclusive", Source: "unavailable"})
				continue
			}
		}
		check := model.FileCheck{Path: path, Package: owned[path], Manifest: manifests[path], Source: "observed"}
		if sum, ok := c.trusted[path]; ok {
			check.Manifest = sum
			check.Source = "verified"
			if check.Package == "" {
				check.Package = "local-manifest"
			}
		}
		full := explain.UnderRoot(c.hostRoot, path)
		info, statErr := os.Stat(full)
		switch {
		case os.IsNotExist(statErr):
			check.State = "absent"
		case statErr != nil:
			check.State = "unreadable"
			c.issue(full, statErr)
		case !info.Mode().IsRegular():
			check.State = "not-regular"
		case check.Package == "" && check.Source != "verified":
			if pkgTrunc {
				check.State = "package-search-incomplete"
			} else {
				check.State = "not-listed-by-dpkg"
			}
		case check.Manifest == "":
			if manTrunc {
				check.State = "manifest-search-incomplete"
			} else {
				check.State = "no-manifest"
			}
		default:
			md5sum, sha, n, state, err := hashDisk(full, maxImageBytes, maxDiskTotal-used)
			used += n
			check.State, check.Bytes = state, n
			if err != nil && state != "skipped-size" && state != "skipped-budget" {
				c.issue(full, err)
			}
			if state == "complete" {
				check.MD5, check.SHA256 = md5sum, sha
				if strings.EqualFold(md5sum, check.Manifest) {
					check.State = "match"
				} else {
					check.State = "mismatch"
				}
			}
		}
		c.snap.FileChecks = append(c.snap.FileChecks, check)
	}
	if used >= maxDiskTotal {
		c.snap.Limits = append(c.snap.Limits, "On-disk utility hashing reached its 64 MiB total read budget; later paths are unverified.")
	}
}

// hashDisk verifies that the opened regular file, its size, and its pathname
// still identify the same inode after a complete bounded read.
func hashDisk(path string, perFile, remaining int64) (md5sum, sha string, n int64, state string, err error) {
	if remaining <= 0 {
		return "", "", 0, "skipped-budget", nil
	}
	before, err := os.Stat(path)
	if err != nil {
		return "", "", 0, "unreadable", err
	}
	if !before.Mode().IsRegular() {
		return "", "", 0, "not-regular", nil
	}
	if before.Size() > perFile {
		return "", "", 0, "skipped-size", nil
	}
	if before.Size() > remaining {
		return "", "", 0, "skipped-budget", nil
	}
	fd, err := syscall.Open(filepath.Clean(path), syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", "", 0, "unreadable", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", "", 0, "unreadable", err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", "", 0, "changed", nil
	}
	m, s := md5.New(), sha256.New()
	n, err = io.Copy(io.MultiWriter(m, s), io.LimitReader(f, perFile+1))
	if err != nil {
		return "", "", n, "unreadable", err
	}
	after, ferr := f.Stat()
	current, perr := os.Stat(path)
	if ferr != nil || perr != nil || n != opened.Size() || n > perFile || !os.SameFile(opened, after) || !os.SameFile(opened, current) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return "", "", n, "changed", nil
	}
	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(s.Sum(nil)), n, "complete", nil
}
