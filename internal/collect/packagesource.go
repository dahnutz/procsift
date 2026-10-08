//go:build linux

package collect

import (
	"path/filepath"
	"strings"
)

// attachPackageSources adds mount context to dpkg-unlisted images. A path that
// merely begins with /snap is not enough; the mount table must show squashfs.
// Even then, the mount is not an integrity or benignness verdict.
func (c *collector) attachPackageSources() {
	body, err := readLimited(filepath.Join(c.proc, "self", "mountinfo"), 1<<20)
	if err != nil {
		c.snap.Limits = append(c.snap.Limits, "Package-source mount context was unavailable; dpkg-unlisted paths remain unclassified.")
		return
	}
	var mounts []string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 5 || len(right) < 1 || right[0] != "squashfs" {
			continue
		}
		mount := left[4]
		if strings.HasPrefix(mount, "/snap/") {
			mounts = append(mounts, mount)
		}
	}
	for i := range c.snap.Processes {
		p := &c.snap.Processes[i]
		if p.Image == nil || p.Image.State != "unlisted" {
			continue
		}
		for _, mount := range mounts {
			if p.Exe == mount || strings.HasPrefix(p.Exe, mount+"/") {
				p.Image.PackageSource = "snap-mount-observed"
				break
			}
		}
	}
}
