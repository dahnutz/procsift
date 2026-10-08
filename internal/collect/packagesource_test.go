//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func TestSnapSourceRequiresMountEvidence(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	mounts := "24 23 7:1 / /snap/core/123 ro - squashfs /dev/loop1 ro\n25 23 7:2 / /snap/fake/1 ro - ext4 /dev/loop2 ro\n"
	if err := os.WriteFile(filepath.Join(proc, "self", "mountinfo"), []byte(mounts), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &model.Snapshot{Processes: []model.Process{
		{Exe: "/snap/core/123/bin/app", Image: &model.ImageCheck{State: "unlisted"}},
		{Exe: "/snap/core/1234/bin/app", Image: &model.ImageCheck{State: "unlisted"}},
		{Exe: "/snap/fake/1/bin/app", Image: &model.ImageCheck{State: "unlisted"}},
	}}
	c := &collector{proc: proc, snap: s}
	c.attachPackageSources()
	if s.Processes[0].Image.PackageSource != "snap-mount-observed" {
		t.Fatal("actual squashfs mount not recognized")
	}
	if s.Processes[1].Image.PackageSource != "" || s.Processes[2].Image.PackageSource != "" {
		t.Fatal("path prefix or non-squashfs mount was treated as Snap context")
	}
}
