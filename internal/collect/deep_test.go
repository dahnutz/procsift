//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func TestDeepComparisonUsesMappedInodeNotHostPath(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	base := filepath.Join(proc, "42")
	if err := os.MkdirAll(filepath.Join(base, "map_files"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(base, "status"), "Name:\tapp\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\nKthread:\t0\n")
	write(filepath.Join(base, "stat"), "42 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 1 1\n")
	exe := filepath.Join(root, "exe")
	write(exe, "executable")
	if err := os.Symlink(exe, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
	mapped := filepath.Join(root, "mapped")
	write(mapped, "abcdefghijklmnop")
	write(filepath.Join(base, "mem"), "abcdefghijklmnop")
	if err := os.Symlink(mapped, filepath.Join(base, "map_files", "0-10")); err != nil {
		t.Fatal(err)
	}
	_, ino, _, _, err := statFollow(mapped)
	if err != nil {
		t.Fatal(err)
	}
	p := model.Process{PID: 42, StartTicks: 100, MapsOK: true, Maps: []model.Region{{Start: 0, End: 16, Perms: "r-xp", Offset: 0, Inode: ino, Path: "/replaced/on/host"}}}
	c := &collector{proc: proc, snap: &model.Snapshot{}}
	c.compareProcessPages(&p)
	if len(p.PageDiffs) != 0 || len(c.snap.Coverage) != 0 {
		t.Fatalf("host pathname influenced mapped-file comparison: diffs=%v coverage=%v", p.PageDiffs, c.snap.Coverage)
	}
}
