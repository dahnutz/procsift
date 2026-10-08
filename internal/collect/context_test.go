//go:build linux

package collect

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/dahnutz/procsift/internal/explain"
)

func TestDeletedImageDossier(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	live := filepath.Join(root, "live-image")
	replaced := filepath.Join(root, "usr", "bin", "app")
	if err := os.MkdirAll(filepath.Dir(replaced), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live, []byte("running-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replaced, []byte("replacement-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The symlink target's readlink text is the deleted pathname. The target
	// file is the inode that is still executing.
	deletedName := filepath.Join(root, "usr", "bin", "app (deleted)")
	if err := os.Rename(live, deletedName); err != nil {
		t.Fatal(err)
	}
	pidDir := filepath.Join(proc, "42")
	if err := os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(pidDir, "status"), "Name:\tapp\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t1\nTracerPid:\t0\nUid:\t0\t0\t0\t0\nThreads:\t1\nKthread:\t0\n")
	write(filepath.Join(pidDir, "stat"), "42 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 1 1\n")
	write(filepath.Join(pidDir, "cmdline"), "app\x00")
	write(filepath.Join(pidDir, "maps"), "00400000-00401000 r-xp 00000000 08:01 10                          /usr/bin/app (deleted)\n")
	write(filepath.Join(proc, "stat"), "btime 1700000000\n")
	write(filepath.Join(proc, "sys", "kernel", "pid_max"), "100\n")
	write(filepath.Join(root, "etc", "passwd"), "root:x:0:0:root:/root:/bin/bash\n")
	list := filepath.Join(root, "var", "lib", "dpkg", "info", "app.list")
	write(list, "/usr/bin/app\n")
	sum := md5.Sum([]byte("replacement-bytes"))
	write(filepath.Join(filepath.Dir(list), "app.md5sums"), hex.EncodeToString(sum[:])+"  usr/bin/app\n")
	write(filepath.Join(root, "var", "log", "dpkg.log"), "2026-01-01 00:00:00 upgrade app:amd64 1 2\n")
	if err := os.Symlink(deletedName, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
	// Touch the replacement so its mtime is after the process start
	// (btime 1700000000 + 100/100 seconds).
	snap, err := Collect(Options{
		ProcRoot:  proc,
		SysRoot:   filepath.Join(root, "sys"),
		DevShm:    filepath.Join(root, "shm"),
		HostRoot:  root,
		Sweep:     false,
		ReadMagic: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Processes) != 1 || snap.Processes[0].ExeInfo == nil {
		t.Fatalf("%+v", snap.Processes)
	}
	info := snap.Processes[0].ExeInfo
	if info.Relation != explain.PathReplaced {
		t.Fatalf("relation %s notes %v", info.Relation, info.Notes)
	}
	if !info.IdentityOK || info.HashState != "complete" || info.SHA256 == "" {
		t.Fatalf("identity %+v", info)
	}
	if info.Label != explain.LabelMaintenance || info.Package != "app" {
		t.Fatalf("label %s package %s", info.Label, info.Package)
	}
	if snap.Processes[0].User != "root" {
		t.Fatalf("user %s", snap.Processes[0].User)
	}
	if len(snap.Processes[0].DeletedMaps) != 1 || snap.Processes[0].DeletedMaps[0].Label != explain.LabelMaintenance {
		t.Fatalf("maps %+v", snap.Processes[0].DeletedMaps)
	}
}
