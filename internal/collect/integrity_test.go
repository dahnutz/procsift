//go:build linux

package collect

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/report"
)

func TestPackageMismatchAndUnpackagedRoot(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	sudo := filepath.Join(root, "usr", "bin", "sudo")
	custom := filepath.Join(root, "usr", "local", "bin", "helper")
	if err := os.MkdirAll(filepath.Dir(sudo), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(custom), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sudo, []byte("tampered-sudo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(custom, []byte("local-helper"), 0o755); err != nil {
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
	status := "Name:\ttool\nState:\tS (sleeping)\nTgid:\t7\nPid:\t7\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\nKthread:\t0\n"
	write(filepath.Join(proc, "7", "status"), status)
	write(filepath.Join(proc, "7", "stat"), "7 (sudo) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 1 1\n")
	write(filepath.Join(proc, "7", "cmdline"), "sudo\x00")
	write(filepath.Join(proc, "8", "status"), "Name:\thelper\nState:\tS (sleeping)\nTgid:\t8\nPid:\t8\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\nKthread:\t0\n")
	write(filepath.Join(proc, "8", "stat"), "8 (helper) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 1 1\n")
	write(filepath.Join(proc, "8", "cmdline"), "helper\x00")
	write(filepath.Join(proc, "8", "cgroup"), "0::/system.slice/helper.service\n")
	write(filepath.Join(proc, "stat"), "btime 1700000000\n")
	write(filepath.Join(proc, "sys", "kernel", "pid_max"), "100\n")
	write(filepath.Join(root, "etc", "passwd"), "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0:toor:/root:/bin/bash\n")
	listed := md5.Sum([]byte("packaged-sudo"))
	write(filepath.Join(root, "var", "lib", "dpkg", "info", "sudo.list"), "/usr/bin/sudo\n")
	write(filepath.Join(root, "var", "lib", "dpkg", "info", "sudo.md5sums"), hex.EncodeToString(listed[:])+"  usr/bin/sudo\n")
	unit := filepath.Join(root, "lib", "systemd", "system", "helper.service")
	write(unit, "[Service]\nExecStart=/usr/local/bin/helper\n")
	write(filepath.Join(filepath.Dir(unit), "helper.timer"), "[Timer]\nUnit=helper.service\n")
	userTimer := filepath.Join(root, "home", "ada", ".config", "systemd", "user", "helper.timer")
	write(userTimer, "[Timer]\nUnit=helper.service\nExecStart=\n# /usr/local/bin/helper\n")
	if err := os.Symlink(sudo, filepath.Join(proc, "7", "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(custom, filepath.Join(proc, "8", "exe")); err != nil {
		t.Fatal(err)
	}
	snap, err := Collect(Options{
		ProcRoot: proc, SysRoot: filepath.Join(root, "sys"), DevShm: filepath.Join(root, "shm"),
		HostRoot: root, Sweep: false, ReadMagic: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	var mismatch, unpackaged *model.Process
	for i := range snap.Processes {
		p := &snap.Processes[i]
		switch p.PID {
		case 7:
			mismatch = p
		case 8:
			unpackaged = p
		}
	}
	if mismatch == nil || mismatch.Image == nil || mismatch.Image.State != "mismatch" || mismatch.Image.Scope != "full" {
		t.Fatalf("mismatch %+v", mismatch)
	}
	if unpackaged == nil || unpackaged.Image == nil || unpackaged.Image.State != "unlisted" {
		t.Fatalf("unpackaged %+v", unpackaged)
	}
	if unpackaged.Unit == nil || unpackaged.Unit.Journal != "not collected" || unpackaged.Unit.TimerLine != "Unit=helper.service" {
		t.Fatalf("unit %+v", unpackaged.Unit)
	}
	if len(snap.ExtraUID0) != 1 || snap.ExtraUID0[0] != "toor" {
		t.Fatalf("uid0 %v", snap.ExtraUID0)
	}
	var userHit bool
	for _, hit := range unpackaged.Startup {
		if hit.Kind == "systemd-user" && hit.Match == "exact-path" {
			userHit = true
		}
	}
	if !userHit {
		t.Fatalf("startup %+v", unpackaged.Startup)
	}
}

func TestMissingKthreadFieldIsUnknown(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(proc, "2", "status"), "Name:\tkthreadd\nState:\tS (sleeping)\nTgid:\t2\nPid:\t2\nPPid:\t0\nUid:\t0\t0\t0\t0\nThreads:\t1\n")
	write(filepath.Join(proc, "2", "stat"), "2 (kthreadd) S 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0\n")
	write(filepath.Join(proc, "stat"), "btime 1700000000\n")
	write(filepath.Join(proc, "sys", "kernel", "pid_max"), "100\n")
	snap, err := Collect(Options{
		ProcRoot: proc, SysRoot: filepath.Join(root, "sys"), DevShm: filepath.Join(root, "shm"),
		HostRoot: root, Sweep: false, ReadMagic: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Processes) != 1 || snap.Processes[0].KthreadKnown {
		t.Fatalf("%+v", snap.Processes)
	}
	rep := report.Build(snap, nil, report.Options{Version: "0.3.0"})
	if rep.Objects.KernelThreadsKnown || rep.Objects.KernelThreads != 0 {
		t.Fatalf("count %+v", rep.Objects)
	}
	var text stringsBuilder
	if err := report.Write(&text, rep, "text"); err != nil {
		t.Fatal(err)
	}
	if !contains(text.String(), "kernel threads") || !contains(text.String(), "unknown") {
		t.Fatal(text.String())
	}
}

type stringsBuilder struct{ b []byte }

func (s *stringsBuilder) Write(p []byte) (int, error) {
	s.b = append(s.b, p...)
	return len(p), nil
}

func (s stringsBuilder) String() string { return string(s.b) }

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && (stringIndex(s, sub) >= 0)))
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
