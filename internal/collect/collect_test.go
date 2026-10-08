//go:build linux

package collect_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dahnutz/procsift/internal/analyze"
	"github.com/dahnutz/procsift/internal/collect"
	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/report"
)

func TestFixtureScan(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	sys := filepath.Join(root, "sys")
	shm := filepath.Join(root, "shm")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string) {
		t.Helper()
		must(os.MkdirAll(filepath.Dir(path), 0o755))
		must(os.WriteFile(path, []byte(body), 0o644))
	}
	link := func(target, path string) {
		t.Helper()
		must(os.MkdirAll(filepath.Dir(path), 0o755))
		must(os.Symlink(target, path))
	}

	write(filepath.Join(proc, "sys", "kernel", "osrelease"), "9.9.9-fixture\n")
	write(filepath.Join(proc, "sys", "kernel", "pid_max"), "100\n")
	write(filepath.Join(proc, "sys", "kernel", "tainted"), "0\n")
	write(filepath.Join(proc, "version"), "Linux version fixture\n")
	write(filepath.Join(proc, "modules"), "evil 4096 0 - Live 0x1000 (E)\nhiddenmod 4096 0 - Live 0x2000\n")
	write(filepath.Join(proc, "sysvipc", "shm"), "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n"+
		"        -1          9   777                    4096     1     1      0     0     0     0     0          0          0          0                     0                     0\n")
	for _, name := range []string{"tcp6", "udp", "udp6"} {
		write(filepath.Join(proc, "net", name), "  sl local_address rem_address st\n")
	}
	write(filepath.Join(proc, "net", "tcp"), "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 00000000 100 0 0 10 0\n"+
		"   1: 0100A8C0:01BB 0200A8C0:0050 01 00000000:00000000 00:00000000 00000000     0        0 7777 1 00000000 100 0 0 10 0\n")
	write(filepath.Join(proc, "42", "status"), "Name:\tpayload\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t1\nTracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\nThreads:\t1\nVmRSS:\t     128 kB\nKthread:\t0\n")
	write(filepath.Join(proc, "42", "cmdline"), "payload --auth-token supersecret\x00")
	write(filepath.Join(proc, "42", "environ"), "LD_PRELOAD=/tmp/libx.so\x00SECRET=do-not-keep\x00")
	write(filepath.Join(proc, "42", "maps"), "00400000-00401000 r-xp 00000000 00:00 1                          /tmp/payload (deleted)\n00600000-00601000 rwxp 00000000 00:00 0 \n")
	link("/tmp/payload (deleted)", filepath.Join(proc, "42", "exe"))
	link("/tmp", filepath.Join(proc, "42", "cwd"))
	link("net:[1]", filepath.Join(proc, "42", "ns", "net"))
	link("net:[1]", filepath.Join(proc, "self", "ns", "net"))
	link("socket:[4242]", filepath.Join(proc, "42", "fd", "3"))
	write(filepath.Join(sys, "module", "evil", "initstate"), "live\n")
	write(filepath.Join(sys, "module", "ghostload", "initstate"), "live\n")
	write(filepath.Join(sys, "module", "builtin", "uevent"), "")
	write(filepath.Join(shm, "stage.bin"), "\x7fELF")

	snap, err := collect.Collect(collect.Options{
		ProcRoot:  proc,
		SysRoot:   sys,
		DevShm:    shm,
		Sweep:     false,
		ReadMagic: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if snap.OSRelease != "9.9.9-fixture" {
		t.Fatalf("release %q", snap.OSRelease)
	}
	if len(snap.Processes) != 1 || snap.Processes[0].PID != 42 {
		t.Fatalf("processes %+v", snap.Processes)
	}
	if strings.Contains(snap.Processes[0].Cmdline, "supersecret") {
		t.Fatalf("cmdline leaked: %s", snap.Processes[0].Cmdline)
	}
	if !strings.Contains(snap.Processes[0].Cmdline, "[redacted]") {
		t.Fatalf("cmdline %q", snap.Processes[0].Cmdline)
	}
	if snap.Processes[0].LDPreload != "/tmp/libx.so" {
		t.Fatalf("preload %q", snap.Processes[0].LDPreload)
	}
	findings := analyze.Analyze(snap)
	rules := map[string]model.Finding{}
	for _, f := range findings {
		rules[f.Rule] = f
	}
	for _, rule := range []string{"PROC-DELETED-EXE", "PROC-LD-PRELOAD", "MEM-DELETED-EXEC", "MOD-UNSIGNED", "MOD-NO-PROC", "MOD-NO-SYSFS", "NET-ORPHAN-SOCKET", "IPC-SHM-EXEC", "IPC-ORPHAN-SHM", "IPC-DEVSHM-FILE"} {
		if _, ok := rules[rule]; !ok {
			t.Fatalf("missing %s in %v", rule, ruleNames(findings))
		}
	}
	if rules["NET-ORPHAN-SOCKET"].Subject != "inode 7777" {
		t.Fatalf("orphan %+v", rules["NET-ORPHAN-SOCKET"])
	}
	rep := report.Build(snap, findings, report.Options{Version: "0.1.0", MinSeverity: "low", IncludeProcesses: true})
	var b strings.Builder
	if err := report.Write(&b, rep, "text"); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	if strings.Contains(text, "supersecret") || strings.Contains(text, "do-not-keep") {
		t.Fatalf("secret leaked into report:\n%s", text)
	}
	if !strings.Contains(text, "PROC-DELETED-EXE") || !strings.Contains(text, "9.9.9-fixture") {
		t.Fatalf("report missing expected lines:\n%s", text)
	}
}

func TestLiveCollectSmoke(t *testing.T) {
	if os.Getenv("PROCSIFT_LIVE_TEST") != "1" {
		t.Skip("set PROCSIFT_LIVE_TEST=1 to enable the live collector smoke test")
	}
	snap, err := collect.Collect(collect.Options{Sweep: false, ReadMagic: false, Progress: nil})
	if err != nil {
		t.Fatal(err)
	}
	self := os.Getpid()
	found := false
	for _, p := range snap.Processes {
		if p.PID == self {
			found = true
			if !p.Listed {
				t.Fatal("current process was marked hidden")
			}
		}
	}
	if !found {
		t.Fatalf("pid %d not in snapshot of %d processes", self, len(snap.Processes))
	}
	for _, g := range snap.Ghosts {
		if g.PID == self {
			t.Fatal("current process reported as a ghost")
		}
	}
	if snap.PIDMax < 2 {
		t.Fatalf("pid_max %d", snap.PIDMax)
	}
}

func ruleNames(fs []model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}
