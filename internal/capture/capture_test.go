//go:build linux

package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCaptureFullAndPrefix(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	body := []byte("captured-image-bytes")
	image := filepath.Join(root, "bin")
	if err := os.WriteFile(image, body, 0o755); err != nil {
		t.Fatal(err)
	}
	pid := filepath.Join(proc, "3")
	if err := os.MkdirAll(filepath.Join(pid, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pid, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	table := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		"0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 777 1 0\n"
	if err := os.WriteFile(filepath.Join(pid, "net", "tcp"), []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "net", "tcp"), []byte("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[777]", filepath.Join(pid, "fd", "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "status"), []byte("Name:\tapp\nState:\tS (sleeping)\nPid:\t3\nTgid:\t3\nPPid:\t1\nUid:\t0\t0\t0\t0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "stat"), []byte("3 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50 1 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "cmdline"), []byte("app\x00--password=secret\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "maps"), []byte("00400000-00401000 r-xp 00000000 08:01 10                          /usr/bin/app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(image, filepath.Join(pid, "exe")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "case")
	if err := Run(Options{ProcRoot: proc, PID: 3, OutDir: out, Version: "0.3.0", MaxBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	man := readManifest(t, out)
	if !man.IdentityStable || man.Hash == nil || man.Hash.Scope != "full" || man.ImageFile != "image.bin" {
		t.Fatalf("%+v", man.Hash)
	}
	if man.Hash.Bytes != int64(len(body)) {
		t.Fatalf("bytes %d", man.Hash.Bytes)
	}
	got, err := os.ReadFile(filepath.Join(out, "image.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("image %q", got)
	}
	if man.Cmdline == "" || containsSecret(man.Cmdline) {
		t.Fatalf("cmdline %q", man.Cmdline)
	}
	if len(man.Sockets) != 1 || !strings.Contains(man.Sockets[0], "127.0.0.1:8080") {
		t.Fatalf("target namespace sockets %+v", man.Sockets)
	}
	prefix := filepath.Join(root, "prefix")
	if err := Run(Options{ProcRoot: proc, PID: 3, OutDir: prefix, Version: "0.3.0", MaxBytes: 4}); err != nil {
		t.Fatal(err)
	}
	short := readManifest(t, prefix)
	if short.Hash == nil || short.Hash.Scope != "prefix" || short.Hash.Bytes != 4 {
		t.Fatalf("%+v", short.Hash)
	}
}

func TestCaptureRequiresVersion(t *testing.T) {
	if err := Run(Options{PID: 3, OutDir: filepath.Join(t.TempDir(), "case")}); err == nil {
		t.Fatal("capture accepted an unspecified version")
	}
}

func TestCaptureRemovesFailedImage(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	pid := filepath.Join(proc, "3")
	if err := os.MkdirAll(pid, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"status": "Name:\tapp\nState:\tS (sleeping)\nPid:\t3\nTgid:\t3\nPPid:\t1\nUid:\t0\t0\t0\t0\n",
		"stat":   "3 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50 1 1\n",
	} {
		if err := os.WriteFile(filepath.Join(pid, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/proc/self/mem", filepath.Join(pid, "exe")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "case")
	if err := Run(Options{ProcRoot: proc, PID: 3, OutDir: out, Version: "0.5.2"}); err != nil {
		t.Fatal(err)
	}
	man := readManifest(t, out)
	if man.Hash != nil || man.ImageFile != "" || len(man.Failures) == 0 {
		t.Fatalf("manifest %+v", man)
	}
	if _, err := os.Stat(filepath.Join(out, "image.bin")); !os.IsNotExist(err) {
		t.Fatalf("orphaned image: %v", err)
	}
}

func TestCaptureFDsSortNumericallyBeforeCap(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 300; i++ {
		if err := os.Symlink("/dev/null", filepath.Join(dir, strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	fds, _, _ := readFDs(dir, t.TempDir())
	joined := strings.Join(fds, "\n")
	if !strings.Contains(joined, "\n255 -> /dev/null") || strings.Contains(joined, "\n256 -> /dev/null") || !strings.Contains(joined, "truncated at 256") {
		t.Fatalf("fd selection %s", joined)
	}
	// fds[0] is the truncation note.
	if !strings.HasPrefix(fds[1], "0 -> ") || !strings.HasPrefix(fds[3], "2 -> ") || !strings.HasPrefix(fds[11], "10 -> ") {
		t.Fatalf("order %v", fds[:12])
	}
}

func TestCaptureStableIdentityNeedsAllThreeViews(t *testing.T) {
	same := fileID{dev: 8, ino: 10}
	other := fileID{dev: 8, ino: 11}
	ok := identityCheck{pid: 3, ticks: 50, before: same, beforeOK: true, opened: same, after: same, afterPID: 3, afterTicks: 50, afterOK: true}
	if !stableIdentity(ok) {
		t.Fatal("matching views rejected")
	}
	for name, edit := range map[string]func(*identityCheck){
		"replaced before open":   func(c *identityCheck) { c.before = other },
		"replaced after read":    func(c *identityCheck) { c.after = other },
		"descriptor differs":     func(c *identityCheck) { c.opened = other },
		"before stat failed":     func(c *identityCheck) { c.beforeOK = false },
		"pid reused":             func(c *identityCheck) { c.afterTicks = 99 },
		"no descriptor identity": func(c *identityCheck) { c.before, c.opened, c.after = fileID{}, fileID{}, fileID{} },
	} {
		c := ok
		edit(&c)
		if stableIdentity(c) {
			t.Errorf("%s: accepted as stable", name)
		}
	}
}

func TestCaptureContextAndExtraTables(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	pid := filepath.Join(proc, "3")
	for _, d := range []string{"fd", "net", "ns"} {
		if err := os.MkdirAll(filepath.Join(pid, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"status":     "Name:\tapp\nState:\tS (sleeping)\nPid:\t3\nTgid:\t3\nPPid:\t1\nUid:\t0\t0\t0\t0\n",
		"stat":       "3 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50 1 1\n",
		"cgroup":     "0::/system.slice/app.service\n",
		"environ":    "PATH=/usr/bin\x00LD_PRELOAD=/tmp/libx.so\x00SECRET=do-not-keep\x00",
		"net/packet": "sk RefCnt Type Proto Iface R Rmem User Inode\nffff 3 3 0003 0 1 0 0 888\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(pid, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// An unreadable table must be recorded, not skipped silently.
	if err := os.Mkdir(filepath.Join(pid, "net", "udp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[4026531840]", filepath.Join(pid, "ns", "net")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[888]", filepath.Join(pid, "fd", "4")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "case")
	if err := Run(Options{ProcRoot: proc, PID: 3, OutDir: out, Version: "0.5.2"}); err != nil {
		t.Fatal(err)
	}
	man := readManifest(t, out)
	if man.Cgroup == "" || !strings.Contains(man.Status, "Name:\tapp") || man.Namespaces["net"] != "net:[4026531840]" {
		t.Fatalf("context %+v", man)
	}
	if man.LoaderEnv["LD_PRELOAD"] != "/tmp/libx.so" || len(man.LoaderEnv) != 1 {
		t.Fatalf("loader env %+v", man.LoaderEnv)
	}
	raw, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "do-not-keep") {
		t.Fatal("raw environment value stored in the manifest")
	}
	if len(man.Sockets) != 1 || !strings.HasPrefix(man.Sockets[0], "packet ") {
		t.Fatalf("sockets %+v", man.Sockets)
	}
	if !strings.Contains(strings.Join(man.Failures, "\n"), "net/udp:") {
		t.Fatalf("unreadable table not recorded: %+v", man.Failures)
	}
}

func TestCaptureRefusesSwappedOutputDirectory(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openOutDir(link); err == nil {
		t.Fatal("symlinked output directory accepted")
	}
	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openOutDir(open); err == nil {
		t.Fatal("group/world-readable directory accepted as the private bundle directory")
	}
	dir, err := openOutDir(real)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := os.Symlink("/etc/passwd", filepath.Join(real, "maps.txt")); err != nil {
		t.Fatal(err)
	}
	if err := writeAt(dir, "maps.txt", []byte("x")); err == nil {
		t.Fatal("wrote through a planted symlink")
	}
}

func readManifest(t *testing.T, dir string) Manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var man Manifest
	if err := json.Unmarshal(b, &man); err != nil {
		t.Fatal(err)
	}
	return man
}

func containsSecret(s string) bool {
	return len(s) >= 6 && (stringIndex(s, "secret") >= 0)
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
