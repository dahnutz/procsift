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
	for i := 0; i < 80; i++ {
		if err := os.Symlink("/dev/null", filepath.Join(dir, strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	fds, _ := readFDs(dir, t.TempDir())
	joined := strings.Join(fds, "\n")
	if !strings.Contains(joined, "63 -> /dev/null") || strings.Contains(joined, "64 -> /dev/null") {
		t.Fatalf("fd selection %s", joined)
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
