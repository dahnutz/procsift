//go:build linux

package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	prefix := filepath.Join(root, "prefix")
	if err := Run(Options{ProcRoot: proc, PID: 3, OutDir: prefix, Version: "0.3.0", MaxBytes: 4}); err != nil {
		t.Fatal(err)
	}
	short := readManifest(t, prefix)
	if short.Hash == nil || short.Hash.Scope != "prefix" || short.Hash.Bytes != 4 {
		t.Fatalf("%+v", short.Hash)
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
