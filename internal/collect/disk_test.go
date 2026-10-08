//go:build linux

package collect

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func TestIdleCriticalUtilityMismatch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bin", "ps")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	want := md5.Sum([]byte("packaged executable"))
	c := &collector{hostRoot: root, snap: &model.Snapshot{}}
	c.checkCriticalFiles(map[string]string{"/bin/ps": "procps"}, true, false, map[string]string{"/bin/ps": hex.EncodeToString(want[:])}, false)
	for _, check := range c.snap.FileChecks {
		if check.Path == "/bin/ps" {
			if check.State != "mismatch" || check.SHA256 == "" || check.Bytes != int64(len("changed executable")) {
				t.Fatalf("idle utility check: %+v", check)
			}
			return
		}
	}
	t.Fatal("idle utility was not checked")
}

func TestUnlistedOrMissingManifestIsNotMismatch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bin", "ps")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unchanged"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &collector{hostRoot: root, snap: &model.Snapshot{}}
	c.checkCriticalFiles(map[string]string{"/bin/ps": "procps"}, true, false, nil, false)
	for _, check := range c.snap.FileChecks {
		if check.Path == "/bin/ps" && check.State != "no-manifest" {
			t.Fatalf("state %s", check.State)
		}
		if check.State == "mismatch" {
			t.Fatalf("false mismatch: %+v", check)
		}
	}
}

func TestFullHashLinksChangedUtilityToRunningImage(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	image := filepath.Join(root, "image")
	bytes := []byte("same bounded full executable")
	if err := os.WriteFile(image, bytes, 0o755); err != nil {
		t.Fatal(err)
	}
	pidDir := filepath.Join(proc, "42")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(image, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
	status := "Name:\tagent\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\nKthread:\t0\n"
	stat := "42 (agent) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 1 1\n"
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	snap := &model.Snapshot{
		Processes:  []model.Process{{PID: 42, UID: 0, StartTicks: 100, Exe: "/usr/local/bin/agent", Image: &model.ImageCheck{State: "unlisted"}}},
		FileChecks: []model.FileCheck{{Path: "/bin/ps", State: "mismatch", SHA256: hex.EncodeToString(sum[:])}},
	}
	c := &collector{proc: proc, snap: snap}
	c.correlateChangedFiles()
	imageCheck := snap.Processes[0].Image
	if imageCheck.SHA256 != hex.EncodeToString(sum[:]) || len(imageCheck.MatchedFiles) != 1 || imageCheck.MatchedFiles[0] != "/bin/ps" {
		t.Fatalf("correlation %+v", imageCheck)
	}
}
