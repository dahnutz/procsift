//go:build linux

package explain

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A user can plant a FIFO, or a symlink to one, in their own unit directory.
// The startup search runs as root and must neither block nor follow it.
func TestStartupSearchIgnoresPlantedFIFOs(t *testing.T) {
	root := t.TempDir()
	userUnits := filepath.Join(root, "home", "mallory", ".config", "systemd", "user")
	if err := os.MkdirAll(userUnits, 0o755); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(userUnits, "stall.service")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, filepath.Join(userUnits, "link.service")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userUnits, "real.service"), []byte("[Service]\nExecStart=/usr/local/bin/agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc", "systemd", "system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "etc", "systemd", "system", "stall.service"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var exact int
	go func() {
		defer close(done)
		results, _ := FindStartupMany(root, []string{"/usr/local/bin/agent"})
		e, _, _ := FindStartup(root, "/usr/local/bin/agent", nil)
		exact = len(results["/usr/local/bin/agent"].Exact) + len(e)
		_ = ReadUnit(root, "stall.service")
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("startup search blocked on a FIFO")
	}
	if exact != 2 {
		t.Fatalf("regular unit not found by both searches: %d exact hits", exact)
	}
}
