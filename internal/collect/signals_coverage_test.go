//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func TestHostSignalReadFailuresRemainVisible(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A non-directory component is a read error, not proof that RPM is absent.
	if err := os.WriteFile(filepath.Join(root, "var", "lib", "rpm"), []byte("blocked"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &collector{proc: filepath.Join(root, "proc"), sys: filepath.Join(root, "sys"), hostRoot: root, snap: &model.Snapshot{}}
	c.noteRPM()
	c.readBPF()
	c.readRawSockets()
	if c.snap.RPMState != "unavailable" || c.snap.BPFTree != "unavailable" {
		t.Fatalf("missing data was called absent: rpm=%s bpf=%s", c.snap.RPMState, c.snap.BPFTree)
	}
	var rpm, bpf, raw bool
	for _, issue := range c.snap.Coverage {
		if filepath.Base(issue.Source) == "rpmdb.sqlite" {
			rpm = true
		}
		if filepath.Base(issue.Source) == "bpf" {
			bpf = true
		}
		if filepath.Base(issue.Source) == "raw" {
			raw = true
		}
	}
	if !rpm || !bpf || !raw {
		t.Fatalf("missing coverage entries: %+v", c.snap.Coverage)
	}
}
