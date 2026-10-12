//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"strings"
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

func TestPreloadPrefixAndGlibcSeparators(t *testing.T) {
	if got := parsePreloadPaths("# /lib/ignored.so\n/lib/used.so # trailing\n"); len(got) != 1 || got[0] != "/lib/used.so" {
		t.Fatalf("comment parsing %+v", got)
	}
	root := t.TempDir()
	path := filepath.Join(root, "etc", "ld.so.preload")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := "/lib/a.so:/lib/b.so # /lib/comment.so\n" + strings.Repeat(" ", 4096)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &collector{hostRoot: root, snap: &model.Snapshot{}}
	c.readPreload()
	if len(c.snap.PreloadPaths) != 2 || c.snap.PreloadPaths[0] != "/lib/a.so" || c.snap.PreloadPaths[1] != "/lib/b.so" {
		t.Fatalf("paths %+v", c.snap.PreloadPaths)
	}
	if len(c.snap.Coverage) != 1 || c.snap.Coverage[0].State != "truncated" {
		t.Fatalf("coverage %+v", c.snap.Coverage)
	}
	if err := os.WriteFile(path, []byte("/lib/only.so "+strings.Repeat(" ", 4096)), 0o644); err != nil {
		t.Fatal(err)
	}
	c.snap = &model.Snapshot{}
	c.readPreload()
	if len(c.snap.PreloadPaths) != 1 || c.snap.PreloadPaths[0] != "/lib/only.so" {
		t.Fatalf("no-newline paths %+v", c.snap.PreloadPaths)
	}
}

func TestPacketSocketReachesFinding(t *testing.T) {
	root := t.TempDir()
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	packet := "sk RefCnt Type Proto Iface R Rmem User Inode\n0000000000000000 3 3 0003 2 1 0 0 4242\nbroken row\n"
	if err := os.WriteFile(filepath.Join(netDir, "packet"), []byte(packet), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &collector{proc: root, snap: &model.Snapshot{}}
	c.readRawSockets()
	if len(c.snap.Sockets) != 1 || c.snap.Sockets[0].Inode != 4242 {
		t.Fatalf("sockets %+v", c.snap.Sockets)
	}
	found := false
	for _, issue := range c.snap.Coverage {
		if issue.Source == filepath.Join(netDir, "packet") && issue.State == "error" {
			found = true
		}
	}
	if !found {
		t.Fatalf("coverage %+v", c.snap.Coverage)
	}
}
