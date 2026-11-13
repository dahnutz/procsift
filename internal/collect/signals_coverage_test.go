//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dahnutz/procsift/internal/analyze"
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
	// The fixture has no dpkg database, so ownership adds a second entry.
	if len(c.snap.Coverage) != 2 || c.snap.Coverage[0].State != "truncated" || !strings.Contains(c.snap.Coverage[1].Detail, "ownership is inconclusive") {
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

func TestPreloadEntrySeverity(t *testing.T) {
	root := t.TempDir()
	mk := func(rel, body string, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	mk("var/lib/dpkg/info/libjemalloc2:amd64.list", "/usr/lib/x86_64-linux-gnu/libjemalloc.so.2\n", 0o644)
	mk("usr/lib/x86_64-linux-gnu/libjemalloc.so.2", "lib", 0o644)
	mk("tmp/hook.so", "lib", 0o644)
	mk("opt/agent/libagent.so", "lib", 0o644)
	mk("opt/open/libopen.so", "lib", 0o666)
	for _, tc := range []struct {
		name, preload string
		severity      string
		evidence      string
	}{
		{"packaged via merged /usr", "/lib/x86_64-linux-gnu/libjemalloc.so.2\n", model.SevMedium, "dpkg package libjemalloc2:amd64"},
		{"missing library", "/usr/lib/nothere.so\n", model.SevMedium, "file does not exist"},
		{"temporary path", "/tmp/hook.so\n", model.SevHigh, "temporary path"},
		{"unpackaged", "/opt/agent/libagent.so\n", model.SevHigh, "not listed by any dpkg package"},
		{"world-writable", "/opt/open/libopen.so\n", model.SevHigh, "world-writable"},
		{"bare name", "libjemalloc.so.2\n", model.SevMedium, "package ownership unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mk("etc/ld.so.preload", tc.preload, 0o644)
			c := &collector{hostRoot: root, snap: &model.Snapshot{}}
			c.readPreload()
			findings := analyze.Analyze(c.snap)
			var got *model.Finding
			for i := range findings {
				if findings[i].Rule == "HOST-LD-PRELOAD" {
					got = &findings[i]
				}
			}
			if got == nil || got.Severity != tc.severity || !strings.Contains(strings.Join(got.Evidence, "\n"), tc.evidence) {
				t.Fatalf("finding %+v", got)
			}
			if !strings.Contains(got.Evidence[0], "mode 0644") {
				t.Fatalf("file facts missing: %+v", got.Evidence)
			}
		})
	}
	for _, empty := range []string{"", "# only a comment\n", " \n\t:\n"} {
		mk("etc/ld.so.preload", empty, 0o644)
		c := &collector{hostRoot: root, snap: &model.Snapshot{}}
		c.readPreload()
		for _, f := range analyze.Analyze(c.snap) {
			if f.Rule == "HOST-LD-PRELOAD" {
				t.Fatalf("empty preload file %q produced %+v", empty, f)
			}
		}
	}
}

func TestParsePreloadPathsTable(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"/a.so\n/b.so\n", []string{"/a.so", "/b.so"}},
		{"/a.so /b.so\t/c.so", []string{"/a.so", "/b.so", "/c.so"}},
		{"/a.so:/b.so::", []string{"/a.so", "/b.so"}},
		{"# /x.so\n/y.so", []string{"/y.so"}},
		{"/a.so#/b.so\n/c.so", []string{"/a.so", "/c.so"}},
		{"\n\n  \n", nil},
		{"/a.so\r\n", []string{"/a.so\r"}}, // glibc does not treat \r as a separator
	} {
		got := parsePreloadPaths(tc.in)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%q: got %q want %q", tc.in, got, tc.want)
		}
	}
}
