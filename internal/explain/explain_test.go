package explain

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dahnutz/procsift/internal/model"
)

func TestPathRelation(t *testing.T) {
	running := FileView{OK: true, Dev: "8:1", Inode: 10}
	if PathRelation(running, FileView{Absent: true}) != PathUnlinked {
		t.Fatal("unlinked")
	}
	if PathRelation(running, FileView{OK: true, Dev: "8:1", Inode: 11}) != PathReplaced {
		t.Fatal("replaced")
	}
	if PathRelation(running, FileView{OK: true, Dev: "8:1", Inode: 10}) != PathSame {
		t.Fatal("same")
	}
	if PathRelation(running, FileView{Denied: true}) != PathInconclusive {
		t.Fatal("denied")
	}
}

func TestExplainRequiresBothPackageAndTime(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	later := start.Add(time.Hour)
	base := ExplainInput{
		Path: "/usr/bin/app", Relation: PathReplaced, IdentityOK: true,
		PackageDBReadable: true, Package: "app", Start: start, StartKnown: true,
		CurrentMtime: later, MtimeKnown: true,
		Transaction: later, TransactionKnown: true,
		ManifestKnown: true, ManifestMatch: true,
	}
	if Explain(base) != LabelMaintenance {
		t.Fatalf("transaction and manifest: %s", Explain(base))
	}
	mtimeOnly := base
	mtimeOnly.TransactionKnown = false
	mtimeOnly.ManifestKnown = false
	mtimeOnly.ManifestMatch = false
	if Explain(mtimeOnly) != LabelInconclusive {
		t.Fatal("newer mtime alone must not corroborate")
	}
	nameOnly := base
	nameOnly.TransactionKnown = false
	nameOnly.ManifestKnown = false
	if Explain(nameOnly) != LabelInconclusive {
		t.Fatal("package name alone must not corroborate")
	}
	noManifest := base
	noManifest.ManifestKnown = false
	noManifest.ManifestMatch = false
	if Explain(noManifest) != LabelInconclusive {
		t.Fatal("transaction without a manifest match must not corroborate")
	}
	timeOnly := base
	timeOnly.Package = ""
	timeOnly.Transaction = later
	timeOnly.TransactionKnown = true
	if Explain(timeOnly) != LabelInconclusive {
		t.Fatal("transaction alone must not corroborate")
	}
	temp := base
	temp.Temp = true
	temp.Path = "/tmp/payload"
	if Explain(temp) != LabelUnexplained {
		t.Fatal("temporary deleted image stays unexplained")
	}
	unlinked := base
	unlinked.Relation = PathUnlinked
	if Explain(unlinked) != LabelUnexplained {
		t.Fatal("unlinked without a replacement stays unexplained")
	}
	moved := base
	moved.IdentityOK = false
	if Explain(moved) != LabelInconclusive {
		t.Fatal("unstable identity")
	}
}

func TestMasquerade(t *testing.T) {
	k := model.Process{PID: 4, PPID: 40, Name: "[kworker/0:1]", Exe: "/tmp/x", Kthread: false}
	rule, _, _, ev, ok := Masquerade(k)
	if !ok || rule != "PROC-KTHREAD-MASQ" || len(ev) < 3 {
		t.Fatalf("kernel style %s %v %v", rule, ok, ev)
	}
	realK := k
	realK.Kthread = true
	realK.KthreadKnown = true
	if _, _, _, _, ok := Masquerade(realK); ok {
		t.Fatal("kernel thread should not be flagged")
	}
	interp := model.Process{Name: "sshd", Exe: "/usr/bin/python3", Cmdline: "python3 /tmp/sshd"}
	rule, _, detail, _, ok := Masquerade(interp)
	if !ok || rule != "PROC-TITLE-MASQ" || detail == "" {
		t.Fatalf("interpreter %s %v", rule, ok)
	}
	script := model.Process{Name: "myjob", Exe: "/usr/bin/python3", Cmdline: "python3 /opt/myjob"}
	if _, _, _, _, ok := Masquerade(script); ok {
		t.Fatal("script title should not be flagged")
	}
	trunc := model.Process{Name: "very-long-daemo", Exe: "/usr/bin/very-long-daemon-name"}
	if _, _, _, _, ok := Masquerade(trunc); ok {
		t.Fatal("truncated comm should not be flagged")
	}
	node := model.Process{Name: "MainThread", Exe: "/usr/bin/node"}
	if _, _, _, _, ok := Masquerade(node); ok {
		t.Fatal("runtime title is not a service masquerade")
	}
}

func TestLineage(t *testing.T) {
	by := map[int]model.Process{
		9: {PID: 9, PPID: 2, Name: "payload", Exe: "/tmp/payload (deleted)", UID: 1000},
		2: {PID: 2, PPID: 1, Name: "cron", Exe: "/usr/sbin/cron", UID: 0},
		1: {PID: 1, PPID: 0, Name: "systemd", Exe: "/usr/lib/systemd/systemd", UID: 0},
	}
	lines := Lineage(by, 9, 8)
	if len(lines) != 3 || lines[0][:6] != "pid 9 " || lines[2][:5] != "pid 1" {
		t.Fatalf("%v", lines)
	}
}

func TestServiceFromCgroup(t *testing.T) {
	text := "0::/system.slice/nginx.service\n"
	if ServiceFromCgroup(text) != "nginx.service" {
		t.Fatal(ServiceFromCgroup(text))
	}
	legacy := "1:name=systemd:/system.slice/cron.service"
	if ServiceFromCgroup(legacy) != "cron.service" {
		t.Fatal(ServiceFromCgroup(legacy))
	}
}

func TestPackagesAndStartup(t *testing.T) {
	root := t.TempDir()
	list := filepath.Join(root, "var", "lib", "dpkg", "info", "app.list")
	if err := os.MkdirAll(filepath.Dir(list), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(list, []byte("/usr/bin/app\n/usr/lib/libapp.so.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "var", "log", "dpkg.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("2026-03-01 00:00:00 upgrade app:amd64 1 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	owned, ok, trunc := FindPackages(root, []string{"/usr/bin/app", "/tmp/nope"})
	if !ok || trunc || owned["/usr/bin/app"] != "app" || owned["/tmp/nope"] != "" {
		t.Fatalf("%v %v %v", owned, ok, trunc)
	}
	when, found := LatestTransaction(root, "app")
	if !found || when.Year() != 2026 {
		t.Fatalf("%v %v", when, found)
	}
	cron := filepath.Join(root, "etc", "cron.d", "payload")
	if err := os.MkdirAll(filepath.Dir(cron), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cron, []byte("* * * * * root /tmp/payload --x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(root, "lib", "systemd", "system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "payload.service"), []byte("[Service]\nExecStart=/bin/true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exact, names, truncated := FindStartup(root, "/tmp/payload", &StartupBudget{})
	if truncated || len(exact) != 1 || exact[0].Match != "exact-path" {
		t.Fatalf("exact %+v trunc %v", exact, truncated)
	}
	if len(names) != 1 || names[0].Match != "name" {
		t.Fatalf("names %+v", names)
	}
	if ex, _, _ := FindStartup(root, "/usr/bin/python3", &StartupBudget{}); len(ex) != 0 {
		t.Fatal("generic interpreter should not be searched")
	}
}

func TestHostPath(t *testing.T) {
	if HostPath("/", "/usr/bin/app (deleted)") != "/usr/bin/app (deleted)" {
		t.Fatal(HostPath("/", "/usr/bin/app (deleted)"))
	}
	got := HostPath("/tmp/fix", "/tmp/fix/usr/bin/app (deleted)")
	if got != "/usr/bin/app (deleted)" {
		t.Fatal(got)
	}
}

func TestParseMapDev(t *testing.T) {
	got, ok := ParseMapDev("00:27")
	if !ok || got != "0:39" {
		t.Fatalf("%s %v", got, ok)
	}
}
