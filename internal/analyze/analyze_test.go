package analyze

import (
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func TestDeletedExeAndHidden(t *testing.T) {
	snap := &model.Snapshot{
		ModulesOK: true,
		SysfsOK:   true,
		SysfsNames: map[string]struct{}{
			"evil": {},
		},
		Processes: []model.Process{
			{
				PID: 42, TGID: 42, PPID: 99, Name: "payload", Listed: true,
				Exe: "/tmp/payload (deleted)", MapsOK: true,
				LDPreload: "/tmp/libx.so",
				Maps: []model.Region{
					{Start: 0x400000, End: 0x401000, Perms: "r-xp", Path: "/tmp/payload (deleted)"},
					{Start: 0x600000, End: 0x601000, Perms: "rwxp", Path: ""},
					{Start: 0x700000, End: 0x701000, Perms: "r-xp", Path: "[vdso]"},
				},
			},
			{
				PID: 7, TGID: 7, PPID: 1, Name: "ghostlead", Listed: false,
			},
		},
		Ghosts: []model.Ghost{{PID: 99}},
	}
	snap.NetOrphans = append([]model.Socket(nil), snap.Sockets...) // Collector-confirmed observations.
	fs := indexRules(Analyze(snap))
	need := []string{"PROC-DELETED-EXE", "PROC-HIDDEN-READDIR", "PROC-HIDDEN-TASK", "PROC-PARENT-HIDDEN", "PROC-LD-PRELOAD", "MEM-DELETED-EXEC", "MEM-WX-ANON"}
	for _, rule := range need {
		if _, ok := fs[rule]; !ok {
			t.Fatalf("missing %s in %v", rule, keys(fs))
		}
	}
	if fs["MEM-WX-ANON"].Severity != model.SevHigh {
		t.Fatalf("wx severity %s", fs["MEM-WX-ANON"].Severity)
	}
	if fs["PROC-DELETED-EXE"].Severity != model.SevHigh {
		t.Fatal(fs["PROC-DELETED-EXE"].Severity)
	}
}

func TestWXSeverity(t *testing.T) {
	small := &model.Process{
		PID: 1, TGID: 1, Name: "app", Listed: true, Exe: "/usr/bin/app", MapsOK: true,
		Maps: []model.Region{{Start: 0x1000, End: 0x3000, Perms: "rwxp"}},
	}
	large := &model.Process{
		PID: 2, TGID: 2, Name: "app", Listed: true, Exe: "/usr/bin/app", MapsOK: true,
		Maps: []model.Region{{Start: 0x1000, End: 0x1000 + wxMediumMin, Perms: "rwxp"}},
	}
	node := &model.Process{
		PID: 3, TGID: 3, Name: "MainThread", Listed: true, Exe: "/usr/bin/node", MapsOK: true,
		Maps: []model.Region{{Start: 0x1000, End: 0x1000 + 32<<20, Perms: "rwxp"}},
	}
	if sev := wxSev(small); sev != model.SevLow {
		t.Fatalf("small %s", sev)
	}
	if sev := wxSev(large); sev != model.SevMedium {
		t.Fatalf("large %s", sev)
	}
	if sev := wxSev(node); sev != model.SevLow {
		t.Fatalf("node %s", sev)
	}
}

func TestEmbeddedAndModulesAndNet(t *testing.T) {
	snap := &model.Snapshot{
		ModulesOK: true,
		SysfsOK:   true,
		SysfsNames: map[string]struct{}{
			"evil":      {},
			"ghostload": {},
		},
		SysfsLoadable: []string{"ghostload"},
		Modules: []model.Module{
			{Name: "evil", State: "Live", Address: "0x1", Taints: "E"},
			{Name: "hiddenmod", State: "Live", Address: "0x2"},
			{Name: "nvidia", State: "Live", Taints: "PO"},
		},
		Processes: []model.Process{{
			PID: 5, TGID: 5, Name: "inj", Listed: true, Exe: "/usr/bin/inj", MapsOK: true,
			FDComplete:   true,
			SocketInodes: []uint64{4242},
			Maps: []model.Region{{
				Start: 0x1000, End: 0x5000, Perms: "r-xp", Magic: "elf",
			}},
		}},
		Sockets: []model.Socket{
			{Proto: "tcp", Local: "0.0.0.0:80", Remote: "0.0.0.0:0", State: "LISTEN", StateID: 10, Inode: 4242},
			{Proto: "tcp", Local: "10.0.0.1:443", Remote: "10.0.0.2:9999", State: "ESTABLISHED", StateID: 1, Inode: 7777},
			{Proto: "tcp", Local: "1.1.1.1:1", Remote: "2.2.2.2:2", State: "TIME_WAIT", StateID: 6, Inode: 8888},
		},
		SocketOwner: map[uint64]int{4242: 5},
		SysV: []model.SysVShm{
			{ID: 9, Perms: 0777, Size: 4096, Nattch: 0},
		},
		DevShm: []model.DevShmFile{{Name: "stage.bin", Size: 100, Magic: "elf", Executable: true}},
	}
	snap.NetOrphans = append([]model.Socket(nil), snap.Sockets...) // Collector-confirmed observations.
	fs := indexRules(Analyze(snap))
	for _, rule := range []string{"MEM-EMBEDDED-IMAGE", "MOD-NO-SYSFS", "MOD-NO-PROC", "MOD-UNSIGNED", "MOD-PROPRIETARY", "NET-ORPHAN-SOCKET", "IPC-ORPHAN-SHM", "IPC-SHM-EXEC", "IPC-DEVSHM-FILE"} {
		if _, ok := fs[rule]; !ok {
			t.Fatalf("missing %s in %v", rule, keys(fs))
		}
	}
	if fs["NET-ORPHAN-SOCKET"].Subject != "inode 7777" {
		t.Fatalf("orphan subject %s", fs["NET-ORPHAN-SOCKET"].Subject)
	}
	if fs["MEM-EMBEDDED-IMAGE"].Severity != model.SevHigh {
		t.Fatal(fs["MEM-EMBEDDED-IMAGE"].Severity)
	}
}

func TestNetSkippedWhenIncomplete(t *testing.T) {
	snap := &model.Snapshot{
		NetIncomplete: true,
		Sockets: []model.Socket{
			{Proto: "tcp", State: "ESTABLISHED", StateID: 1, Inode: 1},
		},
	}
	snap.NetOrphans = append([]model.Socket(nil), snap.Sockets...)
	for _, f := range Analyze(snap) {
		if f.Rule == "NET-ORPHAN-SOCKET" {
			t.Fatal("orphan emitted on incomplete netns walk")
		}
	}
}

func TestMemfdFDStaysLow(t *testing.T) {
	p := &model.Process{
		PID: 1, TGID: 1, Name: "xfce4-session", Listed: true,
		Exe:      "/usr/bin/xfce4-session",
		MemfdFDs: []string{"/memfd:allocation fd (deleted)"},
	}
	var got model.Finding
	for _, f := range processFindings(p) {
		if f.Rule == "PROC-MEMFD-FD" {
			got = f
		}
	}
	if got.Severity != model.SevLow {
		t.Fatalf("severity %q", got.Severity)
	}
}

func TestZombieDeletedExeIgnored(t *testing.T) {
	snap := &model.Snapshot{
		Processes: []model.Process{{
			PID: 3, TGID: 3, Name: "old", State: "Z (zombie)", Listed: true,
			Exe: "/tmp/old (deleted)",
		}},
	}
	snap.NetOrphans = append([]model.Socket(nil), snap.Sockets...)
	for _, f := range Analyze(snap) {
		if f.Rule == "PROC-DELETED-EXE" {
			t.Fatal("zombie should not raise deleted exe")
		}
	}
}

func wxSev(p *model.Process) string {
	for _, f := range memoryFindings(p) {
		if f.Rule == "MEM-WX-ANON" {
			return f.Severity
		}
	}
	return ""
}

func indexRules(fs []model.Finding) map[string]model.Finding {
	out := map[string]model.Finding{}
	for _, f := range fs {
		if _, ok := out[f.Rule]; !ok {
			out[f.Rule] = f
		}
	}
	return out
}

func keys(m map[string]model.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestUnconfirmedSocketDoesNotBecomeFinding(t *testing.T) {
	s := &model.Snapshot{Sockets: []model.Socket{{Proto: "tcp", StateID: 10, Inode: 4242}}}
	if fs := netFindings(s); len(fs) != 0 {
		t.Fatalf("unconfirmed socket flagged: %+v", fs)
	}
	s.NetOrphans = append([]model.Socket(nil), s.Sockets...)
	fs := netFindings(s)
	if len(fs) != 1 || fs[0].Severity != model.SevMedium {
		t.Fatalf("confirmed observation should be medium: %+v", fs)
	}
}
