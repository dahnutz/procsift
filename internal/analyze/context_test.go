package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/dahnutz/procsift/internal/explain"
	"github.com/dahnutz/procsift/internal/model"
)

func TestDeletedDossierStaysHigh(t *testing.T) {
	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	replaced := &model.Process{
		PID: 9, TGID: 9, PPID: 1, Name: "app", UID: 0, User: "root", Listed: true,
		Exe: "/usr/bin/app (deleted)", Started: start, StartTicks: 50,
		FDComplete: true,
		ExeInfo: &model.ExeIdentity{
			BootID: "boot-1", Dev: "8:1", Inode: 10, NLink: 0, Size: 100,
			SHA256: strings.Repeat("ab", 32), HashState: "complete", HashBytes: 100,
			Relation: explain.PathReplaced, CurrentDev: "8:1", CurrentInode: 11,
			Label: explain.LabelMaintenance, Package: "app", IdentityOK: true,
		},
	}
	temp := &model.Process{
		PID: 10, TGID: 10, PPID: 1, Name: "payload", Listed: true,
		Exe: "/tmp/payload (deleted)",
		ExeInfo: &model.ExeIdentity{
			Relation: explain.PathUnlinked, Label: explain.LabelUnexplained, IdentityOK: true,
		},
		SocketInodes: []uint64{77},
		FDComplete:   true,
		Startup: []model.StartupRef{{
			Kind: "cron", File: "/etc/cron.d/payload", Match: "exact-path", Line: "* * * * * root /tmp/payload",
		}},
	}
	snap := &model.Snapshot{
		BootID: "boot-1",
		Processes: []model.Process{
			*replaced, *temp,
			{PID: 1, PPID: 0, Name: "systemd", Exe: "/usr/lib/systemd/systemd"},
		},
		Sockets: []model.Socket{{
			Proto: "tcp", State: "ESTABLISHED", StateID: 1,
			Local: "10.0.0.8:40000", Remote: "10.0.0.9:443", Inode: 77,
		}},
	}
	var replacedFinding, tempFinding model.Finding
	var sawStartup, sawSocket, sawLineage bool
	for _, f := range Analyze(snap) {
		switch {
		case f.Rule == "PROC-DELETED-EXE" && f.PID == 9:
			replacedFinding = f
		case f.Rule == "PROC-DELETED-EXE" && f.PID == 10:
			tempFinding = f
		case f.Rule == "PROC-STARTUP" && f.PID == 10:
			sawStartup = true
		case f.Rule == "PROC-SOCKETS" && f.PID == 10:
			sawSocket = strings.Contains(strings.Join(f.Evidence, "\n"), "10.0.0.9:443")
		case f.Rule == "PROC-LINEAGE" && f.PID == 10:
			sawLineage = true
		}
	}
	if replacedFinding.Severity != model.SevHigh || !strings.Contains(replacedFinding.Summary, explain.LabelMaintenance) || !strings.Contains(replacedFinding.Summary, explain.PathReplaced) {
		t.Fatalf("replaced %+v", replacedFinding)
	}
	blob := strings.Join(replacedFinding.Evidence, "\n")
	if !strings.Contains(blob, "boot boot-1") || !strings.Contains(blob, "inode 10") || !strings.Contains(blob, "package app") {
		t.Fatalf("dossier\n%s", blob)
	}
	if tempFinding.Severity != model.SevHigh || !strings.Contains(tempFinding.Summary, explain.LabelUnexplained) {
		t.Fatalf("temp %+v", tempFinding)
	}
	if !sawStartup || !sawSocket || !sawLineage {
		t.Fatalf("joins startup %v socket %v lineage %v", sawStartup, sawSocket, sawLineage)
	}
}

func TestKernelTitleMasquerade(t *testing.T) {
	snap := &model.Snapshot{Processes: []model.Process{{
		PID: 3, TGID: 3, PPID: 1, Name: "[kworker/1:0]", Exe: "/dev/shm/worker", Listed: true, FDComplete: true,
	}}}
	found := false
	for _, f := range Analyze(snap) {
		if f.Rule == "PROC-KTHREAD-MASQ" && strings.Contains(f.Detail, "mismatch") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected masquerade explanation")
	}
}
