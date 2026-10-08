package analyze

import (
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func TestShellWithoutTTY(t *testing.T) {
	snap := &model.Snapshot{Processes: []model.Process{
		{PID: 7, Name: "bash", Exe: "/bin/bash", Stdin: "socket:[99]", TTYKnown: true, TTY: 0, KthreadKnown: true, PPID: 1},
		{PID: 8, Name: "bash", Exe: "/bin/bash", Stdin: "socket:[99]", TTYKnown: true, TTY: 34816, KthreadKnown: true},
	}}
	findings := Analyze(snap)
	var flagged int
	for _, f := range findings {
		if f.Rule == "PROC-SOCKET-SHELL" {
			flagged++
			if f.PID != 7 || f.Severity != model.SevMedium {
				t.Fatalf("%+v", f)
			}
		}
	}
	if flagged != 1 {
		t.Fatalf("flagged %d", flagged)
	}
}

func TestSensitiveFDStaysLow(t *testing.T) {
	snap := &model.Snapshot{Processes: []model.Process{{
		PID: 3, Name: "dockerd", Exe: "/usr/bin/dockerd", KthreadKnown: true,
		SensitiveFDs: []string{"4 -> /run/docker.sock"},
	}}}
	findings := Analyze(snap)
	for _, f := range findings {
		if f.Rule == "PROC-SENSITIVE-FD" {
			if f.Severity != model.SevLow {
				t.Fatal(f.Severity)
			}
			return
		}
	}
	t.Fatal("missing sensitive fd finding")
}

func TestMetadataIsUnownedWhenUnattributed(t *testing.T) {
	snap := &model.Snapshot{
		Sockets:     []model.Socket{{Proto: "tcp", Remote: "169.254.169.254:80", Local: "10.0.0.5:9", State: "ESTABLISHED", Inode: 5}},
		SocketOwner: map[uint64]int{},
	}
	findings := Analyze(snap)
	for _, f := range findings {
		if f.Rule == "NET-METADATA" {
			if f.PID != 0 || f.Subject != "unowned" {
				t.Fatalf("%+v", f)
			}
			return
		}
	}
	t.Fatal("missing metadata finding")
}

func TestScannerDisguiseIsNotSelfByName(t *testing.T) {
	self := model.Process{PID: 9, UID: 0, Name: "procsift", StartTicks: 10, Exe: "/usr/local/lib/getty", Service: "custom.service", KthreadKnown: true, Image: &model.ImageCheck{State: "unlisted"}}
	other := self
	other.PID = 10
	other.StartTicks = 99
	other.Name = "procsift"
	snap := &model.Snapshot{Scanner: model.Scanner{PID: 9, StartTicks: 10, Known: true}, Processes: []model.Process{self, other}}
	if got := contextualDisguise(snap, &self); len(got) != 0 {
		t.Fatalf("scanner disguise %+v", got)
	}
	if got := contextualDisguise(snap, &other); len(got) != 1 {
		t.Fatalf("other process %+v", got)
	}
	findings := Analyze(snap)
	for _, f := range findings {
		if f.PID == 10 && f.Origin == "scanner_self" {
			t.Fatalf("named like the scanner: %+v", f)
		}
		if f.PID == 9 && f.Rule == "PROC-CONTEXT-DISGUISE" {
			t.Fatal("scanner received contextual disguise")
		}
	}
}
