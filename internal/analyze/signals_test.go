package analyze

import (
	"strings"
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

func TestTruncatedPreloadFailsDefaultThreshold(t *testing.T) {
	snap := &model.Snapshot{PreloadTruncated: true}
	findings := hostFindings(snap)
	if len(findings) != 1 || findings[0].Rule != "HOST-LD-PRELOAD" || findings[0].Severity != model.SevMedium {
		t.Fatalf("findings %+v", findings)
	}
	if result, _ := model.HostExit(findings, model.SevMedium, false); result != "fail" {
		t.Fatalf("result %s", result)
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

func TestPacketSocketSeverity(t *testing.T) {
	all := model.Socket{Proto: "packet", Local: "iface=0", State: "type=3 protocol=0x0003", Inode: 900, EtherProto: 0x0003, Ifindex: 0}
	ipv4 := model.Socket{Proto: "packet", Local: "iface=2", State: "type=3 protocol=0x0800", Inode: 901, EtherProto: 0x0800, Ifindex: 2}
	owner := []model.Process{{PID: 7, Name: "tcpdump"}}
	for _, tc := range []struct {
		name     string
		snap     model.Snapshot
		severity string
		evidence string
	}{
		{"unowned all-protocol", model.Snapshot{Sockets: []model.Socket{all}}, model.SevMedium, "ETH_P_ALL) on all interfaces"},
		{"owned all-protocol", model.Snapshot{Sockets: []model.Socket{all}, SocketOwner: map[uint64]int{900: 7}, Processes: owner}, model.SevLow, "ETH_P_ALL"},
		{"incomplete census", model.Snapshot{Sockets: []model.Socket{all}, NetIncomplete: true}, model.SevLow, "owner unknown"},
		{"focused scan", model.Snapshot{Sockets: []model.Socket{all}, Focused: true}, model.SevLow, "owner unknown"},
		{"unowned single protocol", model.Snapshot{Sockets: []model.Socket{ipv4}}, model.SevLow, "packet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := socketTableFindings(&tc.snap)
			if len(got) != 1 || got[0].Severity != tc.severity || !strings.Contains(strings.Join(got[0].Evidence, "\n"), tc.evidence) {
				t.Fatalf("findings %+v", got)
			}
		})
	}
}

func TestRawRowCapKeepsMediumPacketSocket(t *testing.T) {
	snap := model.Snapshot{SocketOwner: map[uint64]int{}, Processes: []model.Process{{PID: 7, Name: "agent"}}}
	for i := 0; i < 12; i++ {
		ino := uint64(100 + i)
		snap.Sockets = append(snap.Sockets, model.Socket{Proto: "raw", Inode: ino})
		snap.SocketOwner[ino] = 7
	}
	snap.Sockets = append(snap.Sockets, model.Socket{Proto: "packet", Inode: 999, EtherProto: 0x0003})
	got := socketTableFindings(&snap)
	medium := 0
	for _, f := range got {
		if f.Severity == model.SevMedium {
			medium++
		}
	}
	if medium != 1 || len(got) != 10 {
		t.Fatalf("medium %d of %d findings: %+v", medium, len(got), got)
	}
}

func TestOversizeEnvironmentIsInconclusive(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    model.Process
		want string
	}{
		{"variable after the cap", model.Process{PID: 9, Name: "app", EnvTruncated: true}, "looked for only in the first 1 MiB"},
		{"variable inside the prefix", model.Process{PID: 9, Name: "app", EnvTruncated: true, LDPreload: "/tmp/x.so"}, "found in the first 1 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := envOversizeFinding(&tc.p)
			if len(got) != 1 || got[0].Rule != "PROC-ENV-OVERSIZE" || got[0].Severity != model.SevLow || !strings.Contains(got[0].Evidence[0], tc.want) {
				t.Fatalf("findings %+v", got)
			}
		})
	}
	if got := envOversizeFinding(&model.Process{PID: 9}); len(got) != 0 {
		t.Fatalf("complete environment produced %+v", got)
	}
}

func TestTruncatedMapsMarkMemoryFindings(t *testing.T) {
	p := model.Process{PID: 9, Name: "app", MapsOK: true, MapsTruncated: true,
		Maps: []model.Region{{Start: 1, End: 2, Perms: "rwxp", Path: ""}}}
	got := partialMaps(&p, []model.Finding{{Rule: "MEM-WX-ANON", PID: 9}})
	if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "region list is partial") {
		t.Fatalf("findings %+v", got)
	}
	p.MapsTruncated = false
	if got := partialMaps(&p, []model.Finding{{Rule: "MEM-WX-ANON", PID: 9}}); len(got[0].Evidence) != 0 {
		t.Fatalf("complete maps marked partial: %+v", got)
	}
}
