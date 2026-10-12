package compare

import (
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func proc(pid int, ticks uint64, hash, scope string) model.ProcessView {
	return model.ProcessView{PID: pid, StartTicks: ticks, ExeDev: "8:1", ExeInode: 10, ExeHash: hash, ExeHashScope: scope, Name: "app"}
}

func comparable(rep model.Report) model.Report {
	rep.MinSeverity = model.SevLow
	rep.ScanOptions = &model.ScanOptions{ReadMagic: true}
	return rep
}

func TestDiffKeepsIdentityAndVersionSeparate(t *testing.T) {
	older := model.Report{
		Version: "0.4.0",
		Host:    model.HostInfo{BootID: "boot"},
		Processes: []model.ProcessView{
			proc(4, 100, "aaa", "full"),
		},
		Sockets: []model.SocketView{{Proto: "tcp", Local: "10.0.0.1:1", Remote: "10.0.0.2:2", State: "ESTABLISHED", Inode: 9}},
	}
	newer := older
	newer.Version = "0.5.0"
	newer.Processes = []model.ProcessView{proc(4, 100, "aaa", "full")}
	newer.Sockets = append([]model.SocketView{}, older.Sockets...)
	newer.Sockets = append(newer.Sockets, model.SocketView{Proto: "tcp", Local: "10.0.0.1:1", Remote: "10.0.0.9:9", State: "ESTABLISHED", Inode: 11})
	newer.Findings = []model.Finding{{Rule: "NET-METADATA", PID: 4, Severity: model.SevLow}}
	got := Diff(comparable(older), comparable(newer))
	if got.HostEvidence != 0 || len(got.SocketChanges) != 1 || got.SocketChanges[0].Kind != "observed" {
		t.Fatalf("a one-snapshot socket should remain an observation: %+v", got)
	}
	var rule bool
	for _, change := range got.FindingChanges {
		if change.Kind == "new-rule" {
			rule = true
		}
		if change.Kind == "host-evidence" && change.Subject == "NET-METADATA pid 4 " {
			t.Fatalf("new rule counted as host evidence: %+v", change)
		}
	}
	if !rule {
		t.Fatalf("missing new-rule: %+v", got.FindingChanges)
	}
}

func TestRepeatScanExcludesScannerAndTransientTraffic(t *testing.T) {
	host := proc(42, 100, "aaa", "full")
	oldSelf := proc(90, 900, "", "")
	newSelf := proc(91, 901, "", "")
	older := model.Report{
		Version: "0.5.0", Host: model.HostInfo{BootID: "boot", Hostname: "host"},
		ScannerPID: 90, ScannerTicks: 900,
		Processes: []model.ProcessView{host, oldSelf},
		Findings: []model.Finding{
			{Rule: "PROC-DELETED-EXE", PID: 42, Severity: model.SevHigh},
			{Rule: "PROC-MEMFD-EXE", PID: 90, Severity: model.SevHigh, Origin: "scanner_self"},
		},
		Sockets: []model.SocketView{{Proto: "tcp", Local: "127.0.0.1:1", Remote: "127.0.0.1:2", State: "ESTABLISHED", Inode: 10, PID: 90}},
	}
	newer := older
	newer.ScannerPID, newer.ScannerTicks = 91, 901
	newer.Processes = []model.ProcessView{host, newSelf}
	newer.Findings = []model.Finding{
		{Rule: "PROC-DELETED-EXE", PID: 42, Severity: model.SevHigh},
		{Rule: "PROC-MEMFD-EXE", PID: 91, Severity: model.SevHigh, Origin: "scanner_self"},
	}
	newer.Sockets = []model.SocketView{{Proto: "tcp", Local: "127.0.0.1:3", Remote: "127.0.0.1:4", State: "ESTABLISHED", Inode: 11}}
	got := Diff(comparable(older), comparable(newer))
	if got.HostEvidence != 0 || len(got.ProcessChanges) != 0 || len(got.FindingChanges) != 0 || len(got.SocketChanges) != 1 {
		t.Fatalf("scan-created and transient activity became host evidence: %+v", got)
	}
}

func TestDiffRefusesDifferentBootsAndFindsNewHighRule(t *testing.T) {
	older := model.Report{Version: "0.5.0", Host: model.HostInfo{BootID: "first"}, Processes: []model.ProcessView{proc(42, 100, "aaa", "full")}}
	newer := older
	newer.Host.BootID = "second"
	if got := Diff(comparable(older), comparable(newer)); got.ScopeIssue == "" || got.HostEvidence != 0 {
		t.Fatalf("cross-boot comparison was accepted: %+v", got)
	}
	newer.Host.BootID = "first"
	newer.Findings = []model.Finding{{Rule: "PROC-DELETED-EXE", PID: 42, Severity: model.SevHigh}}
	if got := Diff(comparable(older), comparable(newer)); got.ScopeIssue != "" || got.HostEvidence != 1 {
		t.Fatalf("new independent high finding was missed: %+v", got)
	}
}

func TestPIDReuseIsNotContinuity(t *testing.T) {
	older := model.Report{Host: model.HostInfo{BootID: "boot"}, Processes: []model.ProcessView{proc(4, 100, "aaa", "full")}}
	newer := model.Report{Host: model.HostInfo{BootID: "boot"}, Processes: []model.ProcessView{proc(4, 900, "aaa", "full")}}
	got := Diff(comparable(older), comparable(newer))
	if len(got.ProcessChanges) != 1 || got.ProcessChanges[0].Kind != "pid-reuse" {
		t.Fatalf("%+v", got.ProcessChanges)
	}
}

func TestSameRuleOnReusedPIDIsNewEvidence(t *testing.T) {
	older := model.Report{Version: "0.5.0", Host: model.HostInfo{BootID: "boot"}, Processes: []model.ProcessView{proc(4, 100, "aaa", "full")}, Findings: []model.Finding{{Rule: "PROC-DELETED-EXE", PID: 4, Severity: model.SevHigh}}}
	newer := older
	newer.Processes = []model.ProcessView{proc(4, 900, "bbb", "full")}
	got := Diff(comparable(older), comparable(newer))
	if got.HostEvidence != 1 || got.Uncertain != 1 {
		t.Fatalf("same rule on a reused PID was merged with the old process: %+v", got)
	}
}

func TestMissingIdentityIsUncertain(t *testing.T) {
	older := model.Report{Host: model.HostInfo{BootID: "boot"}, Processes: []model.ProcessView{{PID: 4}}}
	newer := model.Report{Host: model.HostInfo{BootID: "boot"}, Processes: []model.ProcessView{{PID: 4, StartTicks: 1}}}
	got := Diff(comparable(older), comparable(newer))
	if len(got.ProcessChanges) != 1 || got.ProcessChanges[0].Kind != "uncertain" {
		t.Fatalf("%+v", got.ProcessChanges)
	}
}

func TestDiffRefusesMismatchedScanScope(t *testing.T) {
	base := comparable(model.Report{Host: model.HostInfo{BootID: "boot"}})
	base.Findings = []model.Finding{{Rule: "PROC-LD-PRELOAD", PID: 42, Severity: model.SevMedium}}
	for _, tc := range []struct {
		name string
		edit func(*model.Report)
	}{
		{"min severity", func(r *model.Report) { r.MinSeverity = model.SevHigh }},
		{"pid", func(r *model.Report) { r.ScanOptions.PID = 42 }},
		{"all", func(r *model.Report) { r.ScanOptions.All = true }},
		{"privileges", func(r *model.Report) { r.Host.EUID = 1000 }},
		{"deep", func(r *model.Report) { r.ScanOptions.Deep = true }},
		{"magic", func(r *model.Report) { r.ScanOptions.ReadMagic = false }},
		{"manifest", func(r *model.Report) { r.ScanOptions.Manifest = "/tmp/reference"; r.ScanOptions.ManifestSHA256 = "abc" }},
		{"missing options", func(r *model.Report) { r.ScanOptions = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newer := base
			scope := *base.ScanOptions
			newer.ScanOptions = &scope
			tc.edit(&newer)
			got := Diff(base, newer)
			if got.ScopeIssue == "" || got.HostEvidence != 0 {
				t.Fatalf("unsafe comparison: %+v", got)
			}
		})
	}
}
