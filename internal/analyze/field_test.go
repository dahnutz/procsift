package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/dahnutz/procsift/internal/explain"
	"github.com/dahnutz/procsift/internal/model"
)

func TestScannerSelfDoesNotMarkADifferentProcess(t *testing.T) {
	snap := &model.Snapshot{
		Scanner: model.Scanner{PID: 9, StartTicks: 10, Known: true},
		Processes: []model.Process{
			{PID: 9, Name: "procsift", StartTicks: 10, Exe: "/memfd:procsift (deleted)", KthreadKnown: true},
			{PID: 10, Name: "procsift", StartTicks: 99, Exe: "/memfd:other (deleted)", KthreadKnown: true},
		},
	}
	findings := Analyze(snap)
	var self, other int
	for _, f := range findings {
		if f.Rule != "PROC-MEMFD-EXE" && f.Rule != "PROC-DELETED-EXE" {
			continue
		}
		if f.PID == 9 {
			self++
			if f.Origin != "scanner_self" {
				t.Fatalf("scanner origin %q", f.Origin)
			}
		}
		if f.PID == 10 && f.Origin != "" {
			t.Fatalf("other process origin %q", f.Origin)
		}
		if f.PID == 10 {
			other++
		}
	}
	if self == 0 || other == 0 {
		t.Fatalf("self %d other %d", self, other)
	}
	rows := Rank(snap, findings)
	for _, row := range rows {
		if row.PID == 9 {
			t.Fatalf("scanner process in first-action list: %+v", row)
		}
	}
}

func TestRankPrefersDeletedTempOverMaintenance(t *testing.T) {
	start := time.Unix(1700000000, 0).UTC()
	snap := &model.Snapshot{Processes: []model.Process{
		{PID: 3, Name: "kept", Exe: "/usr/bin/app (deleted)", Started: start, KthreadKnown: true, ExeInfo: &model.ExeIdentity{
			Relation: explain.PathReplaced, Label: explain.LabelMaintenance, Package: "app", IdentityOK: true,
		}},
		{PID: 4, Name: "drop", Exe: "/tmp/drop (deleted)", KthreadKnown: true, ExeInfo: &model.ExeIdentity{
			Relation: explain.PathUnlinked, Label: explain.LabelUnexplained, IdentityOK: true,
		}},
	}}
	findings := Analyze(snap)
	rows := Rank(snap, findings)
	if len(rows) == 0 || rows[0].PID != 4 {
		t.Fatalf("%+v", rows)
	}
	if rows[0].Level != "observed" {
		t.Fatal(rows[0].Level)
	}
	foundMaint := false
	for _, row := range rows {
		if row.PID == 3 {
			foundMaint = true
			if row.Level != "corroborated" {
				t.Fatalf("maintenance level %s", row.Level)
			}
		}
	}
	if !foundMaint {
		t.Fatal("maintenance process missing from attention")
	}
}

func TestUnpackagedRootStaysSeparateFromExtraUID0(t *testing.T) {
	snap := &model.Snapshot{
		ExtraUID0: []string{"toor"},
		Processes: []model.Process{{
			PID: 8, UID: 0, User: "root", Name: "custom", Exe: "/tmp/custom", KthreadKnown: true,
			Image: &model.ImageCheck{Path: "/tmp/custom", State: "unlisted"},
		}},
	}
	findings := Analyze(snap)
	var root, extra bool
	for _, f := range findings {
		if f.Rule == "PROC-UNPACKAGED-ROOT" {
			root = true
			if !strings.Contains(f.Detail, "temporary") {
				t.Fatal(f.Detail)
			}
		}
		if f.Rule == "PROC-EXTRA-UID0" {
			extra = true
			if strings.Contains(strings.Join(f.Evidence, " "), "password") {
				t.Fatal(f.Evidence)
			}
		}
	}
	if !root || !extra {
		t.Fatalf("root %v extra %v", root, extra)
	}
}

func TestUnitFindingDoesNotClaimLaunch(t *testing.T) {
	snap := &model.Snapshot{Processes: []model.Process{{
		PID: 5, Name: "worker", Exe: "/tmp/worker (deleted)", KthreadKnown: true,
		Service: "example.service",
		Unit: &model.UnitLink{
			Service: "example.service", UnitFile: "/lib/systemd/system/example.service",
			ExecStart: []string{"/var/tmp/worker"},
			TimerFile: "/lib/systemd/system/example.timer", TimerLine: "Unit=example.service",
			Journal: "not collected",
		},
	}}}
	findings := Analyze(snap)
	var unit model.Finding
	for _, f := range findings {
		if f.Rule == "PROC-UNIT" && f.PID == 5 {
			unit = f
		}
	}
	if unit.Rule == "" {
		t.Fatal("missing unit finding")
	}
	text := unit.Detail + " " + strings.Join(unit.Evidence, " ")
	if !strings.Contains(text, "not collected") || !strings.Contains(text, "Unit=example.service") {
		t.Fatal(text)
	}
	if strings.Contains(strings.ToLower(unit.Detail), "this process was started") {
		t.Fatal(unit.Detail)
	}
}
