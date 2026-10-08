package report

import (
	"strings"
	"testing"
	"time"

	"github.com/dahnutz/procsift/internal/model"
)

func TestTextReportContainsFinding(t *testing.T) {
	snap := &model.Snapshot{
		Hostname:  "fixture",
		OSRelease: "9.9.9-fixture",
		Kernel:    "Linux version fixture",
		EUID:      1000,
		PIDMax:    100,
		Started:   time.Unix(1700000000, 0).UTC(),
		Taint:     0,
		Processes: []model.Process{{
			PID: 42, Name: "payload", Exe: "/tmp/payload (deleted)", Listed: true, MapsOK: true,
			Maps: []model.Region{{Start: 1, End: 2, Perms: "r-xp", Path: "/tmp/payload (deleted)"}},
		}},
		Notes:  []string{"note one"},
		Limits: []string{"limit one"},
	}
	findings := []model.Finding{{
		Rule: "PROC-DELETED-EXE", Severity: model.SevHigh, Category: "process",
		PID: 42, Process: "payload", Summary: "executable was deleted and is still running",
	}}
	rep := Build(snap, findings, Options{Version: "0.1.0", MinSeverity: model.SevLow})
	var b strings.Builder
	if err := Write(&b, rep, "text"); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	for _, want := range []string{"procsift 0.1.0", "Host result", "Exit reason", "Daniel Hanganu", "9.9.9-fixture", "PROC-DELETED-EXE", "deleted mappings", "limit one"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q\n%s", want, text)
		}
	}
	if rep.Objects.DeletedMappings != 1 {
		t.Fatalf("deleted %d", rep.Objects.DeletedMappings)
	}
	if rep.Counts.High != 1 {
		t.Fatal(rep.Counts)
	}
}
