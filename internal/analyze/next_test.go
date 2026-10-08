package analyze

import (
	"strings"
	"testing"

	"github.com/dahnutz/procsift/internal/explain"
	"github.com/dahnutz/procsift/internal/model"
)

func TestChangedFileCorrelationRanksAboveSnapContext(t *testing.T) {
	snap := &model.Snapshot{
		FileChecks: []model.FileCheck{{Path: "/bin/ps", Package: "procps", State: "mismatch", MD5: "one", Manifest: "two", SHA256: "same"}},
		Processes: []model.Process{
			{PID: 10, UID: 0, Name: "managed", Exe: "/snap/core/1/bin/managed", KthreadKnown: true, Image: &model.ImageCheck{Path: "/snap/core/1/bin/managed", State: "unlisted", PackageSource: "snap-mount-observed"}},
			{PID: 11, UID: 0, Name: "suspect", Exe: "/usr/local/bin/suspect", KthreadKnown: true, Image: &model.ImageCheck{Path: "/usr/local/bin/suspect", State: "unlisted", SHA256: "same", MatchedFiles: []string{"/bin/ps"}}},
		},
	}
	findings := Analyze(snap)
	var disk, source, related bool
	for _, f := range findings {
		switch f.Rule {
		case "FILE-PKG-MISMATCH":
			disk = true
		case "PROC-PKG-OTHER-SOURCE":
			source = true
		case "PROC-FILE-MATCH":
			related = true
		}
	}
	if !disk || !source || !related {
		t.Fatalf("disk=%t source=%t related=%t", disk, source, related)
	}
	rows := Rank(snap, findings)
	if len(rows) == 0 || rows[0].PID != 11 {
		t.Fatalf("rank %+v", rows)
	}
}

func TestContextualDisguiseNeedsMultipleSignals(t *testing.T) {
	suspect := model.Process{PID: 3, UID: 0, Name: "getty", Exe: "/usr/local/lib/getty", Service: "custom.service", KthreadKnown: true, Image: &model.ImageCheck{State: "unlisted"}}
	if got := contextualDisguise(nil, &suspect); len(got) != 1 || got[0].Rule != "PROC-CONTEXT-DISGUISE" {
		t.Fatalf("unexpected finding: %+v", got)
	}
	ordinary := suspect
	ordinary.Service = ""
	ordinary.Image = &model.ImageCheck{State: "unlisted"}
	if got := contextualDisguise(nil, &ordinary); len(got) != 0 {
		t.Fatalf("name-only false positive: %+v", got)
	}
	deleted := model.Process{PID: 4, Name: "worker", Exe: "/var/tmp/worker (deleted)", Cmdline: "alternate-title", KthreadKnown: true, ExeInfo: &model.ExeIdentity{Label: explain.LabelUnexplained}}
	got := contextualDisguise(nil, &deleted)
	if len(got) != 1 || !strings.Contains(strings.Join(got[0].Evidence, " "), "different command-line title") {
		t.Fatalf("deleted title context: %+v", got)
	}
}
