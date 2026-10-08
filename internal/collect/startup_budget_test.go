//go:build linux

package collect

import (
	"fmt"
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func TestStartupPathCapMarksUnsearchedProcesses(t *testing.T) {
	snap := &model.Snapshot{}
	for i := 1; i <= 65; i++ {
		path := fmt.Sprintf("/usr/local/bin/example-%d", i)
		snap.Processes = append(snap.Processes, model.Process{
			PID: i, Exe: path, Image: &model.ImageCheck{Path: path, State: "unlisted"},
		})
	}
	c := &collector{hostRoot: t.TempDir(), snap: snap}
	c.attachStartup()
	if snap.Processes[0].StartupStatus != "complete" || snap.Processes[64].StartupStatus != "not-searched" || !snap.Processes[64].StartupIncomplete {
		t.Fatalf("first=%s last=%s", snap.Processes[0].StartupStatus, snap.Processes[64].StartupStatus)
	}
	if len(snap.Coverage) == 0 {
		t.Fatal("unsearched process missing from coverage")
	}
}
