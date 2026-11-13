//go:build linux

package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func tcpRow(i int) string {
	return fmt.Sprintf("%4d: 0100007F:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 %d 1 0\n", i, 1000+i%60000, 10000+i)
}

func writeNet(t *testing.T, root, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "net", name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasCoverage(c *collector, source, state, detail string) bool {
	for _, issue := range c.snap.Coverage {
		if issue.Source == source && issue.State == state && strings.Contains(issue.Detail, detail) {
			return true
		}
	}
	return false
}

func TestUnrecognizedSocketTableIsCoverage(t *testing.T) {
	root := t.TempDir()
	writeNet(t, root, "tcp", tcpHeader+"this is not a socket row\n")
	writeNet(t, root, "tcp6", tcpHeader)
	writeNet(t, root, "udp", tcpHeader+tcpRow(1))
	c := &collector{proc: root, snap: &model.Snapshot{}}
	rows, complete := c.readSockets()
	if complete || len(rows) != 1 {
		t.Fatalf("rows %d complete %v", len(rows), complete)
	}
	if !hasCoverage(c, filepath.Join(root, "net", "tcp"), "unavailable", "no rows parsed; format not recognized") {
		t.Fatalf("garbage table not reported: %+v", c.snap.Coverage)
	}
	if hasCoverage(c, filepath.Join(root, "net", "tcp6"), "unavailable", "no rows parsed") {
		t.Fatal("header-only table reported as unrecognized")
	}
}

func TestRawSocketsSurviveLargeTCPInventory(t *testing.T) {
	root := t.TempDir()
	writeNet(t, root, "raw", tcpHeader+"   0: 00000000:00FF 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 4243 2 0000000000000000 0\n")
	c := &collector{proc: root, snap: &model.Snapshot{Sockets: make([]model.Socket, 9000)}}
	c.readRawSockets()
	if len(c.snap.Sockets) != 9001 || c.snap.Sockets[9000].Inode != 4243 {
		t.Fatalf("raw socket dropped after a large TCP inventory: %d sockets", len(c.snap.Sockets))
	}
}

func TestSocketTableRowCap(t *testing.T) {
	old := maxSocketTableRows
	maxSocketTableRows = 3
	t.Cleanup(func() { maxSocketTableRows = old })
	root := t.TempDir()
	writeNet(t, root, "tcp", tcpHeader+tcpRow(1)+tcpRow(2)+tcpRow(3)+tcpRow(4))
	c := &collector{proc: root, snap: &model.Snapshot{}}
	rows, complete := c.readSockets()
	if len(rows) != 3 || complete {
		t.Fatalf("rows %d complete %v", len(rows), complete)
	}
	if !hasCoverage(c, filepath.Join(root, "net", "tcp"), "truncated", "stopped at 3 rows") {
		t.Fatalf("coverage %+v", c.snap.Coverage)
	}
}

func TestExitedThreadIsNotCoverage(t *testing.T) {
	root := t.TempDir()
	task := filepath.Join(root, "42", "task")
	if err := os.MkdirAll(task, 0o755); err != nil {
		t.Fatal(err)
	}
	// A listed thread whose directory no longer resolves: it exited.
	if err := os.Symlink(filepath.Join(root, "gone"), filepath.Join(task, "43")); err != nil {
		t.Fatal(err)
	}
	// A thread directory that exists but whose stat cannot be read is a gap.
	if err := os.Mkdir(filepath.Join(task, "44"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &collector{proc: root, snap: &model.Snapshot{Processes: []model.Process{{PID: 42, Exe: "/tmp/x", StartTicks: 100}}}}
	c.noteLateThreads()
	if hasCoverage(c, filepath.Join(task, "43", "stat"), "unavailable", "") {
		t.Fatalf("exited thread recorded as a gap: %+v", c.snap.Coverage)
	}
	if len(c.snap.Coverage) != 1 || c.snap.Coverage[0].Source != filepath.Join(task, "44", "stat") {
		t.Fatalf("coverage %+v", c.snap.Coverage)
	}
}
