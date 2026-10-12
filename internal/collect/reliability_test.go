//go:build linux

package collect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dahnutz/procsift/internal/model"
)

func TestReadLimitBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	for _, tc := range []struct {
		body      string
		truncated bool
	}{{"1234", false}, {"12345", true}} {
		if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
			t.Fatal(err)
		}
		b, err := readLimited(path, 4)
		if string(b) != "1234" || errors.Is(err, errTruncated) != tc.truncated {
			t.Fatalf("data=%q err=%v", b, err)
		}
	}
}

func TestCoverageErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&os.PathError{Op: "open", Path: "fixture", Err: syscall.EACCES}, "denied"},
		{os.ErrNotExist, "unavailable"}, {errTruncated, "truncated"}, {syscall.EIO, "error"},
	} {
		if got := readState(tc.err); got != tc.want {
			t.Fatalf("%v: got %s want %s", tc.err, got, tc.want)
		}
	}
}

func TestStatusFailureDoesNotBecomeExit(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "42")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "status"), []byte("invalid status"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &collector{proc: root, snap: &model.Snapshot{}}
	if err := c.discover(); err != nil {
		t.Fatal(err)
	}
	if !c.snap.ProcessIncomplete || c.snap.ExitedDuringScan != 0 || len(c.snap.Coverage) != 1 {
		t.Fatalf("snapshot %+v", c.snap)
	}
	if processGone(base, os.ErrNotExist) {
		t.Fatal("missing file within existing process is not an exit")
	}
	if err := os.RemoveAll(base); err != nil {
		t.Fatal(err)
	}
	if !processGone(base, os.ErrNotExist) {
		t.Fatal("missing process directory should count as an exit")
	}
	if processGone(base, os.ErrPermission) {
		t.Fatal("denial is not an exit")
	}
}

func TestMapCoverage(t *testing.T) {
	for _, state := range []string{"unavailable", "truncated"} {
		t.Run(state, func(t *testing.T) {
			base := t.TempDir()
			if state == "truncated" {
				f, err := os.Create(filepath.Join(base, "maps"))
				if err != nil {
					t.Fatal(err)
				}
				if err = f.Truncate((8 << 20) + 1); err != nil {
					t.Fatal(err)
				}
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			c := &collector{snap: &model.Snapshot{}}
			p := model.Process{PID: 42}
			c.readMaps(&p, base)
			wantOK := state == "truncated"
			if p.MapsOK != wantOK || c.snap.MapsUnreadable != 1 || c.snap.MapsDenied != 0 || len(c.snap.Coverage) != 1 || c.snap.Coverage[0].State != state {
				t.Fatalf("p=%+v snap=%+v", p, c.snap)
			}
		})
	}
}

func TestTruncatedMapsKeepCompleteRegions(t *testing.T) {
	base := t.TempDir()
	line := "00400000-00401000 r-xp 00000000 00:00 1 /tmp/payload (deleted)\n"
	if err := os.WriteFile(filepath.Join(base, "maps"), []byte(line+strings.Repeat(" ", 8<<20)), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &collector{snap: &model.Snapshot{}}
	p := model.Process{PID: 42}
	c.readMaps(&p, base)
	if !p.MapsOK || len(p.Maps) != 1 || p.Maps[0].Path != "/tmp/payload (deleted)" || len(c.snap.Coverage) != 1 || c.snap.Coverage[0].State != "truncated" {
		t.Fatalf("maps=%+v coverage=%+v", p.Maps, c.snap.Coverage)
	}
}

func TestTruncatedEnvironmentKeepsLoaderVariable(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "42")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	status := "Name:\ttest\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\n"
	if err := os.WriteFile(filepath.Join(base, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	env := "LD_PRELOAD=/tmp/libx.so\x00" + strings.Repeat("A", 1<<20)
	if err := os.WriteFile(filepath.Join(base, "environ"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &collector{proc: root, snap: &model.Snapshot{}}
	p, err := c.readProcess(42)
	if err != nil {
		t.Fatal(err)
	}
	if p.LDPreload != "/tmp/libx.so" {
		t.Fatalf("preload %q", p.LDPreload)
	}
	found := false
	for _, issue := range c.snap.Coverage {
		if issue.Source == filepath.Join(base, "environ") && issue.State == "truncated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("coverage %+v", c.snap.Coverage)
	}
}

func TestDevShmOpenRejectsFIFOAndSymlink(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "swapped")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		info, _, err := inspectDevShm(fifo)
		if info != nil || err == nil {
			done <- errors.New("FIFO was accepted as regular")
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO open blocked")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	if info, _, err := inspectDevShm(link); info != nil || err == nil {
		t.Fatalf("symlink accepted: info=%v err=%v", info, err)
	}
}

func TestFailedFDLinkInvalidatesCensus(t *testing.T) {
	base := t.TempDir()
	fd := filepath.Join(base, "fd")
	if err := os.Mkdir(fd, 0700); err != nil {
		t.Fatal(err)
	}
	// A regular file simulates a failed descriptor readlink without depending on UID.
	if err := os.WriteFile(filepath.Join(fd, "3"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	c := &collector{snap: &model.Snapshot{}}
	p := model.Process{PID: 42}
	c.readFDs(&p, base)
	if p.FDComplete || len(c.snap.Coverage) != 1 {
		t.Fatalf("p=%+v coverage=%+v", p, c.snap.Coverage)
	}
}

func TestSweepBudgets(t *testing.T) {
	calls := 0
	result := probeTasksContext(context.Background(), 100, 4, func(pid int) bool { calls++; return pid == 2 })
	if calls != 4 || result.Probed != 4 || result.Complete || len(result.Alive) != 1 || result.Alive[0] != 2 || result.StopReason == "" {
		t.Fatalf("calls=%d result=%+v", calls, result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	result = probeTasksContext(ctx, 100, 99, func(pid int) bool {
		calls++
		if calls == 3 {
			cancel()
		}
		return true
	})
	if result.Complete || calls != 3 || !strings.Contains(result.StopReason, "canceled") {
		t.Fatalf("result=%+v", result)
	}
	ctx, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	result = probeTasksContext(ctx, 100, 99, func(int) bool { t.Fatal("expired budget invoked probe"); return false })
	if result.Probed != 0 || result.Complete {
		t.Fatalf("result=%+v", result)
	}
	result = probeTasksContext(context.Background(), 5, 4, func(int) bool { return false })
	if !result.Complete || result.Probed != 4 {
		t.Fatalf("result=%+v", result)
	}
}
