//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

const testSocketRow = "0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 4242\n"

var testSocket = model.Socket{Proto: "tcp", Local: "127.0.0.1:8080", Remote: "0.0.0.0:0", State: "LISTEN", StateID: 10, UID: 1000, Inode: 4242}

func networkFixture(t *testing.T) *collector {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"net", "42/fd", "self/ns"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		body := "sl local_address rem_address st\n"
		if name == "tcp" {
			body += testSocketRow
		}
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("net:[1]", filepath.Join(root, "self/ns/net")); err != nil {
		t.Fatal(err)
	}
	return &collector{proc: root, snap: &model.Snapshot{Sockets: []model.Socket{testSocket}, SocketOwner: map[uint64]int{}, Processes: []model.Process{{PID: 42, Listed: true, FDComplete: true}}}}
}

func TestSocketConfirmation(t *testing.T) {
	for _, scenario := range []string{"persistent", "new_owner", "closed", "fd_failure", "table_failure", "missing_fd_directory"} {
		t.Run(scenario, func(t *testing.T) {
			c := networkFixture(t)
			fd := filepath.Join(c.proc, "42/fd/3")
			var err error
			switch scenario {
			case "new_owner":
				err = os.Symlink("socket:[4242]", fd)
			case "closed":
				err = os.WriteFile(filepath.Join(c.proc, "net/tcp"), []byte("sl local_address rem_address st\n"), 0600)
			case "fd_failure":
				err = os.WriteFile(fd, nil, 0600)
			case "table_failure":
				err = os.Remove(filepath.Join(c.proc, "net/tcp"))
			case "missing_fd_directory":
				err = os.Remove(filepath.Join(c.proc, "42/fd"))
			}
			if err != nil {
				t.Fatal(err)
			}
			c.confirmNetwork("net:[1]")
			if scenario == "persistent" {
				if c.snap.NetIncomplete || len(c.snap.NetOrphans) != 1 {
					t.Fatalf("snapshot %+v", c.snap)
				}
			} else if len(c.snap.NetOrphans) != 0 {
				t.Fatalf("false orphan for %s: %+v", scenario, c.snap.NetOrphans)
			}
			if scenario == "fd_failure" || scenario == "table_failure" || scenario == "missing_fd_directory" {
				if !c.snap.NetIncomplete || len(c.snap.Coverage) == 0 {
					t.Fatalf("failure not disclosed: %+v", c.snap)
				}
			}
		})
	}
}

func TestOrphanIdentityAndOwnership(t *testing.T) {
	changed := testSocket
	changed.Remote = "10.0.0.1:9999"
	if got := stableOrphans([]model.Socket{testSocket}, []model.Socket{changed}, nil, nil); len(got) != 0 {
		t.Fatal("changed socket matched")
	}
	for _, owners := range []struct{ first, second map[uint64]int }{{map[uint64]int{4242: 42}, nil}, {nil, map[uint64]int{4242: 43}}} {
		if got := stableOrphans([]model.Socket{testSocket}, []model.Socket{testSocket}, owners.first, owners.second); len(got) != 0 {
			t.Fatal("owned socket flagged")
		}
	}
}

func TestOwnersIncludeOtherNamespaces(t *testing.T) {
	c := networkFixture(t)
	c.snap.Processes[0].NetNS = "net:[2]"
	c.snap.Processes[0].SocketInodes = []uint64{4242}
	c.markNet("net:[1]")
	if c.snap.SocketOwner[4242] != 42 {
		t.Fatal("descriptor owner omitted because current namespace differs")
	}
	c.snap.Processes[0].FDComplete = false
	c.markNet("net:[1]")
	if !c.snap.NetIncomplete {
		t.Fatal("incomplete census accepted")
	}
}

func TestNamespaceLabelsUseScannerView(t *testing.T) {
	c := networkFixture(t)
	c.onlyPID = 42
	for _, dir := range []string{"1/ns", "42/ns", "42/net"} {
		if err := os.MkdirAll(filepath.Join(c.proc, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("net:[9]", filepath.Join(c.proc, "1/ns/net")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.proc, "42/ns/net")
	if err := os.Symlink("net:[1]", path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.proc, "42/net/tcp"), []byte("sl local_address rem_address st\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.noteNamespaces()
	if c.snap.Processes[0].NetNSView != "same" {
		t.Fatalf("same view %q", c.snap.Processes[0].NetNSView)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[2]", path); err != nil {
		t.Fatal(err)
	}
	c.noteNamespaces()
	if c.snap.Processes[0].NetNSView != "foreign" {
		t.Fatalf("empty foreign view %q", c.snap.Processes[0].NetNSView)
	}
}

func TestPIDCensusChange(t *testing.T) {
	if samePIDSet(map[int]struct{}{1: {}}, map[int]struct{}{2: {}}) {
		t.Fatal("changed PIDs accepted")
	}
	if !samePIDSet(map[int]struct{}{1: {}}, map[int]struct{}{1: {}}) {
		t.Fatal("stable PIDs rejected")
	}
}
