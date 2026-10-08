//go:build linux

package collect

import (
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/dahnutz/procsift/internal/model"
)

// Only run the extra census if the initial observation has an unmatched
// socket. Socket tables bracket this fresh census, reducing creation/closure
// races. Every descriptor lookup must succeed, and the PID set must stay stable.
func (c *collector) confirmNetwork(refNS string) {
	if len(stableOrphans(c.snap.Sockets, c.snap.Sockets, c.snap.SocketOwner, nil)) == 0 {
		return
	}
	before, err := listPIDs(c.proc)
	if err != nil {
		c.issue(c.proc, err)
		c.snap.NetIncomplete = true
		return
	}
	owners := map[uint64]int{}
	ids := union(before, nil)
	for _, p := range c.snap.Processes {
		if !p.Listed && !p.Exited {
			ids[p.PID] = struct{}{}
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for _, pid := range sortedPIDs(ids) {
		if time.Now().After(deadline) {
			c.changed(c.proc, "socket confirmation reached its 2-second collection budget")
			c.snap.NetIncomplete = true
			return
		}
		p := model.Process{PID: pid}
		c.readFDs(&p, filepath.Join(c.proc, strconv.Itoa(pid)))
		if !p.FDComplete {
			c.snap.NetIncomplete = true
			if p.Exited {
				c.changed(c.proc, "a process exited during socket confirmation")
			}
			return
		}
		for _, inode := range p.SocketInodes {
			owners[inode] = pid
		}
	}
	after, err := listPIDs(c.proc)
	if err != nil {
		c.issue(c.proc, err)
		c.snap.NetIncomplete = true
		return
	}
	if !samePIDSet(before, after) || readLink(filepath.Join(c.proc, "self", "ns", "net")) != refNS {
		c.changed(c.proc, "PID census or scanner network namespace changed during socket confirmation")
		c.snap.NetIncomplete = true
		return
	}
	sockets, complete := c.readSockets()
	if !complete || time.Now().After(deadline) {
		c.snap.NetIncomplete = true
		if complete {
			c.changed(c.proc, "socket confirmation reached its 2-second collection budget")
		}
		return
	}
	c.snap.NetOrphans = stableOrphans(c.snap.Sockets, sockets, c.snap.SocketOwner, owners)
	c.snap.Limits = append(c.snap.Limits, "Socket attribution compares two observations of visible processes. Kernel-held sockets, namespace visibility, and races can still explain an unattributed socket; this does not establish concealment.")
}

func stableOrphans(before, after []model.Socket, firstOwners, secondOwners map[uint64]int) []model.Socket {
	stable := make(map[model.Socket]bool, len(after))
	for _, socket := range after {
		stable[socket] = true
	}
	var out []model.Socket
	for _, socket := range before {
		if socket.Inode == 0 || socket.StateID == 6 || socket.StateID == 7 || !stable[socket] {
			continue
		}
		if _, found := firstOwners[socket.Inode]; found {
			continue
		}
		if _, found := secondOwners[socket.Inode]; found {
			continue
		}
		out = append(out, socket)
	}
	return out
}

func samePIDSet(a, b map[int]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for pid := range a {
		if _, ok := b[pid]; !ok {
			return false
		}
	}
	return true
}

func sortedPIDs(ids map[int]struct{}) []int {
	out := mapKeys(ids)
	sort.Ints(out)
	return out
}
