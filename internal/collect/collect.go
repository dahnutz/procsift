//go:build linux

// Package collect reads a live Linux /proc and /sys tree into a snapshot.
package collect

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/procfs"
)

const maxPIDSpace = 1 << 24

const DefaultSweepMaxProbes = 250000
const DefaultSweepTimeout = 2 * time.Second

// Options selects where to read and which probes to run.
type Options struct {
	ProcRoot       string
	SysRoot        string
	DevShm         string
	HostRoot       string
	PIDMax         int
	Sweep          bool
	ReadMagic      bool
	Progress       io.Writer
	SweepMaxProbes int
	SweepTimeout   time.Duration
	OnlyPID        int
	Deep           bool
	Manifest       string
}

// Collect takes one read-only snapshot. A non-real ProcRoot never calls
// kill(pid, 0), because that probe talks to the running kernel rather than
// to the supplied tree.
func Collect(opts Options) (*model.Snapshot, error) {
	opts = apply(opts)
	if _, err := os.Stat(opts.ProcRoot); err != nil {
		return nil, fmt.Errorf("proc filesystem %s: %w", opts.ProcRoot, err)
	}
	c := &collector{
		proc:           opts.ProcRoot,
		sys:            opts.SysRoot,
		devshm:         opts.DevShm,
		hostRoot:       opts.HostRoot,
		sweep:          opts.Sweep,
		readMagic:      opts.ReadMagic,
		real:           filepath.Clean(opts.ProcRoot) == "/proc",
		progress:       opts.Progress,
		snap:           &model.Snapshot{Started: time.Now()},
		magicLeft:      400,
		sweepMaxProbes: opts.SweepMaxProbes,
		sweepTimeout:   opts.SweepTimeout,
		onlyPID:        opts.OnlyPID,
		deep:           opts.Deep,
		manifest:       opts.Manifest,
	}
	c.snap.Limits = append(c.snap.Limits,
		"This scan reads kernel-exported views under /proc and /sys. It does not walk raw physical RAM.",
		"A rootkit that hooks directory listing, /proc lookup, and kill(pid, 0) can still hide a task.",
		"At most 16 bytes are read from the start of an anonymous executable mapping, and only to recognize an ELF, PE, or script header. Process memory is not dumped.",
		"Command lines stored in this report are redacted when an argument looks like a token, password, or key. Reports can still contain paths and process names.",
		"A deleted running executable is read only to hash at most 4 MiB through /proc/pid/exe. That digest is a prefix unless the whole file fit in the cap. The bytes are not executed.",
		"Package integrity checks bounded live root images and selected on-disk utilities even when idle, at most 32 MiB per image or file. The local dpkg database is a reference, not proof that the database is trustworthy. RPM databases are not read.",
		"maintenance corroborated requires a dpkg transaction after process start and a current file whose MD5 matches the package manifest. A newer mtime alone is not enough.",
	)
	c.readHost()
	c.readScanner()
	if opts.PIDMax > 0 {
		c.pidMax = opts.PIDMax
	} else {
		c.pidMax = readPIDMax(c.proc)
	}
	c.snap.PIDMax = c.pidMax
	if c.pidMax > maxPIDSpace {
		c.snap.Notes = append(c.snap.Notes, fmt.Sprintf("pid_max %d is above the sweep cap %d; probing is capped at that range.", c.pidMax, maxPIDSpace))
		c.pidMax = maxPIDSpace
	}
	if opts.OnlyPID > 0 {
		if err := c.discoverFocused(opts.OnlyPID); err != nil {
			return nil, err
		}
	} else if err := c.discover(); err != nil {
		return nil, err
	}
	c.enrichContext()
	c.loadObjects()
	c.readRawSockets()
	c.noteNamespaces()
	if c.deep {
		c.comparePages()
	}
	c.finishNotes()
	c.snap.Duration = time.Since(c.snap.Started)
	return c.snap, nil
}

func apply(opts Options) Options {
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.SysRoot == "" {
		opts.SysRoot = "/sys"
	}
	if opts.DevShm == "" {
		opts.DevShm = "/dev/shm"
	}
	if opts.HostRoot == "" {
		opts.HostRoot = "/"
	}
	if opts.SweepMaxProbes <= 0 {
		opts.SweepMaxProbes = DefaultSweepMaxProbes
	}
	if opts.SweepTimeout <= 0 {
		opts.SweepTimeout = DefaultSweepTimeout
	}
	return opts
}

type collector struct {
	proc           string
	sys            string
	devshm         string
	hostRoot       string
	sweep          bool
	readMagic      bool
	real           bool
	pidMax         int
	progress       io.Writer
	snap           *model.Snapshot
	magicLeft      int
	sweepMaxProbes int
	sweepTimeout   time.Duration
	onlyPID        int
	deep           bool
	manifest       string
	trusted        map[string]string
}

func (c *collector) logf(format string, args ...any) {
	if c.progress == nil {
		return
	}
	fmt.Fprintf(c.progress, "procsift: "+format+"\n", args...)
}

func (c *collector) readHost() {
	c.snap.Hostname, _ = os.Hostname()
	c.snap.EUID = os.Geteuid()
	c.snap.Kernel = readTrim(filepath.Join(c.proc, "version"))
	c.snap.OSRelease = readTrim(filepath.Join(c.proc, "sys", "kernel", "osrelease"))
	c.snap.BootID = readTrim(filepath.Join(c.proc, "sys", "kernel", "random", "boot_id"))
	if t := readTrim(filepath.Join(c.proc, "sys", "kernel", "tainted")); t != "" {
		if n, err := strconv.ParseUint(strings.TrimSpace(t), 10, 64); err == nil {
			c.snap.Taint = n
			c.snap.TaintFlags = procfs.TaintFlags(n)
		}
	}
}

func readPIDMax(proc string) int {
	n, err := strconv.Atoi(readTrim(filepath.Join(proc, "sys", "kernel", "pid_max")))
	if err != nil || n < 2 {
		return 32768
	}
	return n
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (c *collector) finishNotes() {
	if c.real && c.snap.EUID != 0 {
		c.snap.Notes = append(c.snap.Notes, "Running unprivileged. File descriptors, environments, and executable headers of other users may be unreadable. Re-run as root for a full triage.")
	}
	if !c.sweep || !c.real {
		if c.sweep && !c.real {
			c.snap.Limits = append(c.snap.Limits, "PID probe via kill(pid, 0) runs only against the live /proc mount.")
		} else if !c.sweep {
			c.snap.Limits = append(c.snap.Limits, "PID sweep is off. Tasks missing from the /proc directory listing were not probed with kill(pid, 0).")
		}
	}
	if !c.snap.ModulesOK || !c.snap.SysfsOK {
		c.snap.Limits = append(c.snap.Limits, "Kernel module cross-check was skipped because /proc/modules or /sys/module could not be read.")
	}
	if c.snap.NetIncomplete {
		c.snap.Limits = append(c.snap.Limits, "Socket cross-check was inconclusive because collection was incomplete or changed during confirmation. See Collection coverage; missing ownership is not reported as an orphan.")
	}
	if c.snap.MapsUnreadable > 0 {
		c.snap.Notes = append(c.snap.Notes, fmt.Sprintf("Memory maps were incomplete or unreadable for %d processes (%d permission denied).", c.snap.MapsUnreadable, c.snap.MapsDenied))
	}
	if c.snap.MagicDenied > 0 {
		c.snap.Notes = append(c.snap.Notes, fmt.Sprintf("Executable-header reads were refused for %d processes.", c.snap.MagicDenied))
	}
	c.noteKthreadField()
	c.notePackageSources()
	if !c.deep {
		c.snap.Limits = append(c.snap.Limits, "Executable page bytes are not compared with backing files unless -deep is set. JIT, debuggers, and runtimes can differ when that check is on.")
	}
	if c.snap.ExitedDuringScan > 0 {
		c.snap.Notes = append(c.snap.Notes, fmt.Sprintf("%d processes exited while the snapshot was being read.", c.snap.ExitedDuringScan))
	}
	if c.snap.SweepUsed && !c.snap.ProbeBad {
		accounted := len(c.snap.Ghosts)
		for _, p := range c.snap.Processes {
			accounted += p.TaskCount()
		}
		if c.snap.TasksSeen > accounted+50 {
			c.snap.Notes = append(c.snap.Notes, fmt.Sprintf("kill() sees %d tasks; process records account for %d. The gap can be unreadable thread groups or a visibility mismatch.", c.snap.TasksSeen, accounted))
		}
	}
}
