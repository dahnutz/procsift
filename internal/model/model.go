// Package model holds the scan snapshot and the findings produced from it.
package model

import (
	"strings"
	"time"
)

// Severity labels are stable report values. Higher ranks fail a scan first
// when the operator sets an exit threshold.
const (
	SevInfo   = "info"
	SevLow    = "low"
	SevMedium = "medium"
	SevHigh   = "high"
)

// SeverityRank orders info < low < medium < high. Unknown labels rank below info.
func SeverityRank(s string) int {
	switch s {
	case SevInfo:
		return 0
	case SevLow:
		return 1
	case SevMedium:
		return 2
	case SevHigh:
		return 3
	default:
		return -1
	}
}

// AtLeast reports whether a finding meets a minimum severity.
func AtLeast(severity, floor string) bool {
	return SeverityRank(severity) >= SeverityRank(floor)
}

// Snapshot is one read-only pass over the local kernel interfaces.
type Snapshot struct {
	Hostname      string
	Kernel        string
	OSRelease     string
	BootID        string
	EUID          int
	PIDMax        int
	SweepUsed     bool
	ProbeBad      bool
	TasksSeen     int
	SweepProbed   int
	SweepComplete bool
	Started       time.Time
	Duration      time.Duration

	Processes  []Process
	Ghosts     []Ghost
	FileChecks []FileCheck

	ModulesOK     bool
	Modules       []Module
	SysfsOK       bool
	SysfsNames    map[string]struct{}
	SysfsLoadable []string
	Taint         uint64
	TaintFlags    []string

	SysV   []SysVShm
	DevShm []DevShmFile

	Sockets           []Socket
	SocketOwner       map[uint64]int
	NetIncomplete     bool
	NetOrphans        []Socket
	Coverage          []ReadIssue
	ProcessIncomplete bool

	MapsDenied       int
	MapsUnreadable   int
	MagicDenied      int
	ExitedDuringScan int

	Notes  []string
	Limits []string

	// Scanner is this process when its start tick could be read.
	// Findings are marked scanner_self only when both PID and start tick match.
	Scanner Scanner

	// ExtraUID0 lists uid 0 account names other than root. Password fields are never copied.
	ExtraUID0 []string

	PreloadPaths     []string
	PreloadTruncated bool
	BPFPins          []string
	BPFUnprivileged  string
	BPFTree          string
	RPMState         string
}

// ReadIssue records an observation that could not be collected completely.
// State is denied, truncated, unavailable, exited, changed, or error.
type ReadIssue struct {
	Source string `json:"source"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// Process is a thread-group leader observed through /proc.
type Process struct {
	PID          int
	TGID         int
	PPID         int
	Name         string
	State        string
	Threads      int
	UID          int
	VmRSSKiB     int
	Kthread      bool
	KthreadKnown bool
	Exe          string
	Cmdline      string
	Cwd          string
	Listed       bool
	MapsOK       bool
	Maps         []Region

	LDPreload string
	LDAudit   string
	LDLibrary string
	TracerPID int

	NetNS      string
	FDComplete bool
	Exited     bool

	SocketInodes   []uint64
	MemfdFDs       []string
	TempDeletedFDs []string

	StartTicks uint64
	Started    time.Time
	User       string
	Cgroup     string
	Service    string

	ExeInfo           *ExeIdentity
	DeletedMaps       []DeletedMap
	Startup           []StartupRef
	StartupIncomplete bool
	Stdin             string
	TTY               uint64
	TTYKnown          bool
	SensitiveFDs      []string
	LateThreads       []string
	UnownedLibs       []string
	MapFiles          string
	MapFilesDetail    string
	NetNSView         string
	PageDiffs         []string
	ExeDev            string
	ExeInode          uint64
	ExeHash           string
	ExeHashScope      string
	StartupStatus     string
	Image             *ImageCheck
	Unit              *UnitLink
}

// Scanner identifies the process that is running the scan.
type Scanner struct {
	PID        int
	StartTicks uint64
	Exe        string
	Known      bool
}

// ImageCheck is a bounded comparison of a still-linked executable with the local package manifest.
// A match describes that database. It does not prove the database is trustworthy.
type ImageCheck struct {
	Path          string
	Package       string
	MD5           string
	Manifest      string
	State         string
	Scope         string
	Bytes         int64
	Size          int64
	IdentityOK    bool
	PackageSource string   // observed source context, never a trust verdict
	SHA256        string   // full running image hash when bounded correlation succeeded
	MatchedFiles  []string // selected mismatching disk paths with the same full SHA-256
}

// FileCheck compares a selected on-disk utility with a local package manifest.
// It is separate from ImageCheck because the file need not be running.
type FileCheck struct {
	Path     string `json:"path"`
	Package  string `json:"package,omitempty"`
	State    string `json:"state"`
	Source   string `json:"source,omitempty"`
	MD5      string `json:"md5,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Manifest string `json:"manifest,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
}

// UnitLink separates cgroup membership, unit text, and the fact that the journal was not read.
type UnitLink struct {
	Service   string
	UnitFile  string
	ExecStart []string
	TimerFile string
	TimerLine string
	Journal   string
}

// ExeIdentity is a bounded measurement of one deleted running image.
// It is tied to a PID and start tick so a reused PID is not mixed in.
type ExeIdentity struct {
	BootID       string
	Dev          string
	Inode        uint64
	NLink        uint64
	Size         int64
	SHA256       string
	HashState    string
	HashScope    string
	HashBytes    int64
	Relation     string
	CurrentDev   string
	CurrentInode uint64
	Label        string
	Package      string
	IdentityOK   bool
	Notes        []string
}

// DeletedMap is one deleted mapping compared with the path on disk.
type DeletedMap struct {
	Path         string
	RunningDev   string
	RunningInode uint64
	Relation     string
	CurrentDev   string
	CurrentInode uint64
	Label        string
	Package      string
}

// StartupRef is a separate observation that a startup file mentions a path or name.
// Match is exact-path or name. Neither match means the process was launched from that file.
type StartupRef struct {
	Kind  string
	File  string
	Match string
	Line  string
}

// Kernel reports a kernel thread only when the Kthread field was present and true.
// A missing field is unknown, not a kernel thread and not proof of a userspace task.
func (p Process) Kernel() bool { return p.KthreadKnown && p.Kthread }

// Zombie reports a process whose status state begins with Z.
func (p Process) Zombie() bool {
	s := strings.TrimSpace(p.State)
	return strings.HasPrefix(s, "Z")
}

// TaskCount is the thread-group size, at least one.
func (p Process) TaskCount() int {
	if p.Threads > 0 {
		return p.Threads
	}
	return 1
}

// Region is one line of /proc/pid/maps. Magic is set only for a short header
// read of an anonymous executable mapping.
type Region struct {
	Start  uint64
	End    uint64
	Perms  string
	Offset uint64
	Dev    string
	Inode  uint64
	Path   string
	Magic  string
}

// Size is the mapped length in bytes.
func (r Region) Size() uint64 {
	if r.End > r.Start {
		return r.End - r.Start
	}
	return 0
}

// Ghost is a task id that answers a pid probe but has no /proc directory.
type Ghost struct {
	PID int
}

// Module is one row of /proc/modules.
type Module struct {
	Name    string
	Size    uint64
	Refcnt  int
	State   string
	Address string
	Taints  string
}

// SysVShm is one System V shared-memory segment.
type SysVShm struct {
	Key    int64
	ID     int
	Perms  uint32
	Size   uint64
	CPID   int
	LPID   int
	Nattch int
}

// DevShmFile is a regular file sitting in /dev/shm.
type DevShmFile struct {
	Name       string
	Size       int64
	Executable bool
	Magic      string
}

// Socket is one row from the kernel's tcp or udp tables.
type Socket struct {
	Proto   string
	Local   string
	Remote  string
	State   string
	StateID int
	UID     int
	Inode   uint64
}

// Finding is one triage result. Rule names are stable identifiers.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
	Category string   `json:"category"`
	PID      int      `json:"pid,omitempty"`
	Process  string   `json:"process,omitempty"`
	Subject  string   `json:"subject,omitempty"`
	Summary  string   `json:"summary"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
	Origin   string   `json:"origin,omitempty"`
}
