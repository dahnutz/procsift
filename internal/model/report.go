package model

import (
	"fmt"
	"time"
)

// Report is the operator-facing result of a scan.
type Report struct {
	Tool           string        `json:"tool"`
	Version        string        `json:"version"`
	MinSeverity    string        `json:"min_severity"`
	HostResult     string        `json:"host_result"`
	HostExitReason string        `json:"host_exit_reason"`
	HostSignals    HostSignals   `json:"host_signals"`
	Time           time.Time     `json:"time"`
	DurationMS     int64         `json:"duration_ms"`
	Host           HostInfo      `json:"host"`
	ScannerPID     int           `json:"scanner_pid,omitempty"`
	ScannerTicks   uint64        `json:"scanner_start_ticks,omitempty"`
	Objects        ObjectCounts  `json:"objects"`
	Counts         SevCounts     `json:"counts"`
	HostCounts     SevCounts     `json:"host_counts"`
	ScannerCounts  SevCounts     `json:"scanner_counts"`
	FileChecks     []FileCheck   `json:"file_checks,omitempty"`
	Attention      []Attention   `json:"attention,omitempty"`
	Findings       []Finding     `json:"findings"`
	Processes      []ProcessView `json:"processes,omitempty"`
	Sockets        []SocketView  `json:"sockets,omitempty"`
	Notes          []string      `json:"notes"`
	Limits         []string      `json:"limits"`
	Coverage       []ReadIssue   `json:"coverage"`
	ShowProcesses  bool          `json:"-"`
}

// HostInfo describes the machine the snapshot was taken on.
type HostInfo struct {
	Hostname      string   `json:"hostname"`
	Kernel        string   `json:"kernel"`
	OSRelease     string   `json:"os_release"`
	BootID        string   `json:"boot_id,omitempty"`
	EUID          int      `json:"euid"`
	PIDMax        int      `json:"pid_max"`
	SweepUsed     bool     `json:"pid_sweep"`
	TasksSeen     int      `json:"tasks_seen"`
	SweepProbed   int      `json:"pid_sweep_probed"`
	SweepComplete bool     `json:"pid_sweep_complete"`
	Taint         uint64   `json:"taint"`
	TaintFlags    []string `json:"taint_flags,omitempty"`
}

// ObjectCounts is the inventory of memory-backed objects, including clean ones.
type ObjectCounts struct {
	Processes           int    `json:"processes"`
	Threads             int    `json:"threads"`
	KernelThreads       int    `json:"kernel_threads"`
	KernelThreadsKnown  bool   `json:"kernel_threads_known"`
	MappedFileRegions   int    `json:"mapped_file_regions"`
	AnonymousRegions    int    `json:"anonymous_regions"`
	ExecutableAnonymous int    `json:"executable_anonymous"`
	DeletedMappings     int    `json:"deleted_mappings"`
	MemfdMappings       int    `json:"memfd_mappings"`
	WritableExecutable  int    `json:"writable_executable"`
	SysVSegments        int    `json:"sysv_shm_segments"`
	SysVBytes           uint64 `json:"sysv_shm_bytes"`
	DevShmFiles         int    `json:"dev_shm_files"`
	KernelModules       int    `json:"kernel_modules"`
	Sockets             int    `json:"sockets"`
	MapsUnreadable      int    `json:"maps_unreadable_processes"`
}

// SevCounts tallies findings that are present in the report.
type SevCounts struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// ProcessView is the compact inventory row. It does not include memory maps.
type ProcessView struct {
	PID           int    `json:"pid"`
	PPID          int    `json:"ppid"`
	UID           int    `json:"uid"`
	State         string `json:"state"`
	Name          string `json:"name"`
	RSSKiB        int    `json:"rss_kib"`
	Threads       int    `json:"threads"`
	Exe           string `json:"exe,omitempty"`
	Cmdline       string `json:"cmdline,omitempty"`
	Cwd           string `json:"cwd,omitempty"`
	Listed        bool   `json:"listed"`
	Kthread       bool   `json:"kthread,omitempty"`
	KthreadKnown  bool   `json:"kthread_known,omitempty"`
	StartupStatus string `json:"startup_status,omitempty"`
	StartTicks    uint64 `json:"start_ticks,omitempty"`
	ExeDev        string `json:"exe_dev,omitempty"`
	ExeInode      uint64 `json:"exe_inode,omitempty"`
	ExeHash       string `json:"exe_hash,omitempty"`
	ExeHashScope  string `json:"exe_hash_scope,omitempty"`
}

// SocketView is one socket row kept so two reports can be compared.
type SocketView struct {
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	State  string `json:"state"`
	Inode  uint64 `json:"inode,omitempty"`
	PID    int    `json:"pid,omitempty"`
}

// HostSignals is the bounded host inventory that is not a process finding.
type HostSignals struct {
	PreloadPaths    []string `json:"preload_paths,omitempty"`
	BPFPins         []string `json:"bpf_pins,omitempty"`
	BPFUnprivileged string   `json:"bpf_unprivileged,omitempty"`
	BPFTree         string   `json:"bpf_tree,omitempty"`
	RPM             string   `json:"rpm,omitempty"`
}

// Attention is one row in the first-action list. It is an ordering, not a verdict.
type Attention struct {
	PID          int      `json:"pid,omitempty"`
	Process      string   `json:"process,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	Score        int      `json:"score"`
	Level        string   `json:"level"`
	Why          []string `json:"why"`
	Alternatives []string `json:"alternatives,omitempty"`
}

// Failed reports whether any finding meets the exit threshold.
func Failed(findings []Finding, floor string) bool {
	return FailedWithSelf(findings, floor, true)
}

// FailedWithSelf applies the exit threshold to host findings by default.
// Callers can explicitly include findings caused by this scanner invocation.
func FailedWithSelf(findings []Finding, floor string, includeSelf bool) bool {
	need := SeverityRank(floor)
	if need < 0 {
		return false
	}
	for _, f := range findings {
		if !includeSelf && f.Origin == "scanner_self" {
			continue
		}
		if SeverityRank(f.Severity) >= need {
			return true
		}
	}
	return false
}

// HostExit names the first finding that meets the exit threshold.
// Scanner-origin findings are skipped unless includeSelf is set.
// The result is pass or fail. The reason is a rule, not a verdict.
func HostExit(findings []Finding, floor string, includeSelf bool) (result, reason string) {
	need := SeverityRank(floor)
	if need < 0 {
		return "pass", "no exit threshold"
	}
	for _, f := range findings {
		if !includeSelf && f.Origin == "scanner_self" {
			continue
		}
		if SeverityRank(f.Severity) < need {
			continue
		}
		reason = f.Rule
		if f.Origin == "scanner_self" {
			reason += " (scanner_self)"
		}
		if f.PID != 0 {
			reason = fmt.Sprintf("%s pid %d", reason, f.PID)
		}
		return "fail", reason
	}
	return "pass", "no host finding meets the exit threshold"
}
