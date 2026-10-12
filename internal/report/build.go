package report

import (
	"sort"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

// Options controls how a snapshot becomes a report.
type Options struct {
	Version          string
	MinSeverity      string
	ScanOptions      *model.ScanOptions
	FailOn           string
	FailOnSelf       bool
	IncludeProcesses bool
	Attention        []model.Attention
}

// Build assembles the operator-facing report from a snapshot and findings.
func Build(snap *model.Snapshot, findings []model.Finding, opt Options) model.Report {
	if opt.Version == "" {
		opt.Version = "0.5.2"
	}
	if opt.MinSeverity == "" {
		opt.MinSeverity = model.SevLow
	}
	if opt.FailOn == "" {
		opt.FailOn = model.SevMedium
	}
	rep := model.Report{
		Tool:          "procsift",
		Version:       opt.Version,
		Attention:     append([]model.Attention(nil), opt.Attention...),
		Findings:      findings,
		Notes:         append([]string(nil), snap.Notes...),
		Limits:        append([]string(nil), snap.Limits...),
		Coverage:      append([]model.ReadIssue(nil), snap.Coverage...),
		FileChecks:    append([]model.FileCheck(nil), snap.FileChecks...),
		MinSeverity:   opt.MinSeverity,
		ScanOptions:   opt.ScanOptions,
		ShowProcesses: opt.IncludeProcesses,
	}
	if snap != nil {
		if snap.Scanner.Known {
			rep.ScannerPID = snap.Scanner.PID
			rep.ScannerTicks = snap.Scanner.StartTicks
		}
		rep.Time = snap.Started.UTC()
		rep.DurationMS = snap.Duration.Milliseconds()
		rep.Host = model.HostInfo{
			Hostname:      snap.Hostname,
			Kernel:        snap.Kernel,
			OSRelease:     snap.OSRelease,
			BootID:        snap.BootID,
			EUID:          snap.EUID,
			PIDMax:        snap.PIDMax,
			SweepUsed:     snap.SweepUsed,
			TasksSeen:     snap.TasksSeen,
			SweepProbed:   snap.SweepProbed,
			SweepComplete: snap.SweepComplete,
			Taint:         snap.Taint,
			TaintFlags:    append([]string(nil), snap.TaintFlags...),
		}
		rep.Objects = countObjects(snap)
		rep.Processes = processViews(snap)
		rep.Sockets = socketViews(snap)
		rep.HostSignals = model.HostSignals{
			PreloadPaths:    append([]string(nil), snap.PreloadPaths...),
			BPFPins:         append([]string(nil), snap.BPFPins...),
			BPFUnprivileged: snap.BPFUnprivileged,
			BPFTree:         snap.BPFTree,
			RPM:             snap.RPMState,
		}
	}
	for _, f := range findings {
		counts := &rep.HostCounts
		if f.Origin == "scanner_self" {
			counts = &rep.ScannerCounts
		}
		switch f.Severity {
		case model.SevHigh:
			rep.Counts.High++
			counts.High++
		case model.SevMedium:
			rep.Counts.Medium++
			counts.Medium++
		case model.SevLow:
			rep.Counts.Low++
			counts.Low++
		case model.SevInfo:
			rep.Counts.Info++
			counts.Info++
		}
	}
	rep.HostResult, rep.HostExitReason = model.HostExit(findings, opt.FailOn, opt.FailOnSelf)
	return rep
}

func countObjects(s *model.Snapshot) model.ObjectCounts {
	var o model.ObjectCounts
	o.Processes = len(s.Processes)
	o.MapsUnreadable = s.MapsUnreadable
	o.KernelModules = len(s.Modules)
	o.SysVSegments = len(s.SysV)
	o.DevShmFiles = len(s.DevShm)
	o.Sockets = len(s.Sockets)
	for _, seg := range s.SysV {
		o.SysVBytes += seg.Size
	}
	fieldSeen := false
	for _, p := range s.Processes {
		if p.KthreadKnown {
			fieldSeen = true
			if p.Kthread {
				o.KernelThreads++
			}
		}
		o.Threads += p.TaskCount()
		if !p.MapsOK {
			continue
		}
		for _, r := range p.Maps {
			path := r.Path
			if strings.HasSuffix(path, " (deleted)") {
				o.DeletedMappings++
			}
			trimmed := strings.TrimSuffix(path, " (deleted)")
			if strings.Contains(trimmed, "memfd:") {
				o.MemfdMappings++
			}
			anon := path == ""
			if anon {
				o.AnonymousRegions++
			} else if !strings.HasPrefix(path, "[") {
				o.MappedFileRegions++
			}
			exec := len(r.Perms) >= 3 && r.Perms[2] == 'x'
			write := len(r.Perms) >= 2 && r.Perms[1] == 'w'
			if exec && anon {
				o.ExecutableAnonymous++
			}
			if exec && write && !specialName(path) {
				o.WritableExecutable++
			}
		}
	}
	o.KernelThreadsKnown = fieldSeen
	return o
}

func specialName(path string) bool {
	switch path {
	case "[vdso]", "[vvar]", "[vsyscall]", "[uprobes]", "[sigpage]", "[vectors]", "[vvar_vclock]":
		return true
	default:
		return false
	}
}

func processViews(s *model.Snapshot) []model.ProcessView {
	out := make([]model.ProcessView, 0, len(s.Processes))
	for _, p := range s.Processes {
		state := "?"
		if t := strings.TrimSpace(p.State); t != "" {
			state = t[:1]
		}
		out = append(out, model.ProcessView{
			PID:           p.PID,
			PPID:          p.PPID,
			UID:           p.UID,
			State:         state,
			Name:          p.Name,
			RSSKiB:        p.VmRSSKiB,
			Threads:       p.Threads,
			Exe:           p.Exe,
			Cmdline:       p.Cmdline,
			Cwd:           p.Cwd,
			Listed:        p.Listed,
			Kthread:       p.KthreadKnown && p.Kthread,
			KthreadKnown:  p.KthreadKnown,
			StartupStatus: p.StartupStatus,
			StartTicks:    p.StartTicks,
			ExeDev:        p.ExeDev,
			ExeInode:      p.ExeInode,
			ExeHash:       p.ExeHash,
			ExeHashScope:  p.ExeHashScope,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

func socketViews(s *model.Snapshot) []model.SocketView {
	out := make([]model.SocketView, 0, len(s.Sockets))
	for _, sock := range s.Sockets {
		if len(out) >= 2000 {
			break
		}
		out = append(out, model.SocketView{
			Proto:  sock.Proto,
			Local:  sock.Local,
			Remote: sock.Remote,
			State:  sock.State,
			Inode:  sock.Inode,
			PID:    s.SocketOwner[sock.Inode],
		})
	}
	return out
}
