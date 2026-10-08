package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dahnutz/procsift/internal/model"
)

// Write emits a report as "text" or "json".
func Write(w io.Writer, rep model.Report, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(rep)
	}
	return writeText(w, rep)
}

func writeText(w io.Writer, rep model.Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", rep.Tool, rep.Version)
	fmt.Fprintf(&b, "Copyright (c) 2026 Daniel Hanganu. MIT license.\n")
	fmt.Fprintf(&b, "Fast live Linux incident triage. Kernel-exported objects only.\n\n")
	fmt.Fprintf(&b, "Host result   %s\n", empty(rep.HostResult))
	fmt.Fprintf(&b, "Exit reason   %s\n", empty(rep.HostExitReason))
	fmt.Fprintf(&b, "Host findings high %d  medium %d  low %d  info %d\n", rep.HostCounts.High, rep.HostCounts.Medium, rep.HostCounts.Low, rep.HostCounts.Info)
	fmt.Fprintf(&b, "Scanner self  high %d  medium %d  low %d  info %d\n", rep.ScannerCounts.High, rep.ScannerCounts.Medium, rep.ScannerCounts.Low, rep.ScannerCounts.Info)
	fmt.Fprintf(&b, "All findings  high %d  medium %d  low %d  info %d  (raw total, not the exit count)\n", rep.Counts.High, rep.Counts.Medium, rep.Counts.Low, rep.Counts.Info)

	fmt.Fprintf(&b, "Host          %s\n", empty(rep.Host.Hostname))
	fmt.Fprintf(&b, "Kernel        %s\n", empty(oneLine(rep.Host.Kernel)))
	fmt.Fprintf(&b, "OS release    %s\n", empty(rep.Host.OSRelease))
	if rep.Host.BootID != "" {
		fmt.Fprintf(&b, "Boot ID       %s\n", rep.Host.BootID)
	}
	fmt.Fprintf(&b, "EUID          %d\n", rep.Host.EUID)
	if rep.Host.SweepUsed {
		fmt.Fprintf(&b, "PID space     %d of %d IDs probed, complete=%t, %d tasks answered kill(pid, 0)\n", rep.Host.SweepProbed, nonNeg(rep.Host.PIDMax-1), rep.Host.SweepComplete, rep.Host.TasksSeen)
	} else {
		fmt.Fprintf(&b, "PID space     sweep off (pid_max %d)\n", rep.Host.PIDMax)
	}
	taint := "none"
	if len(rep.Host.TaintFlags) > 0 {
		taint = strings.Join(rep.Host.TaintFlags, ", ")
	}
	fmt.Fprintf(&b, "Taint         %d (%s)\n", rep.Host.Taint, taint)
	if !rep.Time.IsZero() {
		fmt.Fprintf(&b, "Started       %s\n", rep.Time.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "Duration      %s\n", time.Duration(rep.DurationMS)*time.Millisecond)
	writeSignals(&b, rep)

	writeAttention(&b, rep)
	fmt.Fprintf(&b, "\nObjects in memory\n")
	row(&b, "processes", rep.Objects.Processes)
	row(&b, "threads", rep.Objects.Threads)
	if rep.Objects.KernelThreadsKnown {
		row(&b, "kernel threads", rep.Objects.KernelThreads)
	} else {
		fmt.Fprintf(&b, "  %-26s %s\n", "kernel threads", "unknown")
	}
	row(&b, "mapped file regions", rep.Objects.MappedFileRegions)
	row(&b, "anonymous regions", rep.Objects.AnonymousRegions)
	row(&b, "executable anonymous", rep.Objects.ExecutableAnonymous)
	row(&b, "deleted mappings", rep.Objects.DeletedMappings)
	row(&b, "memfd mappings", rep.Objects.MemfdMappings)
	row(&b, "writable+executable", rep.Objects.WritableExecutable)
	fmt.Fprintf(&b, "  %-26s %d (%d bytes)\n", "sysv shared segments", rep.Objects.SysVSegments, rep.Objects.SysVBytes)
	row(&b, "/dev/shm files", rep.Objects.DevShmFiles)
	row(&b, "loaded kernel modules", rep.Objects.KernelModules)
	row(&b, "sockets (tcp/udp)", rep.Objects.Sockets)
	row(&b, "maps unreadable", rep.Objects.MapsUnreadable)

	fmt.Fprintf(&b, "\nFindings\n")
	fmt.Fprintf(&b, "  showing %s and above. Host result is %s.\n", rep.MinSeverity, empty(rep.HostResult))
	fmt.Fprintf(&b, "  high: concealment or fileless execution. medium: investigate. low: context, often benign.\n")
	if len(rep.Findings) == 0 {
		fmt.Fprintf(&b, "\n  No anomalies at this severity.\n")
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "\n[%s] %s", strings.ToUpper(f.Severity), f.Rule)
		if f.PID != 0 {
			fmt.Fprintf(&b, "  pid %d", f.PID)
		}
		if f.Process != "" {
			fmt.Fprintf(&b, "  %s", f.Process)
		}
		if f.Subject != "" && f.PID == 0 {
			fmt.Fprintf(&b, "  %s", f.Subject)
		}
		fmt.Fprintf(&b, "\n  %s\n", f.Summary)
		if f.Origin != "" {
			fmt.Fprintf(&b, "  origin %s\n", f.Origin)
		}
		if f.Detail != "" {
			fmt.Fprintf(&b, "  %s\n", f.Detail)
		}
		for _, ev := range f.Evidence {
			fmt.Fprintf(&b, "  - %s\n", ev)
		}
	}

	if rep.ShowProcesses && len(rep.Processes) > 0 {
		fmt.Fprintf(&b, "\nProcesses\n")
		fmt.Fprintf(&b, "  %-7s %-7s %-7s %-8s %-2s %-16s %s\n", "PID", "PPID", "UID", "RSS_KB", "ST", "NAME", "EXE")
		for _, p := range rep.Processes {
			fmt.Fprintf(&b, "  %-7d %-7d %-7d %-8d %-2s %-16s %s\n", p.PID, p.PPID, p.UID, p.RSSKiB, p.State, trunc(p.Name, 16), trunc(p.Exe, 64))
		}
	}
	if len(rep.FileChecks) > 0 {
		fmt.Fprintf(&b, "\nCritical file checks\n")
		for _, check := range rep.FileChecks {
			fmt.Fprintf(&b, "  %s: %s", check.Path, check.State)
			if check.Package != "" {
				fmt.Fprintf(&b, " (dpkg %s)", check.Package)
			}
			fmt.Fprintln(&b)
		}
	}

	if len(rep.Notes) > 0 {
		fmt.Fprintf(&b, "\nNotes\n")
		for _, n := range rep.Notes {
			fmt.Fprintf(&b, "  - %s\n", n)
		}
	}
	if len(rep.Coverage) > 0 {
		fmt.Fprintf(&b, "\nCollection coverage\n")
		for _, issue := range rep.Coverage {
			fmt.Fprintf(&b, "  - %s: %s (%s)\n", issue.Source, issue.State, issue.Detail)
		}
	}
	if len(rep.Limits) > 0 {
		fmt.Fprintf(&b, "\nLimits\n")
		for _, n := range rep.Limits {
			fmt.Fprintf(&b, "  - %s\n", n)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeSignals(b *strings.Builder, rep model.Report) {
	sig := rep.HostSignals
	if sig.RPM == "" && sig.BPFUnprivileged == "" && len(sig.PreloadPaths) == 0 && len(sig.BPFPins) == 0 && sig.BPFTree == "" {
		return
	}
	fmt.Fprintf(b, "\nHost signals\n")
	if sig.RPM != "" {
		fmt.Fprintf(b, "  rpm %s\n", sig.RPM)
	}
	if sig.BPFUnprivileged != "" || sig.BPFTree != "" {
		fmt.Fprintf(b, "  bpf unprivileged %s, pin tree %s, pins %d\n", empty(sig.BPFUnprivileged), empty(sig.BPFTree), len(sig.BPFPins))
	}
	for _, path := range sig.PreloadPaths {
		fmt.Fprintf(b, "  ld.so.preload %s\n", path)
	}
}

func writeAttention(b *strings.Builder, rep model.Report) {
	scanner := false
	for _, f := range rep.Findings {
		if f.Origin == "scanner_self" {
			scanner = true
			break
		}
	}
	if len(rep.Attention) == 0 && !scanner {
		return
	}
	fmt.Fprintf(b, "\nAttention\n")
	fmt.Fprintf(b, "  First-action order. Scores are fixed weights on findings. This is not a compromised verdict.\n")
	if len(rep.Attention) == 0 {
		fmt.Fprintf(b, "  No other process outranks the raw findings.\n")
	}
	for i, row := range rep.Attention {
		name := row.Process
		if name == "" {
			name = row.Subject
		}
		fmt.Fprintf(b, "  %d. ", i+1)
		if row.PID != 0 {
			fmt.Fprintf(b, "pid %d ", row.PID)
		}
		fmt.Fprintf(b, "%s  score %d  %s\n", name, row.Score, row.Level)
		if len(row.Why) > 0 {
			fmt.Fprintf(b, "     why: %s\n", strings.Join(row.Why, "; "))
		}
		for _, alt := range row.Alternatives {
			fmt.Fprintf(b, "     alternative: %s\n", alt)
		}
		if i == 0 && row.PID != 0 {
			fmt.Fprintf(b, "     next: %s -pid %d\n", rep.Tool, row.PID)
			for _, why := range row.Why {
				if strings.Contains(why, "deleted") {
					fmt.Fprintf(b, "     preserve: %s capture -pid %d -o directory\n", rep.Tool, row.PID)
					break
				}
			}
		}
	}
	if scanner {
		fmt.Fprintf(b, "  Findings marked scanner_self come from this scan's own process. They keep their severity but do not affect exit status unless -fail-on-self is set.\n")
	}
}

func row(b *strings.Builder, label string, n int) {
	fmt.Fprintf(b, "  %-26s %d\n", label, n)
}

func empty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func nonNeg(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
