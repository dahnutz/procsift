//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"encoding/json"

	"github.com/dahnutz/procsift/internal/analyze"
	"github.com/dahnutz/procsift/internal/capture"
	"github.com/dahnutz/procsift/internal/collect"
	"github.com/dahnutz/procsift/internal/compare"
	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/report"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return runScan(nil)
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "capture":
		return runCapture(args[1:])
	case "diff":
		return runDiff(args[1:])
	case "version", "-version", "--version":
		fmt.Printf("procsift %s\n", version)
		fmt.Printf("Copyright (c) 2026 Daniel Hanganu\n")
		fmt.Printf("Licensed under the MIT license. Use, share, and modify it freely.\n")
		fmt.Printf("Keep this copyright notice with every copy.\n")
		return 0
	case "help", "-h", "--help":
		usage(os.Stdout)
		return 0
	default:
		if len(args[0]) > 0 && args[0][0] == '-' {
			return runScan(args)
		}
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

func runScan(args []string) int {
	opt, code, err := parseScan(args)
	if err != nil {
		if code == 0 {
			return 0
		}
		fmt.Fprintf(os.Stderr, "procsift: %s\n", err)
		return code
	}
	var progress io.Writer
	if !opt.quiet {
		progress = os.Stderr
	}
	snap, err := collect.Collect(collect.Options{
		PIDMax:         opt.pidMax,
		Sweep:          opt.sweep && !opt.noSweep,
		SweepMaxProbes: opt.sweepMaxProbes,
		SweepTimeout:   opt.sweepTimeout,
		ReadMagic:      !opt.noMagic,
		Progress:       progress,
		OnlyPID:        opt.onlyPID,
		Deep:           opt.deep,
		Manifest:       opt.manifest,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "procsift: %s\n", err)
		return 2
	}
	findings := analyze.Analyze(snap)
	shown := filter(findings, opt.minSeverity)
	rep := report.Build(snap, shown, report.Options{
		Version:          version,
		MinSeverity:      opt.minSeverity,
		FailOn:           opt.failOn,
		FailOnSelf:       opt.failOnSelf,
		IncludeProcesses: opt.all,
		Attention:        analyze.Rank(snap, findings),
	})
	if opt.output != "" {
		err = writeReportFile(opt.output, rep, opt.format)
	} else {
		err = report.Write(os.Stdout, rep, opt.format)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "procsift: write report: %s\n", err)
		return 2
	}
	if opt.output != "" {
		fmt.Fprintf(os.Stderr, "procsift: wrote %s (host %s: %s; total high=%d)\n", opt.output, rep.HostResult, rep.HostExitReason, rep.Counts.High)
	}
	if model.FailedWithSelf(shown, opt.failOn, opt.failOnSelf) {
		return 1
	}
	return 0
}

func runCapture(args []string) int {
	opt, code, err := parseCapture(args)
	if err != nil {
		if code == 0 {
			return 0
		}
		fmt.Fprintf(os.Stderr, "procsift: %s\n", err)
		return code
	}
	err = capture.Run(capture.Options{
		PID:      opt.pid,
		OutDir:   opt.output,
		Version:  version,
		MaxBytes: opt.maxBytes,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "procsift: %s\n", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "procsift: wrote capture bundle %s\n", opt.output)
	return 0
}

func runDiff(args []string) int {
	opt, code, err := parseDiff(args)
	if err != nil {
		if code == 0 {
			return 0
		}
		fmt.Fprintf(os.Stderr, "procsift: %s\n", err)
		return code
	}
	older, err := readReport(opt.old)
	if err != nil {
		fmt.Fprintf(os.Stderr, "procsift: %s\n", err)
		return 2
	}
	newer, err := readReport(opt.new)
	if err != nil {
		fmt.Fprintf(os.Stderr, "procsift: %s\n", err)
		return 2
	}
	result := compare.Diff(older, newer)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "procsift: %s\n", err)
		return 2
	}
	if result.ScopeIssue != "" {
		return 2
	}
	if result.HostEvidence > 0 {
		return 1
	}
	return 0
}

func readReport(path string) (model.Report, error) {
	const maxReportBytes = 64 << 20
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return model.Report{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return model.Report{}, err
	}
	if !info.Mode().IsRegular() {
		return model.Report{}, fmt.Errorf("report %s is not a regular file", path)
	}
	if info.Size() > maxReportBytes {
		return model.Report{}, fmt.Errorf("report %s exceeds the 64 MiB input limit", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxReportBytes+1))
	if err != nil {
		return model.Report{}, err
	}
	if len(b) > maxReportBytes {
		return model.Report{}, fmt.Errorf("report %s exceeds the 64 MiB input limit", path)
	}
	var rep model.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return model.Report{}, err
	}
	if (rep.Tool != "procsift" && rep.Tool != "ramtriage") || rep.Version == "" {
		return model.Report{}, fmt.Errorf("report %s is not a ProcSift or ramtriage JSON report", path)
	}
	return rep, nil
}

func filter(in []model.Finding, floor string) []model.Finding {
	out := make([]model.Finding, 0, len(in))
	for _, f := range in {
		if model.AtLeast(f.Severity, floor) {
			out = append(out, f)
		}
	}
	return out
}
