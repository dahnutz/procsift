//go:build linux

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dahnutz/procsift/internal/collect"
	"github.com/dahnutz/procsift/internal/model"
)

type scanOpts struct {
	format         string
	output         string
	minSeverity    string
	failOn         string
	failOnSelf     bool
	all            bool
	pidMax         int
	noSweep        bool
	sweep          bool
	sweepMaxProbes int
	sweepTimeout   time.Duration
	noMagic        bool
	quiet          bool
	json           bool
	onlyPID        int
	deep           bool
	manifest       string
}

func parseScan(args []string) (scanOpts, int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var opt scanOpts
	fs.StringVar(&opt.format, "format", "text", "report format: text or json")
	fs.StringVar(&opt.output, "o", "", "create a new report file (mode 0600); existing paths are refused")
	fs.StringVar(&opt.minSeverity, "min-severity", "low", "lowest severity to include: info, low, medium, high")
	fs.StringVar(&opt.failOn, "fail-on", "medium", "exit 1 when a host finding is at or above this severity")
	fs.BoolVar(&opt.failOnSelf, "fail-on-self", false, "include scanner-origin findings in the exit threshold")
	fs.BoolVar(&opt.all, "all", false, "include every process in the report")
	fs.IntVar(&opt.pidMax, "pid-max", 0, "override pid_max for the task probe (0 uses the kernel value)")
	fs.BoolVar(&opt.sweep, "sweep", false, "probe pid space with kill(pid, 0) within explicit budgets")
	fs.IntVar(&opt.sweepMaxProbes, "sweep-max-probes", collect.DefaultSweepMaxProbes, "maximum number of pid probes")
	fs.DurationVar(&opt.sweepTimeout, "sweep-timeout", collect.DefaultSweepTimeout, "maximum time for pid probing")
	fs.BoolVar(&opt.noSweep, "no-sweep", false, "do not probe pid space with kill(pid, 0)")
	fs.BoolVar(&opt.noMagic, "no-magic", false, "do not read executable-mapping headers")
	fs.BoolVar(&opt.quiet, "q", false, "suppress progress on stderr")
	fs.BoolVar(&opt.json, "json", false, "shorthand for -format json")
	fs.IntVar(&opt.onlyPID, "pid", 0, "narrow the process census to one pid and its parents; selected host checks still run")
	fs.BoolVar(&opt.deep, "deep", false, "compare the first 16 bytes of up to four executable mappings per selected process")
	fs.StringVar(&opt.manifest, "manifest", "", "local md5sums reference for the paths it names; authenticity is not checked")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			usage(os.Stdout)
			return opt, 0, err
		}
		return opt, 2, err
	}
	if fs.NArg() != 0 {
		return opt, 2, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if opt.json {
		opt.format = "json"
	}
	opt.format = strings.ToLower(opt.format)
	if opt.format != "text" && opt.format != "json" {
		return opt, 2, fmt.Errorf("unknown format %q", opt.format)
	}
	if model.SeverityRank(opt.minSeverity) < 0 {
		return opt, 2, fmt.Errorf("unknown severity %q", opt.minSeverity)
	}
	if model.SeverityRank(opt.failOn) < 0 {
		return opt, 2, fmt.Errorf("unknown severity %q", opt.failOn)
	}
	if opt.onlyPID < 0 {
		return opt, 2, fmt.Errorf("pid must be zero or positive")
	}
	if opt.pidMax < 0 || opt.sweepMaxProbes <= 0 || opt.sweepTimeout <= 0 {
		return opt, 2, fmt.Errorf("pid-max must be non-negative; sweep-max-probes and sweep-timeout must be positive")
	}
	return opt, 0, nil
}

type captureOpts struct {
	pid      int
	output   string
	maxBytes int64
}

func parseCapture(args []string) (captureOpts, int, error) {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var opt captureOpts
	fs.IntVar(&opt.pid, "pid", 0, "process to preserve")
	fs.StringVar(&opt.output, "o", "", "new directory for the private bundle")
	fs.Int64Var(&opt.maxBytes, "max-bytes", 64<<20, "maximum image bytes to copy")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			usage(os.Stdout)
			return opt, 0, err
		}
		return opt, 2, err
	}
	if fs.NArg() != 0 {
		return opt, 2, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if opt.pid <= 0 {
		return opt, 2, fmt.Errorf("capture requires -pid")
	}
	if opt.output == "" {
		return opt, 2, fmt.Errorf("capture requires -o")
	}
	if opt.maxBytes <= 0 {
		return opt, 2, fmt.Errorf("max-bytes must be positive")
	}
	return opt, 0, nil
}

type diffOpts struct {
	old string
	new string
}

func parseDiff(args []string) (diffOpts, int, error) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var opt diffOpts
	fs.StringVar(&opt.old, "old", "", "earlier JSON report")
	fs.StringVar(&opt.new, "new", "", "later JSON report")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			usage(os.Stdout)
			return opt, 0, err
		}
		return opt, 2, err
	}
	if fs.NArg() != 0 {
		return opt, 2, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if opt.old == "" || opt.new == "" {
		return opt, 2, fmt.Errorf("diff requires -old and -new")
	}
	return opt, 0, nil
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `procsift %s — fast live Linux incident triage

Copyright (c) 2026 Daniel Hanganu. MIT license.

Usage:
  procsift [scan] [flags]
  procsift capture -pid N -o directory
  procsift diff -old earlier.json -new later.json
  procsift version

The scan is read-only. It inventories processes, mappings, shared memory,
kernel modules, and sockets, then flags hidden tasks and fileless objects.

Flags:
  -format text|json     report format (default text)
  -json                 same as -format json
  -o path               create a new file mode 0600; refuse existing paths
  -min-severity level   lowest severity to print (default low)
  -fail-on level        exit 1 at this severity for host findings (default medium)
  -fail-on-self         include scanner-origin findings in the exit decision
  -all                  include the full process list
  -pid-max N            override the pid space probe
  -sweep                opt in to the bounded kill(pid, 0) probe
  -sweep-max-probes N    maximum IDs to probe (default 250000)
  -sweep-timeout time    probing time budget (default 2s)
  -no-sweep             disable probing, even if -sweep was supplied
  -no-magic             do not read 16-byte executable headers
  -pid N                narrow process census to one PID and parents; host checks remain
  -deep                 compare only the first 16 bytes of selected executable mappings
  -manifest path        local md5sums reference; not fetched over the network
  -q                    quiet progress

diff flags:
  -old report.json      earlier JSON report
  -new report.json      later JSON report

capture flags:
  -pid N                process whose open executable is copied
  -o directory          new private directory; existing paths are refused
  -max-bytes N          cap on the copied image (default 64 MiB)

The capture bundle records whether the image hash is a full read or a prefix.
It does not execute the copy or contact recorded endpoints.

Exit status:
  0  no host finding meets -fail-on
  1  a host finding meets -fail-on, or a scanner finding does when -fail-on-self is set
  2  the scan could not run

diff exits 1 for new medium or high host findings or a changed image. One-snapshot
processes and sockets are observations. Different hosts, boots, or scan scopes return 2.

Run as root to read other users' file descriptors and executable headers.
`, version)
}
