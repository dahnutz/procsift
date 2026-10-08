//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func TestReportFileIsPrivateAndValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := writeReportFile(path, model.Report{Tool: "procsift"}, "json"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions %o", info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report model.Report
	if err = json.Unmarshal(b, &report); err != nil || report.Tool != "procsift" {
		t.Fatalf("report %s err %v", b, err)
	}
}

func TestExistingReportDestinationsAreRefused(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "dangling", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			out := filepath.Join(dir, "output")
			original := []byte("must remain unchanged")
			if err := os.WriteFile(target, original, 0644); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "regular":
				out = target
			case "symlink":
				err = os.Symlink(target, out)
			case "dangling":
				err = os.Symlink(filepath.Join(dir, "absent"), out)
			case "hardlink":
				err = os.Link(target, out)
			case "fifo":
				err = syscall.Mkfifo(out, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := writeReportFile(out, model.Report{}, "json"); !errors.Is(err, os.ErrExist) {
				t.Fatalf("expected exists error, got %v", err)
			}
			b, err := os.ReadFile(target)
			if err != nil || string(b) != string(original) {
				t.Fatalf("target changed: %s err=%v", b, err)
			}
			info, err := os.Stat(target)
			if err != nil || info.Mode().Perm() != 0644 {
				t.Fatalf("target mode changed or stat failed: %v", err)
			}
			if kind == "dangling" {
				if _, err := os.Stat(filepath.Join(dir, "absent")); !os.IsNotExist(err) {
					t.Fatal("dangling target created")
				}
			}
		})
	}
}

func TestSweepFlags(t *testing.T) {
	opt, _, err := parseScan(nil)
	if err != nil || opt.sweep || opt.sweepMaxProbes <= 0 || opt.sweepTimeout <= 0 {
		t.Fatalf("defaults %+v err=%v", opt, err)
	}
	for _, args := range [][]string{{"-sweep-max-probes", "0"}, {"-sweep-timeout", "0s"}, {"-pid-max", "-1"}} {
		if _, code, err := parseScan(args); err == nil || code != 2 {
			t.Fatalf("invalid args %v accepted", args)
		}
	}
	opt, _, err = parseScan([]string{"-sweep", "-no-sweep"})
	if err != nil || (opt.sweep && !opt.noSweep) {
		t.Fatal("no-sweep should disable explicit sweep")
	}
}
