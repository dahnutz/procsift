//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadReportRejectsUnboundedOrUnrecognizedInput(t *testing.T) {
	dir := t.TempDir()
	invalid := filepath.Join(dir, "unrecognized.json")
	if err := os.WriteFile(invalid, []byte(`{"tool":"other","version":"0.5.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readReport(invalid); err == nil {
		t.Fatal("unrecognized JSON was accepted as a scan report")
	}
	large := filepath.Join(dir, "large.json")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate((64 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readReport(large); err == nil || !strings.Contains(err.Error(), "64 MiB") {
		t.Fatalf("oversized input was not bounded: %v", err)
	}
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readReport(fifo); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("FIFO input was not rejected: %v", err)
	}
}
