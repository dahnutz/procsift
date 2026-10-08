//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/report"
)

func writeReportFile(path string, rep model.Report, format string) error {
	// O_EXCL makes the existence check and creation atomic. It also refuses
	// symlinks (including dangling ones), hardlinks, FIFOs, and existing files.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create new report %s: %w", path, err)
	}
	defer f.Close()
	if err := report.Write(f, rep, format); err != nil {
		return fmt.Errorf("write %s (partial report retained): %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
