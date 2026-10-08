package report

import (
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func TestReportSeparatesHostAndScannerCounts(t *testing.T) {
	rep := Build(&model.Snapshot{}, []model.Finding{
		{Severity: model.SevHigh, Origin: "scanner_self"},
		{Severity: model.SevMedium},
	}, Options{Version: "0.4.0"})
	if rep.Counts.High != 1 || rep.Counts.Medium != 1 || rep.ScannerCounts.High != 1 || rep.HostCounts.Medium != 1 || rep.HostCounts.High != 0 {
		t.Fatalf("counts total=%+v host=%+v scanner=%+v", rep.Counts, rep.HostCounts, rep.ScannerCounts)
	}
}
