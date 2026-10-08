package model

import "testing"

func TestExitPolicyKeepsScannerFindingsVisible(t *testing.T) {
	self := Finding{Rule: "PROC-MEMFD-EXE", Severity: SevHigh, Origin: "scanner_self"}
	host := Finding{Rule: "PROC-DELETED-EXE", Severity: SevHigh}
	if FailedWithSelf([]Finding{self}, SevMedium, false) {
		t.Fatal("scanner-only run failed host exit policy")
	}
	if !FailedWithSelf([]Finding{self}, SevMedium, true) {
		t.Fatal("explicit scanner exit policy did not fail")
	}
	if !FailedWithSelf([]Finding{self, host}, SevMedium, false) {
		t.Fatal("independent host finding did not fail")
	}
	result, reason := HostExit([]Finding{self}, SevMedium, false)
	if result != "pass" || reason != "no host finding meets the exit threshold" {
		t.Fatalf("scanner-only exit %s %s", result, reason)
	}
	result, reason = HostExit([]Finding{self, host}, SevMedium, false)
	if result != "fail" || reason != "PROC-DELETED-EXE" {
		t.Fatalf("host exit %s %s", result, reason)
	}
}
