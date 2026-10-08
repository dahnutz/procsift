package procfs

import "testing"

func TestTaintFlags(t *testing.T) {
	// Bit 0 and bit 13: proprietary and unsigned.
	got := TaintFlags(1 | (1 << 13))
	if len(got) != 2 || got[0] != "proprietary-module" || got[1] != "unsigned-module" {
		t.Fatalf("%v", got)
	}
	if flags := TaintFlags(0); flags != nil {
		t.Fatalf("%v", flags)
	}
}
