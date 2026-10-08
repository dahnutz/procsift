package procfs

import "testing"

func TestParseStartTicks(t *testing.T) {
	line := "3335 (cat) R 3309 3309 3309 0 -1 4194304 90 0 0 0 0 0 0 0 20 0 1 0 22067 5967872 454"
	ticks, ok := ParseStartTicks(line)
	if !ok || ticks != 22067 {
		t.Fatalf("ticks %d ok %v", ticks, ok)
	}
	spaced := "9 (my proc) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99 1 1"
	ticks, ok = ParseStartTicks(spaced)
	if !ok || ticks != 99 {
		t.Fatalf("spaced %d ok %v", ticks, ok)
	}
	if _, ok := ParseStartTicks("nope"); ok {
		t.Fatal("expected failure")
	}
}
