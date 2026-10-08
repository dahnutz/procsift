//go:build linux

package main

import "testing"

func TestFailOnSelfIsExplicit(t *testing.T) {
	defaults, code, err := parseScan(nil)
	if err != nil || code != 0 || defaults.failOnSelf {
		t.Fatalf("default %+v %d %v", defaults, code, err)
	}
	selected, code, err := parseScan([]string{"-fail-on-self"})
	if err != nil || code != 0 || !selected.failOnSelf {
		t.Fatalf("selected %+v %d %v", selected, code, err)
	}
}
