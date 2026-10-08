package analyze

import "testing"

func TestClassifyTask(t *testing.T) {
	cases := []struct {
		name                      string
		listed, dir, status, kill bool
		pid, tgid                 int
		want                      string
	}{
		{"listed leader", true, true, true, true, 10, 10, TaskNormal},
		{"hidden leader", false, true, true, true, 10, 10, TaskHidden},
		{"thread", false, true, true, true, 11, 10, TaskThread},
		{"ghost", false, false, false, true, 12, 0, TaskGhost},
		{"absent", false, false, false, false, 13, 0, TaskAbsent},
		{"listed even if status failed", true, false, false, true, 14, 0, TaskNormal},
	}
	for _, tc := range cases {
		got := ClassifyTask(tc.listed, tc.dir, tc.status, tc.pid, tc.tgid, tc.kill)
		if got != tc.want {
			t.Fatalf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}
