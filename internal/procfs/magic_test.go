package procfs

import "testing"

func TestClassifyMagic(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{0x7f, 'E', 'L', 'F', 2, 1}, "elf"},
		{[]byte{'M', 'Z', 0x90, 0}, "mz"},
		{[]byte("#!/bin/sh\n"), "shebang"},
		{[]byte{0x00, 0x01, 0x02, 0x03}, ""},
		{[]byte{'M'}, ""},
	}
	for _, tc := range cases {
		if got := ClassifyMagic(tc.in); got != tc.want {
			t.Fatalf("%q: got %q want %q", tc.in, got, tc.want)
		}
	}
}
