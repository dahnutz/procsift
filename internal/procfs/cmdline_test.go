package procfs

import (
	"testing"
	"unicode/utf8"
)

func TestRedactCmdline(t *testing.T) {
	in := []byte("node server --auth-token supersecret --host 127.0.0.1 --password=hunter2 --dns-result-order=ipv4first\x00")
	got := NormalizeCmdline(in)
	if stringsContains(got, "supersecret") || stringsContains(got, "hunter2") {
		t.Fatalf("secret leaked: %s", got)
	}
	if !stringsContains(got, "--auth-token [redacted]") || !stringsContains(got, "--password=[redacted]") {
		t.Fatalf("%s", got)
	}
	if !stringsContains(got, "--host 127.0.0.1") || !stringsContains(got, "--dns-result-order=ipv4first") {
		t.Fatalf("%s", got)
	}
}

func TestInterestingEnv(t *testing.T) {
	b := []byte("PATH=/usr/bin\x00LD_PRELOAD=/tmp/libx.so\x00SECRET=abc\x00LD_LIBRARY_PATH=/dev/shm/lib\x00")
	pre, audit, lib := InterestingEnv(b)
	if pre != "/tmp/libx.so" || audit != "" || lib != "/dev/shm/lib" {
		t.Fatalf("%q %q %q", pre, audit, lib)
	}
}

func TestRedactKeepsPortAndHidesAttachedSecrets(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"nc -l -p 4444", "nc -l -p 4444"},
		{"mysql -pHunter2", "mysql -p[redacted]"},
		{"mysql -p12345", "mysql -p[redacted]"},
		{"nc -l -p4444", "nc -l -p4444"},
		{"curl https://user:pw@host/path", "curl https://[redacted]@host/path"},
		{"curl -H Authorization:Bearer secret https://host", "curl -H Authorization:[redacted] [redacted] https://host"},
	} {
		if got := RedactCmdline(tc.in); got != tc.want {
			t.Errorf("%q: got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	for _, n := range []int{1, 3, 4, 5, 6, 7} {
		got := Truncate("abé漢字", n)
		if !utf8.ValidString(got) || len(got) > n {
			t.Fatalf("limit %d: %q", n, got)
		}
	}
}

func stringsContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && contains(s, sub)))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
