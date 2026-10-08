package procfs

import "testing"

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
