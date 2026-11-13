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
		{"sshpass -p hunter2 ssh host", "sshpass -p [redacted] ssh host"},
		{"/usr/bin/sshpass -phunter2 ssh host", "/usr/bin/sshpass -p[redacted] ssh host"},
		{"mysqldump -pS3cret db", "mysqldump -p[redacted] db"},
		{"find / -print", "find / -print"},
		{"gcc -pthread x.c", "gcc -pthread x.c"},
		{"ssh -p 2222 host", "ssh -p 2222 host"},
		{"curl https://user:pw@host/path", "curl https://user:[redacted]@host/path"},
		{"psql postgres://u:p@ss@db/app", "psql postgres://u:[redacted]@db/app"},
		{"git clone https://ghp_abcdef123456@github.com/o/r", "git clone https://[redacted]@github.com/o/r"},
		{"git clone ssh://git@github.com/o/r", "git clone ssh://git@github.com/o/r"},
		{"curl https://host/a@b", "curl https://host/a@b"},
		{"app --db=mysql://root:pw@h/x --url=http://h/", "app --db=mysql://root:[redacted]@h/x --url=http://h/"},
		{"curl --header=Authorization: Bearer tok https://h", "curl --header=Authorization:[redacted] Bearer [redacted] https://h"},
		{"curl -H X-Auth: Bearer abc https://h", "curl -H X-Auth: Bearer [redacted] https://h"},
		{"curl -H X-Api-Key:abc123 https://h", "curl -H X-Api-Key:[redacted] https://h"},
		{"curl -H X-Auth-Token: abc123 https://h", "curl -H X-Auth-Token:[redacted] [redacted] https://h"},
		{"curl -u user:pw https://h", "curl -u user:[redacted] https://h"},
		{"curl --user=user:pw https://h", "curl --user=user:[redacted] https://h"},
		{"curl -uuser:pw https://h", "curl -uuser:[redacted] https://h"},
		{"java -Dpassword=x -jar app.jar", "java -Dpassword=[redacted] -jar app.jar"},
		{"env PGPASSWORD=x psql", "env PGPASSWORD=[redacted] psql"},
		{"app --token=abc --token abc", "app --token=[redacted] --token [redacted]"},
		{"mysql -p", "mysql -p"},
		{"redis-cli -h 10.0.0.5 -p 6379", "redis-cli -h 10.0.0.5 -p 6379"},
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
