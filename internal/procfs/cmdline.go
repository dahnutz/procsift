package procfs

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

var urlCredentials = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+:[^\s/@]+@`)

// NormalizeCmdline turns a NUL-separated argument vector into a single line
// and redacts values that look like tokens, passwords, or keys.
func NormalizeCmdline(b []byte) string {
	b = bytes.ReplaceAll(b, []byte{0}, []byte{' '})
	return Truncate(RedactCmdline(string(b)), 240)
}

// RedactCmdline hides values of sensitive flags. The argument vector is
// already flattened, so quoting from the original command is not available.
func RedactCmdline(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	parts := strings.Fields(s)
	client := strings.ToLower(filepath.Base(parts[0]))
	mysqlPassword := strings.HasPrefix(client, "mysql") || strings.HasPrefix(client, "mariadb")
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		if strings.HasPrefix(strings.ToLower(p), "authorization:") {
			parts[i] = "Authorization:[redacted]"
			// Quoting is lost after flattening. Keep this bounded so later
			// endpoints remain visible.
			for n := 0; n < 2 && i+1 < len(parts) && !strings.HasPrefix(parts[i+1], "-") && !strings.Contains(parts[i+1], "://"); n++ {
				i++
				parts[i] = "[redacted]"
			}
			continue
		}
		if eq := strings.IndexByte(p, '='); eq > 0 && sensitiveKey(p[:eq]) {
			parts[i] = p[:eq+1] + "[redacted]"
			continue
		}
		if strings.HasPrefix(p, "-p") && len(p) > 2 && (mysqlPassword || hasNonDigit(p[2:])) {
			parts[i] = "-p[redacted]"
			continue
		}
		if strings.HasPrefix(p, "-") && sensitiveKey(p) && i+1 < len(parts) && !strings.HasPrefix(parts[i+1], "-") {
			i++
			parts[i] = "[redacted]"
		}
	}
	return urlCredentials.ReplaceAllString(strings.Join(parts, " "), "${1}[redacted]@")
}

func hasNonDigit(s string) bool {
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return true
		}
	}
	return false
}

func sensitiveKey(arg string) bool {
	a := strings.ToLower(strings.TrimLeft(arg, "-"))
	if i := strings.IndexByte(a, '='); i >= 0 {
		a = a[:i]
	}
	a = strings.ReplaceAll(a, "_", "-")
	switch a {
	case "password", "pass", "passwd", "token", "secret",
		"auth-token", "access-token", "api-key", "apikey",
		"credential", "credentials", "private-key", "session",
		"session-token", "bearer", "authorization":
		return true
	}
	for _, frag := range []string{"password", "passwd", "token", "secret", "credential", "api-key", "apikey", "authorization"} {
		if strings.Contains(a, frag) {
			return true
		}
	}
	return false
}

// InterestingEnv returns only loader variables. The rest of the environment,
// which often holds secrets, is discarded.
func InterestingEnv(b []byte) (preload, audit, library string) {
	for _, p := range bytes.Split(b, []byte{0}) {
		s := string(p)
		key, val, ok := strings.Cut(s, "=")
		if !ok {
			continue
		}
		switch key {
		case "LD_PRELOAD":
			preload = Truncate(val, 200)
		case "LD_AUDIT":
			audit = Truncate(val, 200)
		case "LD_LIBRARY_PATH":
			library = Truncate(val, 200)
		}
	}
	return preload, audit, library
}

// Truncate shortens s to at most n bytes, appending an ellipsis when it cuts.
func Truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	if n <= 0 || len(s) <= n {
		return s
	}
	if n < 3 {
		cut := n
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		return s[:cut]
	}
	cut := n - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
