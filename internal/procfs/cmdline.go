package procfs

import (
	"bytes"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// NormalizeCmdline turns a NUL-separated argument vector into a single line
// and redacts values that look like tokens, passwords, or keys.
func NormalizeCmdline(b []byte) string {
	b = bytes.ReplaceAll(b, []byte{0}, []byte{' '})
	// Redact before truncating, so a secret cannot survive by being cut
	// mid-token.
	return Truncate(RedactCmdline(string(b)), 240)
}

// RedactCmdline hides credentials in a command line. The argument vector is
// already flattened, so quoting from the original command is not available.
//
// Redacted: values of sensitive flags and KEY=VALUE pairs (password, token,
// secret, key, credential), -p passwords for mysql/mariadb/sshpass, curl -u
// passwords,
// Authorization and other credential headers, the token after an
// authorization scheme (Bearer, Basic, Token, Digest), URL passwords, and
// token-like URL user names.
//
// Deliberately kept, because they are triage evidence: ports (nc -p 4444),
// hosts, IP addresses, paths, user names in URLs, and ordinary flags.
func RedactCmdline(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	parts := strings.Fields(s)
	client := strings.ToLower(filepath.Base(parts[0]))
	// -p means a password only for some clients. Elsewhere it is a port
	// (nc, ssh) or an unrelated flag (find -print, gcc -pthread).
	attachedP := strings.HasPrefix(client, "mysql") || strings.HasPrefix(client, "mariadb") || client == "sshpass"
	separateP := client == "sshpass"
	// next redacts the following argument when it can be a value: not a
	// flag and not a URL, so later endpoints stay visible.
	next := func(i int) int {
		if i+1 < len(parts) && !strings.HasPrefix(parts[i+1], "-") && !strings.Contains(parts[i+1], "://") {
			i++
			parts[i] = "[redacted]"
		}
		return i
	}
	// headerValue redacts a header value that flattening split from its
	// name: one argument, or a scheme word followed by its token.
	headerValue := func(i int) int {
		if i+1 < len(parts) && authScheme(parts[i+1]) {
			return next(i + 1)
		}
		return next(i)
	}
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		if name, value, ok := credentialHeader(p); ok {
			parts[i] = name + "[redacted]"
			switch {
			case value == "":
				i = headerValue(i)
			case authScheme(value):
				i = next(i)
			}
			continue
		}
		if authScheme(p) {
			i = next(i)
			continue
		}
		if eq := strings.IndexByte(p, '='); eq > 0 && sensitiveKey(p[:eq]) {
			parts[i] = p[:eq+1] + "[redacted]"
			continue
		}
		if attachedP && strings.HasPrefix(p, "-p") && len(p) > 2 {
			parts[i] = "-p[redacted]"
			continue
		}
		if separateP && p == "-p" && i+1 < len(parts) {
			i++
			parts[i] = "[redacted]"
			continue
		}
		if client == "curl" {
			// curl -u user:password, --user user:password, -uuser:password.
			switch {
			case (p == "-u" || p == "--user") && i+1 < len(parts):
				i++
				parts[i] = userPassword(parts[i])
				continue
			case strings.HasPrefix(p, "--user="):
				parts[i] = "--user=" + userPassword(p[len("--user="):])
				continue
			case strings.HasPrefix(p, "-u") && len(p) > 2 && !strings.HasPrefix(p, "--"):
				parts[i] = "-u" + userPassword(p[2:])
				continue
			}
		}
		if strings.HasPrefix(p, "-") && sensitiveKey(p) {
			i = next(i)
		}
	}
	for i := range parts {
		parts[i] = redactURLUserinfo(parts[i])
	}
	return strings.Join(parts, " ")
}

// credentialHeader recognizes "Name:" or "Name:value" where the name is
// Authorization or contains a sensitive word (X-Auth-Token, X-Api-Key). The
// header may be glued to a flag, as in --header=Authorization:. It returns
// the text up to and including the colon, and the value after it.
func credentialHeader(arg string) (name, value string, ok bool) {
	colon := strings.IndexByte(arg, ':')
	if colon <= 0 || strings.HasPrefix(arg[colon:], "://") {
		return "", "", false
	}
	key := arg[:colon]
	if eq := strings.LastIndexByte(key, '='); eq >= 0 {
		key = key[eq+1:]
	}
	if key == "" || strings.ContainsAny(key, "/@") {
		return "", "", false
	}
	if !strings.EqualFold(key, "authorization") && !sensitiveKey(key) {
		return "", "", false
	}
	return arg[:colon+1], arg[colon+1:], true
}

// userPassword keeps the user of "user:password" and hides the password.
func userPassword(v string) string {
	if user, _, ok := strings.Cut(v, ":"); ok {
		return user + ":[redacted]"
	}
	return v
}

func authScheme(arg string) bool {
	switch strings.ToLower(arg) {
	case "bearer", "basic", "token", "digest":
		return true
	}
	return false
}

// redactURLUserinfo replaces the password in scheme://user:password@host,
// keeping the user, and replaces a user name that looks like an access token.
// It scans strings instead of using net/url, so a malformed URL cannot fail
// the whole line. The userinfo ends at the last @ before the path, so an @
// inside the password does not leak its tail.
func redactURLUserinfo(arg string) string {
	var b strings.Builder
	rest := arg
	for {
		k := strings.Index(rest, "://")
		if k < 0 {
			break
		}
		start := k + 3
		b.WriteString(rest[:start])
		rest = rest[start:]
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		authority := rest[:end]
		at := strings.LastIndexByte(authority, '@')
		if at < 0 {
			continue
		}
		userinfo := authority[:at]
		if colon := strings.IndexByte(userinfo, ':'); colon >= 0 {
			b.WriteString(userinfo[:colon+1] + "[redacted]")
		} else if tokenLike(userinfo) {
			b.WriteString("[redacted]")
		} else {
			b.WriteString(userinfo)
		}
		rest = rest[at:]
	}
	b.WriteString(rest)
	return b.String()
}

// tokenLike reports whether a URL user name is probably an access token, as
// in https://ghp_xxx@github.com/. Short names such as git or deploy are kept.
func tokenLike(user string) bool {
	for _, prefix := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-"} {
		if strings.HasPrefix(user, prefix) {
			return true
		}
	}
	return len(user) >= 32
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
