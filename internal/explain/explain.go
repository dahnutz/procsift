// Package explain classifies deleted images, titles, lineage, and startup mentions.
// It does not decide that a process is hostile.
package explain

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/dahnutz/procsift/internal/model"
)

const (
	LabelMaintenance  = "maintenance corroborated"
	LabelUnexplained  = "unexplained"
	LabelInconclusive = "inconclusive"

	PathUnlinked     = "unlinked"
	PathReplaced     = "replaced"
	PathSame         = "same-inode"
	PathInconclusive = "inconclusive"
)

// FileView is one side of an inode comparison.
type FileView struct {
	OK    bool
	Dev   string
	Inode uint64
	// Absent is true when the pathname has no directory entry.
	Absent bool
	// Denied is true when the pathname could not be stated.
	Denied bool
}

// PathRelation compares the inode still running with the file at the old pathname.
func PathRelation(running, current FileView) string {
	if current.Absent {
		return PathUnlinked
	}
	if current.Denied || !current.OK || !running.OK {
		return PathInconclusive
	}
	if running.Dev == current.Dev && running.Inode == current.Inode {
		return PathSame
	}
	return PathReplaced
}

// ExplainInput is the evidence used to label a deleted image.
// Package ownership alone, a newer mtime alone, or a transaction alone is not enough.
// Maintenance corroborated requires an applicable transaction and a current file
// whose hash matches the package manifest. The local database is not independently trusted.
type ExplainInput struct {
	Path              string
	Temp              bool
	Relation          string
	IdentityOK        bool
	PackageDBReadable bool
	Package           string
	Start             time.Time
	StartKnown        bool
	CurrentMtime      time.Time
	MtimeKnown        bool
	Transaction       time.Time
	TransactionKnown  bool
	ManifestKnown     bool
	ManifestMatch     bool
}

// Explain returns maintenance corroborated, unexplained, or inconclusive.
func Explain(in ExplainInput) string {
	if in.Temp {
		return LabelUnexplained
	}
	if !in.IdentityOK || in.Relation == PathInconclusive || in.Relation == PathSame {
		return LabelInconclusive
	}
	if in.Relation == PathUnlinked {
		return LabelUnexplained
	}
	if in.Relation != PathReplaced {
		return LabelInconclusive
	}
	if !in.PackageDBReadable || in.Package == "" || !in.StartKnown {
		return LabelInconclusive
	}
	if !in.TransactionKnown || !in.Transaction.After(in.Start) {
		return LabelInconclusive
	}
	if !in.ManifestKnown || !in.ManifestMatch {
		return LabelInconclusive
	}
	return LabelMaintenance
}

// ServiceFromCgroup returns the last systemd service name in a cgroup file, if any.
func ServiceFromCgroup(text string) string {
	var found string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		path := line
		if i := strings.LastIndex(line, ":"); i >= 0 {
			path = line[i+1:]
		}
		base := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			base = path[i+1:]
		}
		if strings.Contains(base, ".service") {
			if i := strings.Index(base, ".service"); i > 0 {
				found = base[:i+len(".service")]
			}
		}
	}
	return found
}

// DevString formats a Linux dev_t as decimal major:minor (20-bit minor).
func DevString(dev uint64) string {
	major := dev >> 20
	minor := dev & ((1 << 20) - 1)
	return itoa(major) + ":" + itoa(minor)
}

// ParseMapDev parses the hex major:minor field from /proc/pid/maps.
func ParseMapDev(s string) (string, bool) {
	maj, min, ok := strings.Cut(s, ":")
	if !ok || maj == "" || min == "" {
		return "", false
	}
	major, err1 := parseHex(maj)
	minor, err2 := parseHex(min)
	if err1 != nil || err2 != nil {
		return "", false
	}
	return itoa(major) + ":" + itoa(minor), true
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func parseHex(s string) (uint64, error) {
	var n uint64
	for _, c := range s {
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += uint64(c - '0')
		case c >= 'a' && c <= 'f':
			n += uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n += uint64(c-'A') + 10
		default:
			return 0, errHex
		}
	}
	return n, nil
}

type hexErr string

func (e hexErr) Error() string { return string(e) }

const errHex hexErr = "bad hex"

// SameID reports whether two device:inode pairs name the same file.
func SameID(devA string, inoA uint64, devB string, inoB uint64) bool {
	return devA != "" && devA == devB && inoA == inoB
}

// UnderRoot joins an absolute path onto a fixture root.
// An absolute second argument to filepath.Join would discard the root.
func UnderRoot(root, abs string) string {
	if root == "" || root == "/" {
		return abs
	}
	return filepath.Join(root, strings.TrimPrefix(abs, "/"))
}

// HostPath recovers a host pathname from a proc symlink target.
// A fixture may store the target under its own directory. Live paths, and
// targets that do not sit under root, are returned unchanged.
func HostPath(root, recorded string) string {
	suffix := ""
	path := recorded
	if strings.HasSuffix(path, " (deleted)") {
		suffix = " (deleted)"
		path = strings.TrimSuffix(path, " (deleted)")
	}
	if root != "" && root != "/" {
		root = strings.TrimRight(filepath.Clean(root), "/")
		switch {
		case path == root:
			path = "/"
		case strings.HasPrefix(path, root+"/"):
			path = path[len(root):]
		}
	}
	return path + suffix
}

// DossierLines renders one deleted-image measurement. The label is an explanation, not a clearance.
func DossierLines(boot string, p model.Process, info *model.ExeIdentity) []string {
	if info == nil {
		return nil
	}
	user := p.User
	if user == "" {
		user = "-"
	}
	started := "ticks " + itoa(p.StartTicks)
	if !p.Started.IsZero() {
		started = p.Started.UTC().Format(time.RFC3339) + " (" + started + ")"
	}
	pkg := info.Package
	if pkg == "" {
		pkg = "none"
	}
	svc := p.Service
	if svc == "" {
		svc = "none"
	}
	hash := info.HashState
	if info.SHA256 != "" {
		hash = info.SHA256 + " " + info.HashState
	}
	lines := []string{
		"boot " + empty(boot),
		"pid " + itoa(uint64(p.PID)) + " start " + started,
		"ppid " + itoa(uint64(p.PPID)) + " uid " + itoa(uint64(p.UID)) + " user " + user,
		"exe " + p.Exe,
		"running dev " + empty(info.Dev) + " inode " + itoa(info.Inode) + " nlink " + itoa(info.NLink) + " size " + itoa(uint64(info.Size)),
		"sha256 " + hash + " scope " + empty(info.HashScope) + " bytes " + itoa(uint64(info.HashBytes)),
		"path " + info.Relation + " current dev " + empty(info.CurrentDev) + " inode " + itoa(info.CurrentInode),
		"package " + pkg,
		"label " + info.Label,
		"service " + svc,
		"identity-stable " + boolWord(info.IdentityOK),
	}
	if p.Cmdline != "" {
		lines = append(lines, "cmd "+p.Cmdline)
	}
	for _, n := range info.Notes {
		lines = append(lines, "note "+n)
	}
	return lines
}

func empty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func boolWord(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
