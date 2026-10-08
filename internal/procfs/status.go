package procfs

import (
	"strconv"
	"strings"
)

// Status is the subset of /proc/pid/status used for triage.
type Status struct {
	Name         string
	State        string
	PID          int
	TGID         int
	PPID         int
	TracerPID    int
	UID          int
	Threads      int
	VmRSSKiB     int
	Kthread      bool
	KthreadKnown bool
}

// ParseStatus reads a /proc/pid/status body. A missing Pid is an error.
func ParseStatus(text string) (Status, error) {
	var s Status
	for _, line := range strings.Split(text, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "Name":
			s.Name = val
		case "State":
			s.State = val
		case "Pid":
			s.PID = atoiField(val)
		case "Tgid":
			s.TGID = atoiField(val)
		case "PPid":
			s.PPID = atoiField(val)
		case "TracerPid":
			s.TracerPID = atoiField(val)
		case "Uid":
			s.UID = atoiField(val)
		case "Threads":
			s.Threads = atoiField(val)
		case "VmRSS":
			s.VmRSSKiB = atoiField(val)
		case "Kthread":
			s.KthreadKnown = true
			s.Kthread = atoiField(val) == 1
		}
	}
	if s.PID == 0 {
		return s, errNoPID
	}
	if s.TGID == 0 {
		s.TGID = s.PID
	}
	return s, nil
}

func atoiField(s string) int {
	f := firstField(s)
	n, _ := strconv.Atoi(f)
	return n
}

func firstField(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s
	}
	return s[:i]
}
