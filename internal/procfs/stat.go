package procfs

import "strconv"
import "strings"

// ParseStartTicks returns the starttime field from /proc/pid/stat.
// The value is in USER_HZ ticks since boot. The comm field may contain spaces.
func ParseStartTicks(stat string) (uint64, bool) {
	stat = strings.TrimSpace(stat)
	i := strings.LastIndex(stat, ")")
	if i < 0 || i+1 >= len(stat) {
		return 0, false
	}
	fields := strings.Fields(stat[i+1:])
	// starttime is the 20th field after the comm parenthesis.
	if len(fields) < 20 {
		return 0, false
	}
	n, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ParseTTY returns tty_nr from /proc/pid/stat. Zero means no controlling terminal.
func ParseTTY(stat string) (uint64, bool) {
	stat = strings.TrimSpace(stat)
	i := strings.LastIndex(stat, ")")
	if i < 0 || i+1 >= len(stat) {
		return 0, false
	}
	fields := strings.Fields(stat[i+1:])
	// tty_nr is the 7th field after the comm parenthesis.
	if len(fields) < 7 {
		return 0, false
	}
	n, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
