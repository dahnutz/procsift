package analyze

// Task kinds produced by comparing directory listings, /proc lookup, and a pid probe.
const (
	TaskNormal = "normal"
	TaskThread = "thread"
	TaskHidden = "hidden"
	TaskGhost  = "ghost"
	TaskAbsent = "absent"
)

// ClassifyTask decides what a pid is from one observation.
// inListing is true when a /proc directory read returned the pid.
// procDir is true when that pid directory can be opened directly.
// statusOK is true when /proc/pid/status yielded a pid.
// killVisible is true when kill(pid, 0) returns success or EPERM.
func ClassifyTask(inListing, procDir, statusOK bool, pid, tgid int, killVisible bool) string {
	if procDir && statusOK && tgid != pid && !inListing {
		return TaskThread
	}
	if procDir && statusOK && tgid == pid && !inListing {
		return TaskHidden
	}
	if procDir || inListing {
		return TaskNormal
	}
	if killVisible {
		return TaskGhost
	}
	_ = pid
	return TaskAbsent
}
