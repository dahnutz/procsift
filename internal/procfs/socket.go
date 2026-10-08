package procfs

import "strconv"
import "strings"

// SocketInode parses a file-descriptor target of the form socket:[inode].
func SocketInode(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inner := target[len("socket:[") : len(target)-1]
	n, err := strconv.ParseUint(inner, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
