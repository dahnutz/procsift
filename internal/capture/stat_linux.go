//go:build linux

package capture

import (
	"os"
	"syscall"
)

type fileID struct {
	dev uint64
	ino uint64
}

func fileIDs(info os.FileInfo) (fileID, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return fileID{}, false
	}
	return fileID{dev: st.Dev, ino: st.Ino}, true
}
