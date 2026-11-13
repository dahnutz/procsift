//go:build linux

// Package safeio opens files the scanner reads without letting a path that
// someone else controls hang the scan or redirect it.
package safeio

import (
	"errors"
	"os"
	"syscall"
)

// ErrNotRegular reports that the opened descriptor was not a regular file.
var ErrNotRegular = errors.New("not a regular file")

// OpenRegular opens path read-only without following a final symlink and
// without blocking, then checks on the descriptor that it is a regular file.
// Use it for paths an unprivileged user can influence (/dev/shm, /tmp, home
// directories, container roots).
func OpenRegular(path string) (*os.File, os.FileInfo, error) {
	return open(path, syscall.O_NOFOLLOW)
}

// OpenRegularFollow is OpenRegular for paths that must be followed: magic
// links such as /proc/<pid>/exe and map_files entries, and operator-supplied
// paths where a symlink is a deliberate choice. A FIFO or device at the end of
// the path still cannot block the scan or be read.
func OpenRegularFollow(path string) (*os.File, os.FileInfo, error) {
	return open(path, 0)
}

func open(path string, extra int) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|extra, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: ErrNotRegular}
	}
	return f, info, nil
}
