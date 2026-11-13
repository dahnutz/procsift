//go:build !unix

package safeio

import "os"

// OpenRegular falls back to a plain open on platforms without O_NOFOLLOW and
// O_NONBLOCK. ProcSift only scans on Linux; this keeps shared packages
// building elsewhere.
func OpenRegular(path string) (*os.File, os.FileInfo, error) {
	return OpenRegularFollow(path)
}

// OpenRegularFollow opens path and requires a regular file.
func OpenRegularFollow(path string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
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
