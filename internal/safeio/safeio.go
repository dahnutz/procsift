// Package safeio opens files the scanner reads without letting a path that
// someone else controls hang the scan or redirect it.
package safeio

import "errors"

// ErrNotRegular reports that the opened descriptor was not a regular file.
var ErrNotRegular = errors.New("not a regular file")
