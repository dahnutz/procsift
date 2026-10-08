//go:build linux

package collect

import (
	"errors"
	"os"

	"github.com/dahnutz/procsift/internal/model"
)

var errTruncated = errors.New("read exceeded the collection limit")

func readState(err error) string {
	switch {
	case errors.Is(err, errTruncated):
		return "truncated"
	case errors.Is(err, os.ErrPermission):
		return "denied"
	case errors.Is(err, os.ErrNotExist):
		return "unavailable"
	default:
		return "error"
	}
}

func (c *collector) issue(source string, err error) {
	c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: source, State: readState(err), Detail: err.Error()})
}

func (c *collector) changed(source, detail string) {
	c.snap.Coverage = append(c.snap.Coverage, model.ReadIssue{Source: source, State: "changed", Detail: detail})
}

// An absent status/maps/fd file does not establish that its process exited.
// Verify that the containing process directory is also absent.
func processGone(base string, err error) bool {
	if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	_, statErr := os.Stat(base)
	return errors.Is(statErr, os.ErrNotExist)
}
