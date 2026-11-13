//go:build unix

package safeio

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOpenRegular(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	fifoLink := filepath.Join(dir, "fifo-link")
	if err := os.Symlink(fifo, fifoLink); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path         string
		follow             bool
		wantOK, notRegular bool
	}{
		{"regular", regular, false, true, false},
		{"regular follow", regular, true, true, false},
		{"fifo", fifo, false, false, true},
		{"fifo follow", fifo, true, false, true},
		{"symlink refused", link, false, false, false},
		{"symlink followed", link, true, true, false},
		{"symlink to fifo followed", fifoLink, true, false, true},
		{"directory", dir, false, false, true},
		{"device", "/dev/null", true, false, true},
		{"missing", filepath.Join(dir, "missing"), false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			var f *os.File
			var err error
			go func() {
				defer close(done)
				if tc.follow {
					f, _, err = OpenRegularFollow(tc.path)
				} else {
					f, _, err = OpenRegular(tc.path)
				}
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("open blocked")
			}
			if f != nil {
				f.Close()
			}
			if (err == nil) != tc.wantOK {
				t.Fatalf("err %v, want ok %v", err, tc.wantOK)
			}
			if tc.notRegular && !errors.Is(err, ErrNotRegular) {
				t.Fatalf("err %v, want ErrNotRegular", err)
			}
		})
	}
}
