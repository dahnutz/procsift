//go:build linux

// Package capture copies a still-open executable and the metadata needed to
// tie it to one process. It does not execute the bytes or contact endpoints.
package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dahnutz/procsift/internal/procfs"
)

const DefaultMaxBytes int64 = 64 << 20

// Options selects one process and the private directory that receives the bundle.
type Options struct {
	ProcRoot string
	PID      int
	OutDir   string
	Version  string
	MaxBytes int64
}

// Hash is a SHA-256 of the captured image. Scope is full only when every byte
// of the file was read and the process identity stayed stable.
type Hash struct {
	Algorithm string `json:"algorithm"`
	Scope     string `json:"scope"`
	Bytes     int64  `json:"bytes"`
	Size      int64  `json:"size,omitempty"`
	Digest    string `json:"digest"`
}

// Manifest is the bundle index. image.bin is absent when the read failed or
// the process identity changed.
type Manifest struct {
	Tool           string    `json:"tool"`
	Version        string    `json:"version"`
	Collected      time.Time `json:"collected"`
	BootID         string    `json:"boot_id,omitempty"`
	PID            int       `json:"pid"`
	StartTicks     uint64    `json:"start_ticks,omitempty"`
	IdentityStable bool      `json:"identity_stable"`
	Exe            string    `json:"exe,omitempty"`
	Cmdline        string    `json:"cmdline,omitempty"`
	ImageFile      string    `json:"image_file,omitempty"`
	Hash           *Hash     `json:"hash,omitempty"`
	MapsFile       string    `json:"maps_file,omitempty"`
	Descriptors    []string  `json:"descriptors,omitempty"`
	Sockets        []string  `json:"sockets,omitempty"`
	Failures       []string  `json:"failures,omitempty"`
	DurationMS     int64     `json:"duration_ms"`
	Limits         []string  `json:"limits"`
}

// Run writes a new directory. An existing path is refused.
func Run(opt Options) error {
	if opt.PID <= 0 {
		return fmt.Errorf("pid must be positive")
	}
	if opt.OutDir == "" {
		return fmt.Errorf("output directory is required")
	}
	if opt.ProcRoot == "" {
		opt.ProcRoot = "/proc"
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = DefaultMaxBytes
	}
	if opt.Version == "" {
		opt.Version = "0.4.0"
	}
	if _, err := os.Lstat(opt.OutDir); err == nil {
		return fmt.Errorf("refuse existing path %s", opt.OutDir)
	}
	if err := os.Mkdir(opt.OutDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", opt.OutDir, err)
	}
	started := time.Now()
	base := filepath.Join(opt.ProcRoot, strconv.Itoa(opt.PID))
	man := Manifest{
		Tool:      "procsift",
		Version:   opt.Version,
		Collected: started.UTC(),
		PID:       opt.PID,
		BootID:    readTrim(filepath.Join(opt.ProcRoot, "sys", "kernel", "random", "boot_id")),
		Limits: []string{
			"The captured image is not executed.",
			"Endpoints recorded here are not contacted.",
			"A hash scope of prefix is not a full-file digest. full is used only when the read reached the end of the file and the process identity stayed stable.",
		},
	}
	if st, err := readStatus(base); err != nil {
		man.Failures = append(man.Failures, "status: "+err.Error())
	} else {
		man.PID = st.PID
	}
	if body, err := os.ReadFile(filepath.Join(base, "stat")); err == nil {
		if ticks, ok := procfs.ParseStartTicks(string(body)); ok {
			man.StartTicks = ticks
		}
	} else {
		man.Failures = append(man.Failures, "stat: "+err.Error())
	}
	man.Exe = readLink(filepath.Join(base, "exe"))
	if cmd, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		man.Cmdline = procfs.NormalizeCmdline(cmd)
	}
	beforeDev, beforeIno, beforeSize := statExe(filepath.Join(base, "exe"))
	hash, imageName, fail := copyImage(filepath.Join(base, "exe"), filepath.Join(opt.OutDir, "image.bin"), opt.MaxBytes, beforeSize)
	if fail != "" {
		man.Failures = append(man.Failures, fail)
	}
	afterTicks, afterDev, afterIno, afterPID, afterOK := recheck(base)
	stable := afterOK && afterPID == man.PID && afterTicks == man.StartTicks && afterDev == beforeDev && afterIno == beforeIno && beforeDev != 0
	man.IdentityStable = stable
	if imageName != "" && !stable {
		_ = os.Remove(filepath.Join(opt.OutDir, imageName))
		man.Failures = append(man.Failures, "process identity changed during the read; image discarded")
		hash = nil
	}
	if hash != nil {
		if !stable || hash.Bytes != hash.Size {
			hash.Scope = "prefix"
		}
		man.Hash = hash
		if stable {
			man.ImageFile = imageName
		}
	}
	if maps, err := os.ReadFile(filepath.Join(base, "maps")); err == nil {
		if len(maps) > 256<<10 {
			maps = maps[:256<<10]
			man.Failures = append(man.Failures, "maps truncated at 256 KiB")
		}
		if err := writePrivate(filepath.Join(opt.OutDir, "maps.txt"), maps); err == nil {
			man.MapsFile = "maps.txt"
		}
	} else {
		man.Failures = append(man.Failures, "maps: "+err.Error())
	}
	man.Descriptors, man.Sockets = readFDs(filepath.Join(base, "fd"), opt.ProcRoot)
	man.DurationMS = time.Since(started).Milliseconds()
	body, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := writePrivate(filepath.Join(opt.OutDir, "manifest.json"), body); err != nil {
		return err
	}
	return nil
}

func copyImage(src, dst string, max, size int64) (*Hash, string, string) {
	in, err := os.Open(src)
	if err != nil {
		return nil, "", "image: " + err.Error()
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, "", "image create: " + err.Error()
	}
	defer out.Close()
	h := sha256.New()
	n, err := io.Copy(out, io.TeeReader(io.LimitReader(in, max), h))
	if err != nil {
		return nil, "image.bin", "image read: " + err.Error()
	}
	scope := "prefix"
	if n == size && n <= max {
		if n < max {
			scope = "full"
		} else {
			var extra [1]byte
			if x, _ := in.Read(extra[:]); x == 0 {
				scope = "full"
			}
		}
	}
	if err := out.Sync(); err != nil {
		return nil, "image.bin", "image sync: " + err.Error()
	}
	return &Hash{
		Algorithm: "sha256",
		Scope:     scope,
		Bytes:     n,
		Size:      size,
		Digest:    hex.EncodeToString(h.Sum(nil)),
	}, "image.bin", ""
}

func readFDs(dir, proc string) (fds, sockets []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{"fd: " + err.Error()}, nil
	}
	if len(entries) > 64 {
		entries = entries[:64]
		fds = append(fds, "descriptor list truncated at 64")
	}
	inodes := map[uint64]struct{}{}
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil {
			fds = append(fds, e.Name()+": unreadable")
			continue
		}
		fds = append(fds, e.Name()+" -> "+target)
		if len(target) > 8 && target[:7] == "socket:" {
			var ino uint64
			if _, err := fmt.Sscanf(target, "socket:[%d]", &ino); err == nil && ino > 0 {
				inodes[ino] = struct{}{}
			}
		}
	}
	if len(inodes) == 0 {
		return fds, sockets
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		body, err := os.ReadFile(filepath.Join(proc, "net", name))
		if err != nil {
			continue
		}
		for _, sock := range procfs.ParseNet(name, string(body)) {
			if _, ok := inodes[sock.Inode]; ok {
				sockets = append(sockets, fmt.Sprintf("%s %s %s -> %s inode %d", sock.Proto, sock.State, sock.Local, sock.Remote, sock.Inode))
			}
		}
	}
	return fds, sockets
}

func writePrivate(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readStatus(base string) (procfs.Status, error) {
	b, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return procfs.Status{}, err
	}
	return procfs.ParseStatus(string(b))
}

func recheck(base string) (ticks, dev, ino uint64, pid int, ok bool) {
	b, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return 0, 0, 0, 0, false
	}
	st, err := procfs.ParseStatus(string(b))
	if err != nil {
		return 0, 0, 0, 0, false
	}
	body, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return 0, 0, 0, st.PID, false
	}
	ticks, ticksOK := procfs.ParseStartTicks(string(body))
	dev, ino, _ = statExe(filepath.Join(base, "exe"))
	if !ticksOK || dev == 0 {
		return ticks, dev, ino, st.PID, false
	}
	return ticks, dev, ino, st.PID, true
}

func statExe(path string) (dev, ino uint64, size int64) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, 0
	}
	size = info.Size()
	if st, ok := fileIDs(info); ok {
		return st.dev, st.ino, size
	}
	return 0, 0, size
}

func readLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return target
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return string(b)
}
