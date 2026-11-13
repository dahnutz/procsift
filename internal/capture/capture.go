//go:build linux

// Package capture copies a still-open executable and the metadata needed to
// tie it to one process. It does not execute the bytes or contact endpoints.
package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/dahnutz/procsift/internal/model"
	"github.com/dahnutz/procsift/internal/procfs"
	"github.com/dahnutz/procsift/internal/safeio"
)

const DefaultMaxBytes int64 = 64 << 20

// Read caps for the small /proc files copied into the manifest.
const (
	maxSmallFile   = 64 << 10
	maxEnviron     = 1 << 20
	maxMapsCopy    = 256 << 10
	maxSocketTable = 32 << 20
	maxDescriptors = 256
	maxNamespaces  = 32
)

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
	Tool           string            `json:"tool"`
	Version        string            `json:"version"`
	Collected      time.Time         `json:"collected"`
	BootID         string            `json:"boot_id,omitempty"`
	PID            int               `json:"pid"`
	StartTicks     uint64            `json:"start_ticks,omitempty"`
	IdentityStable bool              `json:"identity_stable"`
	Exe            string            `json:"exe,omitempty"`
	Cmdline        string            `json:"cmdline,omitempty"`
	ImageFile      string            `json:"image_file,omitempty"`
	Hash           *Hash             `json:"hash,omitempty"`
	MapsFile       string            `json:"maps_file,omitempty"`
	Status         string            `json:"status,omitempty"`
	Cgroup         string            `json:"cgroup,omitempty"`
	LoaderEnv      map[string]string `json:"loader_env,omitempty"`
	Namespaces     map[string]string `json:"namespaces,omitempty"`
	Descriptors    []string          `json:"descriptors,omitempty"`
	Sockets        []string          `json:"sockets,omitempty"`
	Failures       []string          `json:"failures,omitempty"`
	DurationMS     int64             `json:"duration_ms"`
	Limits         []string          `json:"limits"`
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
		return fmt.Errorf("capture version is required")
	}
	if _, err := os.Lstat(opt.OutDir); err == nil {
		return fmt.Errorf("refuse existing path %s", opt.OutDir)
	}
	if err := os.Mkdir(opt.OutDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", opt.OutDir, err)
	}
	out, err := openOutDir(opt.OutDir)
	if err != nil {
		return err
	}
	defer out.Close()
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
			"Only loader variables are kept from the environment; other values are not copied.",
		},
	}
	fail := func(what string, err error) { man.Failures = append(man.Failures, what+": "+err.Error()) }
	if b, truncated, err := readCapped(filepath.Join(base, "status"), maxSmallFile); err != nil {
		fail("status", err)
	} else if st, perr := procfs.ParseStatus(string(b)); perr != nil {
		fail("status", perr)
	} else {
		man.PID = st.PID
		man.Status = string(b)
		if truncated {
			man.Failures = append(man.Failures, "status truncated at 64 KiB")
		}
	}
	if body, _, err := readCapped(filepath.Join(base, "stat"), maxSmallFile); err == nil {
		if ticks, ok := procfs.ParseStartTicks(string(body)); ok {
			man.StartTicks = ticks
		}
	} else {
		fail("stat", err)
	}
	man.Exe = readLink(filepath.Join(base, "exe"))
	if cmd, _, err := readCapped(filepath.Join(base, "cmdline"), maxSmallFile); err == nil {
		man.Cmdline = procfs.NormalizeCmdline(cmd)
	}
	if b, _, err := readCapped(filepath.Join(base, "cgroup"), maxSmallFile); err == nil {
		man.Cgroup = string(b)
	} else {
		fail("cgroup", err)
	}
	man.LoaderEnv = readLoaderEnv(base, &man)
	man.Namespaces = readNamespaces(filepath.Join(base, "ns"), &man)

	exe := filepath.Join(base, "exe")
	beforeID, beforeOK := statExe(exe)
	hash, imageName, copyFail, openedID := copyImage(exe, out, "image.bin", opt.MaxBytes)
	if copyFail != "" {
		man.Failures = append(man.Failures, copyFail)
	}
	afterTicks, afterID, afterPID, afterOK := recheck(base)
	stable := stableIdentity(identityCheck{
		pid: man.PID, ticks: man.StartTicks,
		before: beforeID, beforeOK: beforeOK, opened: openedID,
		after: afterID, afterPID: afterPID, afterTicks: afterTicks, afterOK: afterOK,
	})
	man.IdentityStable = stable
	if imageName != "" && (!stable || hash == nil) {
		_ = removeAt(out, imageName)
		if !stable {
			man.Failures = append(man.Failures, "process identity changed during the read; image discarded")
		}
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
	if maps, truncated, err := readCapped(filepath.Join(base, "maps"), maxMapsCopy); err == nil {
		if truncated {
			man.Failures = append(man.Failures, "maps truncated at 256 KiB")
		}
		if err := writeAt(out, "maps.txt", maps); err == nil {
			man.MapsFile = "maps.txt"
		} else {
			fail("maps write", err)
		}
	} else {
		fail("maps", err)
	}
	var sockFailures []string
	man.Descriptors, man.Sockets, sockFailures = readFDs(filepath.Join(base, "fd"), base)
	man.Failures = append(man.Failures, sockFailures...)
	man.DurationMS = time.Since(started).Milliseconds()
	body, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return writeAt(out, "manifest.json", body)
}

// openOutDir opens the directory Run just created, refusing a symlink, and
// checks that it is still a private directory owned by this user. Files are
// then created relative to this descriptor, so swapping the path mid-capture
// cannot redirect them.
func openOutDir(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	dir := os.NewFile(uintptr(fd), path)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		dir.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || int(st.Uid) != os.Geteuid() || st.Mode&0o077 != 0 {
		dir.Close()
		return nil, fmt.Errorf("%s is no longer the private directory this capture created", path)
	}
	return dir, nil
}

func createAt(dir *os.File, name string) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name)), nil
}

func removeAt(dir *os.File, name string) error {
	return syscall.Unlinkat(int(dir.Fd()), name)
}

func writeAt(dir *os.File, name string, body []byte) error {
	f, err := createAt(dir, name)
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

// identityCheck holds the three views of the executable. A capture is
// stable only when the path before the read, the descriptor actually read,
// and the path after the read name the same file, and the process kept its
// PID and start time.
type identityCheck struct {
	pid        int
	ticks      uint64
	before     fileID
	beforeOK   bool
	opened     fileID
	after      fileID
	afterPID   int
	afterTicks uint64
	afterOK    bool
}

func stableIdentity(c identityCheck) bool {
	return c.beforeOK && c.afterOK && c.opened.dev != 0 &&
		c.before == c.opened && c.opened == c.after &&
		c.afterPID == c.pid && c.afterTicks == c.ticks
}

func copyImage(src string, dir *os.File, name string, max int64) (*Hash, string, string, fileID) {
	in, info, err := safeio.OpenRegularFollow(src)
	if err != nil {
		return nil, "", "image: " + err.Error(), fileID{}
	}
	defer in.Close()
	openedID, ok := fileIDs(info)
	if !ok {
		return nil, "", "image: opened executable identity is unavailable", fileID{}
	}
	size := info.Size()
	out, err := createAt(dir, name)
	if err != nil {
		return nil, "", "image create: " + err.Error(), openedID
	}
	defer out.Close()
	h := sha256.New()
	n, err := io.Copy(out, io.TeeReader(io.LimitReader(in, max), h))
	if err != nil {
		return nil, name, "image read: " + err.Error(), openedID
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
		return nil, name, "image sync: " + err.Error(), openedID
	}
	return &Hash{
		Algorithm: "sha256",
		Scope:     scope,
		Bytes:     n,
		Size:      size,
		Digest:    hex.EncodeToString(h.Sum(nil)),
	}, name, "", openedID
}

func readLoaderEnv(base string, man *Manifest) map[string]string {
	b, truncated, err := readCapped(filepath.Join(base, "environ"), maxEnviron)
	if err != nil {
		man.Failures = append(man.Failures, "environ: "+err.Error())
		return nil
	}
	if truncated {
		man.Failures = append(man.Failures, "environ exceeds 1 MiB; loader variables past the cap were not seen")
		if i := bytes.LastIndexByte(b, 0); i >= 0 {
			b = b[:i+1]
		} else {
			b = nil
		}
	}
	preload, audit, library := procfs.InterestingEnv(b)
	env := map[string]string{}
	for k, v := range map[string]string{"LD_PRELOAD": preload, "LD_AUDIT": audit, "LD_LIBRARY_PATH": library} {
		if v != "" {
			env[k] = v
		}
	}
	if len(env) == 0 {
		return nil
	}
	return env
}

func readNamespaces(dir string, man *Manifest) map[string]string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		man.Failures = append(man.Failures, "ns: "+err.Error())
		return nil
	}
	if len(entries) > maxNamespaces {
		entries = entries[:maxNamespaces]
		man.Failures = append(man.Failures, "namespace list truncated at 32")
	}
	out := map[string]string{}
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil {
			out[e.Name()] = target
		}
	}
	return out
}

func readFDs(dir, proc string) (fds, sockets, failures []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{"fd: " + err.Error()}, nil, nil
	}
	sort.Slice(entries, func(i, j int) bool {
		a, ae := strconv.Atoi(entries[i].Name())
		b, be := strconv.Atoi(entries[j].Name())
		if ae == nil && be == nil {
			return a < b
		}
		return entries[i].Name() < entries[j].Name()
	})
	if len(entries) > maxDescriptors {
		entries = entries[:maxDescriptors]
		fds = append(fds, fmt.Sprintf("descriptor list truncated at %d", maxDescriptors))
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
		return fds, sockets, nil
	}
	// The target's own namespace tables: /proc/<pid>/net, not the scanner's.
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6", "raw", "raw6", "packet"} {
		path := filepath.Join(proc, "net", name)
		body, truncated, err := readCapped(path, maxSocketTable)
		if err != nil {
			failures = append(failures, "net/"+name+": "+err.Error())
			continue
		}
		if truncated {
			failures = append(failures, "net/"+name+" truncated at 32 MiB")
			if i := bytes.LastIndexByte(body, '\n'); i >= 0 {
				body = body[:i+1]
			}
		}
		var rows []model.Socket
		if name == "packet" {
			rows, _ = procfs.ParsePacket(string(body))
		} else {
			rows = procfs.ParseNet(name, string(body))
		}
		for _, sock := range rows {
			if _, ok := inodes[sock.Inode]; ok {
				sockets = append(sockets, fmt.Sprintf("%s %s %s -> %s inode %d", sock.Proto, sock.State, sock.Local, sock.Remote, sock.Inode))
			}
		}
	}
	return fds, sockets, failures
}

// readCapped reads at most max bytes without blocking on a FIFO, and reports
// whether the file was longer.
func readCapped(path string, max int) ([]byte, bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

func recheck(base string) (ticks uint64, id fileID, pid int, ok bool) {
	b, _, err := readCapped(filepath.Join(base, "status"), maxSmallFile)
	if err != nil {
		return 0, fileID{}, 0, false
	}
	st, err := procfs.ParseStatus(string(b))
	if err != nil {
		return 0, fileID{}, 0, false
	}
	body, truncated, err := readCapped(filepath.Join(base, "stat"), maxSmallFile)
	if err != nil || truncated {
		return 0, fileID{}, st.PID, false
	}
	ticks, ticksOK := procfs.ParseStartTicks(string(body))
	id, idOK := statExe(filepath.Join(base, "exe"))
	if !ticksOK || !idOK {
		return ticks, id, st.PID, false
	}
	return ticks, id, st.PID, true
}

func statExe(path string) (fileID, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return fileID{}, false
	}
	id, ok := fileIDs(info)
	return id, ok && id.dev != 0
}

func readLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return target
}

func readTrim(path string) string {
	b, _, err := readCapped(path, 4096)
	if err != nil {
		return ""
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return string(b)
}
