# First scan with ProcSift

This guide covers a standard scan, the first report, focused follow-up, and JSON comparison. Commands below use `./bin/procsift` from the source checkout. If you downloaded the standalone binary, use `./procsift` instead. The full command reference is available with `./procsift help` or `./bin/procsift help`.

## 1. Know what will happen

A normal ProcSift scan **reads** kernel-published process, memory-map, socket, and module information. It does not stop processes, repair files, or contact the addresses it finds. It does not prove a host is clean.

If you use `-o`, ProcSift writes the report to the path you give it. If you use `capture`, it also writes a bundle containing one process's open executable and related evidence.

Use a binary built for the host's architecture. For the current source checkout, rebuild with Go 1.22 or newer so the executable matches the source:

```sh
make build
./bin/procsift version
```

## 2. Run the first scan

Root can read more of `/proc` than an ordinary user. Use a new output path for each scan; ProcSift refuses to overwrite any existing path.

```sh
sudo install -d -m 0700 /var/tmp/procsift-case
sudo ./bin/procsift -json -o /var/tmp/procsift-case/first.json
```

The directory and report are written on the scanned host. To leave no report file there, omit `-o` and collect standard output through the chosen evidence channel. A shell redirect uses the shell's file permissions rather than ProcSift's mode `0600` report creation.

The command can return `1` and still have written a valid report. That code means a finding met the selected threshold. A return of `2` means the scan or report write failed; read stderr and check whether a partial report was written.

To read a short text report on screen:

```sh
sudo ./bin/procsift
```

## 3. Read the first screen

Start with these lines:

```text
Host result   fail
Exit reason   PROC-DELETED-EXE pid 4242
Host findings high 1  medium 2  low 5  info 0
Scanner self  high 2  medium 0  low 1  info 0
All findings  high 3  medium 2  low 6  info 0  (raw total, not the exit count)
```

The **host result** applies to host findings. **Scanner self** contains findings caused by ProcSift's own process; an in-memory launch can create deleted-image and memfd findings. The raw total includes both.

**Attention** orders follow-up subjects and gives reasons and alternatives. **Findings** contains the underlying observations. **Collection coverage** identifies incomplete reads that limit an interpretation.

## 4. Follow up on one process

Suppose the report highlights PID `4242`. That number is an example; use the PID in your own report. A process may exit or a PID may be reused, so compare its start time and executable identity across reads.

```sh
sudo ./bin/procsift -pid 4242
```

This narrows the **process census** to that PID and up to eight parents. Selected host-level file checks and socket reads still run. It is a useful closer look, not a strict one-process-only mode.

If the executable has been deleted and your evidence procedure permits a local bundle, preserve it before the process exits:

```sh
sudo ./bin/procsift capture -pid 4242 -o /var/tmp/procsift-case/pid-4242
```

The directory must be new. The bundle's `manifest.json` says whether the executable hash covers the entire file or only a capped prefix. ProcSift does not execute its contents.

## 5. Interpret common findings carefully

| What you see | Useful first question |
| --- | --- |
| `PROC-DELETED-EXE` or `MEM-DELETED-EXEC` | Is this the same process instance, and is there package-transaction evidence for an ordinary replacement? The finding stays visible even if maintenance is corroborated. |
| `FILE-PKG-MISMATCH` | Which on-disk file differs from the local package manifest? Do not run the suspect utility to check it. The local manifest may also have been changed. |
| `PROC-FILE-MATCH` | Does a running image have the **same full hash** as a changed utility? This links bytes, not intent or installation history. |
| `PROC-PKG-OTHER-SOURCE` | Is the process on an observed Snap mount? That explains why dpkg does not list it; it does not verify the Snap image. |
| `PROC-CONTEXT-DISGUISE` | Which path, command title, package, and service facts disagree? A familiar name by itself is not enough. |
| A coverage entry marked `denied`, `truncated`, or `unavailable` | Which conclusion depends on the missing read? Keep that limit in the case notes. |

A deleted executable hash capped at 4 MiB is marked `scope prefix`. Do not compare it as if it were a full-file SHA-256. `maintenance corroborated` requires a package transaction and a replacement file matching the local manifest; a newer timestamp alone is not enough.

## 6. Take a second snapshot if it helps

A second report can show whether a process or connection appeared later:

```sh
sudo ./bin/procsift -json -o /var/tmp/procsift-case/second.json
sudo ./bin/procsift diff -old /var/tmp/procsift-case/first.json -new /var/tmp/procsift-case/second.json
```

`diff` accepts reports from the same host and boot when privileges, scan options, manifest contents, and minimum severity match. It excludes the scanner's own process and reports one-snapshot process and socket changes as observations. A new medium or high finding is host evidence. Different hosts, boots, or scan settings return `2`. Reports without recorded scan options cannot be compared. The output describes changed evidence, not its cause.

A bounded PID sweep is optional. It probes PID numbers but cannot prove that a rootkit is absent:

```sh
sudo ./bin/procsift -sweep -sweep-max-probes 32768 -sweep-timeout 3s
```

Use `-deep` only when you need its extra comparison. It checks the first 16 bytes of a few executable mappings against their backing files; it cannot find patches farther into a function. Ordinary runtimes and debuggers can differ. The normal scan leaves it off.

## 7. Compare process identity

Boot ID, PID, start ticks, and executable inode identify a process instance more reliably than PID alone. The report also records scan time, version, and incomplete reads. Keep the command, binary hash, exit code, and report hash with the scan when comparing runs. For collection scope and limits, see [README.md](README.md).
