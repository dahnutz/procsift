# ProcSift design

ProcSift is a bounded live triage scanner for Linux. It combines process, memory-map, socket, module, startup, and package observations into a text or JSON report. The scan does not acquire physical memory or modify the processes it inspects.

For commands, see [README.md](README.md) and [FIRST_SCAN.md](FIRST_SCAN.md). [ROADMAP.md](ROADMAP.md) lists version changes and remaining work.

Copyright © 2026 Daniel Hanganu. [MIT licensed](LICENSE).

## Data sources

ProcSift reads Linux interfaces directly. It does not depend on `ps`, `ss`, `netstat`, or `lsof` to describe the host.

| Source | Used for |
| --- | --- |
| `/proc/<pid>` | Process identity, executable link, mapped regions, descriptors, parent chain, and service cgroup |
| `/proc/net` and socket descriptors | Socket inventory and process ownership by inode |
| `/proc/modules` and `/sys/module` | Loaded-module cross-check |
| `/proc/sysvipc/shm` and `/dev/shm` | Shared-memory inventory |
| Startup files and generated systemd units | Configuration references to selected processes |
| Local package records | Ownership and manifest comparisons for selected images and utilities |

A bounded 16-byte read of an anonymous executable mapping can identify an ELF, PE, or script header. `-no-magic` disables that read. The default scan does not sweep PID space or compare mapped page bytes with backing files.

These interfaces define the tool's visibility. Restricted `/proc` mounts, namespaces, permissions, process churn, and kernel-level concealment can all limit the result. Coverage entries describe incomplete reads instead of treating them as clean checks.

## Findings and explanations

Rules describe observations. A deleted executable remains a high finding even when package-transaction evidence supports an ordinary update. Its hash is marked `full` only when every byte was read; a capped 4 MiB read is a `prefix` hash.

Package checks use local references. A dpkg record is not an independent clean baseline. A Snap squashfs mount explains why dpkg may not list an executable, but does not verify the mounted image. An operator-supplied `-manifest` file is used for the paths it names; ProcSift does not authenticate that file. RPM ownership is not parsed in 0.5.1.

Process context is kept separate from proof of launch. A cgroup records service membership, a unit or startup file records configuration, and the scanner does not read the journal. Socket ownership is joined by inode. An unmatched socket is not automatically a hidden process.

The Attention list orders at most five subjects using fixed weights on findings. Each row gives its reasons and alternatives. The score is an ordering aid, not a probability or compromise verdict.

## Optional operations

- `-pid N` narrows the process census to one PID and at most eight parents. Selected host file, socket, module, shared-memory, and host-signal checks still run; the report states that scope.
- `-sweep` probes PID numbers with `kill(pid, 0)` within a count and time budget. It sends no signal and cannot prove that a kernel-level rootkit is absent.
- `-deep` compares at most 16 bytes from selected executable pages with the exact `map_files` backing inode. Process identity and the mapped inode are checked before and after the read. Missing or changed backing is a coverage limit, not a mismatch.
- `capture -pid` writes a new local directory containing one process's open executable and related metadata. The manifest records complete versus prefix hash scope. Captured bytes are not executed.
- `diff` accepts two JSON reports from the same host and boot. Scanner-origin changes are excluded. Process and socket changes seen in only one snapshot are observations; a new medium or high finding counts as host evidence. Different hosts or boots are refused. A diff describes changed evidence, not its cause.

## Output and release checks

Text begins with the host result and exit reason, followed by host counts, scanner-self counts, the raw total, Attention, findings, coverage, and limits. A scanner launched from a memfd can flag itself; those findings stay in the raw report and do not fail the host by default. `-fail-on-self` includes them in the exit decision.

`-o` creates a new file with mode `0600` and refuses existing paths. Command-line arguments that resemble credentials are redacted. Reports can still contain operational details, including paths and network addresses. `capture` writes a separate bundle and requires a new destination directory.

The Go module path is `github.com/dahnutz/procsift`. Local builds do not require the GitHub repository to exist. `make build` creates the Linux binary with CGO disabled and VCS stamping disabled, so the same files build to the same binary after export without `.git`. `make verify-binary` rebuilds with the current toolchain and compares the result with `bin/procsift`. `make release-check` requires a clean checkout and Go 1.27.1, runs tests, and verifies the binary. It is intended for use after the source, documentation, and binary have been committed together.

## Remaining limits

RPM ownership is unavailable until an RPM database reader is implemented. The normal scan does not read the journal, walk raw physical memory, or replay a captured `/proc` tree. The optional page comparison reads short headers; it is not a full memory-versus-disk analysis. Two snapshots cannot explain every short-lived connection or process. Ordinary-host and benign-update validation remain useful before making performance or false-positive claims.
