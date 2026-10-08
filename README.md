# ProcSift

**Fast live Linux incident triage.**

ProcSift is a standalone utility for live Linux incident triage. It reads process, memory-map, socket, module, startup, and package context from kernel-published views and produces a prioritized text or JSON report.

It is a first pass, not a compromise verdict. It does not acquire physical RAM, run recovered files, contact observed network endpoints, or fix the host. A rootkit that controls the kernel views it reads can still hide from it.

ProcSift was called `ramtriage` through version 0.4.0. Version 0.5.0 introduced the `procsift` command and report name; 0.5.1 hardens comparison and release checks. There is no old-name compatibility command.

Copyright © 2026 Daniel Hanganu. [MIT licensed](LICENSE).

## Download and run

For Linux x86-64, download the executable directly once this repository is published:

```sh
wget -q https://raw.githubusercontent.com/dahnutz/procsift/main/bin/procsift
chmod +x procsift
sudo ./procsift
```

No Go installation or repository checkout is needed for this path. The command above prints a text report on screen. To save JSON, use `sudo ./procsift -json -o /tmp/procsift-first.json` with a new filename for each run.

If you have checked out the source, build it with Go 1.22 or newer:

```sh
make build
./bin/procsift version
```

Run a first scan as root for the fullest view. Choose a **new** report filename for each run:

```sh
sudo ./bin/procsift -json -o /tmp/procsift-first.json
```

The scan may exit with code `1` because it found something to investigate. That does not mean the report failed to write. The file is created with mode `0600` and will usually be owned by root. For a readable report on screen, run `sudo ./bin/procsift` without `-json` or `-o`.

For the commands, a walkthrough, and examples of what to do with a finding, see [First scan guide](FIRST_SCAN.md).

## Report contents

- **Host result and counts:** Host findings and findings caused by ProcSift's own process are counted separately. The Attention list orders up to five subjects for follow-up; its score is not a malware score.
- **Findings:** Each rule names the process or file and gives the observations behind it. Deleted executables, changed utilities, and unusual process context appear as separate findings.
- **Explanations:** Package-update evidence and observed Snap mounts appear alongside the original finding. A local package database is a reference, not independent proof of file integrity.
- **Coverage and limits:** Denied, truncated, and unavailable reads are recorded. An incomplete check does not become a clean result.

The default scan is bounded and does not probe every possible PID. It reads a small header from selected executable mappings; `-no-magic` disables that read. The optional `-deep` comparison reads a few executable page headers and is off by default. The optional `-sweep` probes PID numbers with `kill(pid, 0)` within a time and count limit.

## Commands you will use most

```sh
# A concise text report on screen
sudo ./bin/procsift

# A JSON report; the path must not exist yet
sudo ./bin/procsift -json -o /tmp/procsift-second.json

# Focus the process census on one PID and up to eight parents
sudo ./bin/procsift -pid 4242

# Preserve one open executable and its related process evidence
sudo ./bin/procsift capture -pid 4242 -o /tmp/procsift-capture-4242

# Compare two JSON reports; interpret the output carefully
sudo ./bin/procsift diff -old /tmp/procsift-first.json -new /tmp/procsift-second.json
```

`-pid` narrows the process census. It still performs selected host-level file checks and socket reads; it is not a strict single-process scan. `capture` creates a new local directory and copies evidence from the selected process. It never executes that copy. An existing destination is rejected.

`diff` compares reports from the same host and boot. Scanner-created processes are excluded; one-snapshot processes and sockets are shown as observations. A new medium or high finding counts as host evidence. Different boots or hosts return exit code `2`. The command reports differences between snapshots; it does not determine why they occurred.

| Scan exit code | Meaning |
| --- | --- |
| `0` | No host finding met `-fail-on` (default: medium). It does not certify a clean host. |
| `1` | A host finding met the threshold, or a scanner finding did when `-fail-on-self` was selected. The report can still be complete. |
| `2` | The scan or report write failed. Read stderr and check whether a partial private output remains. |

## Report excerpt

```text
Host result   fail
Exit reason   PROC-DELETED-EXE pid 4242
Host findings high 1  medium 0  low 0  info 0
Scanner self  high 0  medium 0  low 0  info 0

[HIGH] PROC-DELETED-EXE  pid 4242  worker
  executable was deleted and is still running; unlinked; unexplained
  - exe /var/tmp/example/worker (deleted)
  - sha256 <example> truncated scope prefix bytes 4194304
```

Here the file is gone from its old path, but the process is still running. The hash covers only the first 4 MiB, so it is a **prefix**, not a full-file hash. `Unexplained` describes the available file and package evidence; it does not establish who put the process there. A legitimate program can also keep a deleted old image after an update. Follow up on the process identity, service, sockets, and preserved evidence before drawing a conclusion.

The report may also show high findings for ProcSift itself when it was launched from an anonymous `memfd`. They remain visible as `scanner_self` and do not affect the default host exit decision. Another process with the same name is not automatically treated as the scanner.

## Scope and privacy

ProcSift inventories processes, threads, mapped files, anonymous executable memory, shared memory, kernel modules, sockets, selected startup files, and package context. The `-deep` option can compare short executable page headers with their backing files. The scanner does not dump a process's memory. `capture -pid` can copy the selected process's **open executable** into a private local bundle, with a manifest that says whether the copy is complete or capped.

Reports can contain usernames, paths, command lines, and network addresses. Arguments that look like passwords, tokens, or keys are redacted. Redaction is best-effort; report files use mode `0600` when written with `-o`.

The local dpkg database is used as a reference, not as a trusted clean baseline. A Snap squashfs mount explains why dpkg may not list a process; it does not verify that Snap image. RPM ownership is not parsed in 0.5.1. A supplied `-manifest` file is another local reference, not a signed or independently authenticated source.

For all flags, run `./bin/procsift help`. [ROADMAP.md](ROADMAP.md) records shipped behavior and known limits; [PROPOSAL.md](PROPOSAL.md) explains the design.
