# ProcSift roadmap

This file records implemented behavior and open work. Rule names identify observations; they do not label a process as malicious. The command was `ramtriage` through 0.4.0 and `procsift` from 0.5.0 onward.

For usage, see [README.md](README.md) and [FIRST_SCAN.md](FIRST_SCAN.md). [PROPOSAL.md](PROPOSAL.md) describes the collection and report model.

## Unreleased

- The text report shows control characters from process names, paths and command lines as `\xNN` or `\uNNNN` escapes, so host data cannot send terminal escape sequences. Newlines are kept for the report layout. JSON output is unchanged.
- The `-manifest` file, `/proc/<pid>/exe` images and `/dev/shm` entries are opened without blocking and must be regular files. A FIFO or device passed as `-manifest` no longer hangs the scan. Symlinks are still refused in `/dev/shm` and followed for the operator's manifest and for magic links.
- `NET-RAW-SOCKET` says when a packet socket captures all protocols (`ETH_P_ALL`). It becomes medium when such a socket has no owner in a complete descriptor census. When the census is incomplete or the scan uses `-pid`, it stays low and says the owner is unknown.
- Every socket table shares one 32 MiB read cap and a 65536-row cap per table. A large TCP inventory no longer pushes raw and packet sockets out of the scan. A table with rows that cannot be parsed is reported as unrecognized instead of read as empty.
- Late-thread checks stop reading once eight late threads are recorded, and a thread that exits during the walk is not reported as a coverage gap.
- A process environment over the 1 MiB read cap produces `PROC-ENV-OVERSIZE` (low): the loader-variable check is inconclusive because a variable can sit past the cap. Memory findings from a process whose `maps` exceeded 8 MiB say the region list is partial.
- Command-line redaction also hides the token after `Bearer`, `Basic`, `Token` or `Digest`, credential headers such as `X-Api-Key:` or `--header=Authorization:`, `curl -u` passwords, and token-like URL user names. URL passwords are hidden up to the last `@`, and the URL user is kept.
- `HOST-LD-PRELOAD` records the file's size, mode, owner, and time, and the package, location, and mode of each listed library. It becomes high when a library is in a temporary path, world-writable, or exists but no dpkg package lists it; a missing library stays medium. The parser's glibc behavior is checked against glibc 2.42 `elf/rtld.c`.
- `capture` keeps the image only when the executable path before the read, the opened descriptor, and the path after the read agree. It records status, cgroup, namespace links, and loader variables (never the raw environment), lists up to 256 descriptors, adds raw, raw6, and packet sockets, and records unreadable tables. Every `/proc` read is capped, and bundle files are created through the directory descriptor with `O_EXCL|O_NOFOLLOW`.
- `/dev/shm` FIFOs, sockets, devices, and symlinks are listed by kind (`IPC-DEVSHM-SPECIAL`, low) without being opened, and the walk stops at 4096 entries. Startup and unit files are opened without blocking, and symlinks are refused in user unit directories, so a FIFO planted there can no longer stall a root scan.
- `diff` refuses reports made by different ProcSift versions, because rule coverage and severities change between releases. It is meant for comparing rescans made with the same binary; longer-term history belongs in the SIEM integration. The upgrade-only `new-rule` change kind is removed.

## 0.5.2 — collection and capture

- Packet sockets are parsed from `/proc/net/packet`. A truncated `/proc` read keeps its complete prefix rows or fields and records the missing tail in coverage.
- `ld.so.preload` is parsed using glibc's separators and comment syntax; listed entries or a truncated file produce a medium finding. Command-line redaction keeps bare `-p` ports visible and masks attached passwords, URL credentials, and authorization headers.
- Shared-memory files are opened without following symlinks or blocking on FIFOs. Capture reads the target process's network namespace, checks the opened executable identity, discards failed partial copies, and orders descriptors numerically.
- Reports record the scan options and supplied manifest hash. `diff` refuses mismatched scope, privilege, or severity, including older reports without scan options.
- `-deep` still compares only the first 16 bytes of selected executable mappings. A wider page comparison needs a separate design and test fixtures.

## 0.5.1 — comparison and release checks

- `diff` now requires the same host and boot, excludes scanner-created changes, and treats one-snapshot processes and sockets as observations. New medium or high findings and changed executable images count as host evidence. Input is capped at 64 MiB.
- `-deep` opens the exact `map_files` backing inode and rechecks process and mapping identity. Unavailable or changed backing becomes a coverage entry instead of a mismatch.
- Failed BPF, raw-socket, and RPM database reads are recorded. The focused scan's remaining host-wide checks are stated in help and in the report.
- The module path is `github.com/dahnutz/procsift`. Local manifests are labeled as supplied references rather than authenticated data.
- `make verify-binary` compares the executable with a current source build. VCS stamping is disabled so a source export without `.git` produces the same bytes. `make release-check` requires a clean checkout and the pinned Go toolchain, then runs tests and binary verification.

## 0.5.0 — ProcSift

The command, JSON `tool` value, and capture manifest use the ProcSift name. There is no old-name compatibility command.

- The report separates host findings, scanner-self findings, and raw totals. The exit reason names the first finding at the configured threshold.
- Startup coverage identifies files that were unreadable, capped, or skipped. Exact path matches remain visible.
- `-pid` narrows the process census. `-deep` optionally compares short executable page bytes with backing files and is off by default.
- A local `-manifest` file supplies hashes for selected paths. Its authenticity is not checked. dpkg and Snap mounts remain observed local context; RPM ownership is not parsed.
- `diff` first compares process identity, sockets, and findings across two JSON reports.
- New checks cover a shell with socket input and no known terminal, selected sensitive descriptors, late or unusually named threads, and mapped libraries that are temporary, deleted, or unlisted by package records.
- Host observations include `ld.so.preload`, raw and packet sockets, the cloud metadata address, pinned BPF names, and unprivileged BPF state.
- Selected process checks read network-namespace and `map_files` views. Missing and denied views remain coverage limits.

## 0.4.0 — idle files and source context

A bounded set of on-disk utilities is checked even when the commands are idle. `FILE-PKG-MISMATCH` is separate from a running-image finding. A full SHA-256 can link a running root image to a changed utility.

An observed Snap squashfs mount gives context to a dpkg-unlisted process; it does not verify the image. Scanner-self findings remain visible but do not fail the host by default. Attention ranking gives correlated images and changed files priority over plain package-source differences. Startup files are searched together and generated systemd units are read as configuration.

## 0.3.0 — package and process context

This release added bounded package checks for running root images, unpackaged-root and extra-uid-0 observations, and an unknown kernel-thread count when the kernel does not expose `Kthread`. The deleted-image maintenance label began requiring an applicable dpkg transaction and a current file matching the manifest. The original finding remains visible.

It also added scanner-self attribution, `capture -pid`, Attention ranking, and service/timer context. A cgroup and unit file do not prove a launch event; the journal is not read.

## 0.2.0 and earlier — core scan

The initial releases established bounded reads, explicit coverage failures, and exclusive report-file creation at mode `0600`. A deleted running executable receives a dossier with process identity, file identity, old-path relationship, and a hash marked full or prefix. Separate rules cover temporary executables, memfds, anonymous executable regions, module-view differences, shared memory, sockets, parent chains, and startup references.

## Open work

### Next: Wazuh integration — in testing

An hourly JSONL output and sample Wazuh configuration exist as a prototype. They are not part of this ProcSift build yet. The integration will keep the current scan and report behavior, add a local event log for the Wazuh agent, and test the manager rules with `wazuh-logtest` before release.

- Include scan status and collection gaps in each run's summary, and make failed or missing runs detectable.
- Distinguish new or changed findings from findings repeated by every hourly scan.
- Check safe log appends, rotation, and file permissions. Test host and scanner-self alerts against a Wazuh agent and manager.

### After Wazuh: RPM support — test host pending

Use the planned RPM test server to check database layouts, ownership, and file integrity against real packages. Keep reads bounded and report missing, denied, or unsupported RPM data as incomplete rather than clean. Add fixtures from the verified behavior before enabling RPM findings.

### Visibility and first-run triage

- Put scan visibility before the findings: scanner PID and mount, user, and network namespace identities; `/proc` mount restrictions such as `hidepid`; effective privileges; and counts of denied, truncated, and capped checks. State when the view is limited and recommend external or offline investigation when kernel concealment is plausible. The current report has EUID and individual coverage entries, but not this summary.
- Compare `/proc` process and thread lists with bounded cgroup v2 `cgroup.procs` and `cgroup.threads` reads where PID namespaces align. Recheck discrepant IDs and start times before reporting them; record inaccessible cgroups, exits, PID reuse, and moves between cgroups. The optional PID sweep remains a separate view.
- Add an optional, bounded lookback over existing journal or audit records for processes that exited before the scan. Report historical launches separately from live findings. Link a record to a live process only when boot, time, PID, and service evidence agree; missing or unreadable logs are a coverage limit, not evidence that nothing ran.
- Spend the current mapped-library budget first on authentication and other critical daemons, then on processes already carrying independent findings. Check unit `ExecStart`, package ownership, and preload context alongside unexpected libraries; state which processes or mappings were skipped by the budget.
- Compare `/proc/net` socket observations with bounded sock_diag queries in the same network namespace. Repeat discrepant reads to reduce churn noise and report namespace or permission limits. A disagreement is an investigation lead, not proof of a hidden socket.
- Extend the existing process-disguise finding with unit `ExecStart`, package owner, parent identity, and kernel-thread status. Increase priority only when independent identity fields disagree; a familiar process name alone is insufficient.
- Offer opt-in immediate preservation for selected high-priority live processes. Recheck PID, start time, and opened executable identity, cap copied bytes, and report failed or partial captures. Manual `capture -pid` remains available.
- Pair detection fixtures with ordinary cases: hidden-PID discrepancies, preload libraries, memfd impersonation, exited processes, and socket-view differences alongside updates, Snap, containers, JIT runtimes, and legitimate BPF agents. Check first-page ranking and coverage behavior, not just whether a rule fires.

### Broader first-run coverage

- Inventory persistence independently of running processes: selected systemd units and timers, cron, SSH keys and configuration, PAM, loader configuration, udev rules, shell startup files, and setuid files. Keep path and read budgets explicit. Package ownership, changes, and timestamps provide context; none alone proves a backdoor.
- Add Unix-domain sockets from `/proc/net/unix` and join their inodes to process descriptors. This would expose local listeners that the current IP and packet socket inventory misses.
- Inventory loaded eBPF programs and links by ID, including programs without pins. Record program type, attachment, ownership when available, and permission or kernel limits. An unrecognized program is an investigation lead, not proof of a rootkit.
- Read available tracefs or debugfs ftrace and kprobe registrations with bounded reads. Legitimate tracing and observability tools use these interfaces too; inaccessible views remain coverage limits.
- Add host or fleet baselines for recurring scans. Exceptions should have a reason and expiry, and the original finding should remain visible in the report. Add container and pod identifiers to process findings where cgroup evidence supports them.

### Later

- Provide direct downloads from tagged releases with SHA-256 sums and a verifiable signature.
- Correlate visible login sessions with process ancestry when session records are available. Missing or stale `utmp` and `wtmp` data must not imply that nobody logged in.
- Accept an offline, operator-supplied indicator list for hashes, paths, and addresses. Record the indicator source and hash scope; a match is a lead for investigation.
- Report kernel lockdown and module-signature settings as host context. A change in kernel taint requires an earlier measurement; one scan can only show its current value.
- Add an offline replay format for captured `/proc` evidence. JSON `diff` compares reports; it does not rerun the scanner against a captured tree.
- Validate routine package updates and false-positive behavior on ordinary hosts before publishing performance or detection-rate claims.
- Consider stronger correlation across several snapshots for short-lived processes and sockets. A two-report diff can show a change but cannot establish its cause.

Raw physical-memory acquisition, credential collection, and automatic remediation remain outside ProcSift's scope.
