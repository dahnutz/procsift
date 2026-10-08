# ProcSift roadmap

This file records shipped behavior and open work. Rule names identify observations; they do not label a process as malicious. The command was `ramtriage` through 0.4.0 and `procsift` from 0.5.0 onward.

For usage, see [README.md](README.md) and [FIRST_SCAN.md](FIRST_SCAN.md). [PROPOSAL.md](PROPOSAL.md) describes the collection and report model.

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

### Later

- Add an offline replay format for captured `/proc` evidence. JSON `diff` compares reports; it does not rerun the scanner against a captured tree.
- Validate routine package updates and false-positive behavior on ordinary hosts before publishing performance or detection-rate claims.
- Consider stronger correlation across several snapshots for short-lived processes and sockets. A two-report diff can show a change but cannot establish its cause.

Raw physical-memory acquisition, credential collection, and automatic remediation remain outside ProcSift's scope.
