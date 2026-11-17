# RFC 0001: file-integrity-monitor design

- **Status:** Accepted for M1 (M2 and M3 sections are plans)
- **Author:** EquinoxWN
- **Created:** 2026-11-17

## Problem

An attacker who gets onto a Linux server usually leaves something behind: an extra key in
`authorized_keys`, a cron job, a replaced binary, a setuid bit, an edited `/etc/passwd`. Without
something comparing those files with a known-good state, such changes can go unnoticed for
months. The usual tools either scan once a day (a long window, and they say nothing about what
happened in between) or watch events in real time and miss changes made while the watcher was
down or when the kernel drops events. A second problem (M2) is noise: package updates change
hundreds of binaries, and a monitor that alerts on each one is soon ignored.

**Users:** Linux administrators and security engineers who look after a handful to a few hundred
servers and want to know quickly when a critical file changes.

**Critical-to-quality measures (Define):**

| CTQ | Target | M1 status |
|---|---|---|
| Simulated tampering detected (new SSH key, modified binary, new cron job, setuid bit, owner change, new user key) | 100 % by both the full scan and the live watcher | measured on the fixture host (docs/results/m1.md) |
| Live detection latency with the portable polling backend at 0.1 s | under 1 s | measured locally: max 149 to 150 ms in two runs, 1021 ms in one run under heavy parallel load |
| Live detection latency with inotify | under 1 s | CI only, not run yet |
| Duplicate alerts for one unchanged state, including after a restart | 0 | tested |
| Baseline edits that still verify | 0 | tested (seal and HMAC) |
| False alerts during normal package updates | under 1 % of updates | M2, not measured |

## Goals

- M1: a baseline records SHA-256, mode, owner and group of critical files (binaries, configuration,
  cron, SSH keys), sealed so that edits to it are detected.
- M1: inotify watches those paths in real time; scheduled full scans catch anything the watcher
  missed (changes while the monitor was down, dropped events, content changed with size and
  mtime restored).
- M2: changes are checked against the package manager (dpkg / rpm) so legitimate updates are not
  flagged; auditd records which user and process made each change.
- M3: alerts show a diff for text files, approved changes update the baseline, and a lab
  simulates intrusions and measures the false-alert rate during package updates.

## Non-goals

- Running as a hosted production service, or a central server for many hosts.
- Protecting against an attacker who already has root **and** the HMAC key (see Risks).
- Preventing changes. The monitor only reads and reports.
- Kernel-level tamper resistance (IMA/EVM, fs-verity) is out of scope; it is a different layer.

## Design (M1)

```
policy (TOML) ──> Tree.walk ──> Tree.entry (lstat, open O_NOFOLLOW, SHA-256)
                                      │
             baseline.json <── seal ──┘   (sha256 or hmac-sha256)
                                      │
watcher (inotify | poll) ──paths──> Monitor.check_paths ──┐
scheduled / overflow / startup ───> Monitor.full_scan  ───┴─> compare_one ─> AlertLog (JSONL)
```

- **Policy.** TOML, parsed with the standard library `tomllib`, validated strictly (unknown keys,
  relative paths, `..`, control characters and watching `/` are rejected). Each group has a
  severity, path patterns (globs per component, e.g. `/home/*/.ssh`), `recursive` and file-name
  excludes. A path belongs to the most severe group that covers it. The bundled policy covers
  SSH keys, accounts and sudoers, cron and systemd units, binaries and selected configuration.
- **Tree.** A read-only view of `/` or of a fixture directory standing in for it. Symlinks are
  recorded with their target and never followed or descended. A file is opened only after
  `lstat` reports a regular file (FIFOs and devices are never opened), with `O_NOFOLLOW` and
  `O_NONBLOCK`, and the opened file's device and inode must match the `lstat`. Directories that
  cannot be listed are reported as entries with an error, not skipped. A fixture tree may carry
  `.fim-meta/stat.tsv` (mode, uid, gid per path) because a Windows checkout cannot hold Linux
  modes and owners. Off Linux the root must be a fixture directory, never a drive root.
- **Baseline.** JSON with the policy, every entry and a seal over the canonical form: SHA-256 by
  default, HMAC-SHA256 with `--key-file`. A keyed baseline is never accepted with a plain digest
  (no downgrade). Written atomically (temp file, fsync, rename).
- **Compare.** Per path: added, removed, type, content, link target, mode, owner, unreadable.
  Severity comes from the group and is raised to critical when a setuid, setgid or
  world-writable bit appears.
- **Watchers.** `InotifyWatcher` (ctypes, no dependency) watches covered directories and the
  existing ancestors of each pattern, so a new `/home/eve/.ssh` is followed; a new directory
  triggers new watches and a walk of the directory (files created before the watch was added are
  still seen); `IN_Q_OVERFLOW` triggers a full scan. `PollingWatcher` compares cheap `lstat` keys
  and works everywhere; it is what runs on the author's Windows machine.
- **Monitor.** A full scan at startup, the watcher's paths re-read and compared as they arrive,
  a full scan every `--rescan-every` seconds and on overflow. Each difference state is alerted
  once; when a path matches the baseline again a `resolved` record is written. The alert log is
  replayed at startup, so a restart does not repeat alerts for states still open.

## Alternatives considered

| Option | Why not (for M1) |
|---|---|
| **AIDE-style scheduled scans only** | Simple and robust, but a change is found only at the next run (often daily), and nothing says when it happened. M1 keeps the full scan as the safety net and adds the live watcher. |
| **inotify only** | Low latency, but misses changes made while the monitor is down, drops events on queue overflow, and cannot see changes made through another mount namespace. The scheduled full scan covers those gaps. |
| **fanotify** | Can watch whole mounts without one watch per directory, but needs `CAP_SYS_ADMIN`, and its useful modes for this (FAN_REPORT_DFID_NAME) need kernel 5.9+. Kept as an option if watch counts become a problem. |
| **auditd file watches only** | Gives the user and process (planned for M2 as context), but does not give content hashes or a baseline to compare with, and its rules are global system configuration. |
| **watchdog (Python library)** | Wraps inotify, but adds a dependency and hides overflow handling; the inotify part needed here is about 150 lines with ctypes. |
| **SQLite baseline** | Fast lookups for very large trees, but a sealed JSON file is easier to review, copy off the host and verify; M1 trees are thousands of files, not millions. |

## Measurement plan (Measure)

- **Detection:** the fixture host is copied under `.tmp/`, baselined, then six intrusion steps are
  applied (new key for root, modified `sshd`, new cron file, setuid on `ls`, a new user with a
  key, owner change on `/etc/shadow`). The full scan must report exactly those paths with the
  expected kinds and severities (`test_scan_finds_exactly_the_simulated_tampering`).
- **Latency:** `scripts/demo.py` applies the same steps while the monitor runs and records the time
  from each change to its alert with `time.monotonic` (poll backend locally; inotify in CI).
- **Blind spots:** a same-size change with the mtime restored is shown to be missed by the
  polling watcher and caught by the full scan (`test_full_scan_catches_a_change_with_size_and_mtime_restored`).
- **M2/M3:** false-alert rate over real `apt upgrade` / `dnf update` runs, lab detection rate.

## Milestones

- **M1:** a sealed baseline of hashes, permissions and owners of critical files; inotify watches
  those paths in real time; scheduled full scans catch anything missed.
- **M2:** changes are checked against the package manager, so legitimate updates are not flagged;
  auditd records which user and process made each change.
- **M3:** alerts show a diff for text files and approved changes update the baseline; a lab
  simulates unauthorized changes and the false-alert rate during package updates is published.

## Risks and open questions

- **Root attacker.** Someone with root can stop the monitor, edit the baseline and the alert log.
  The HMAC seal helps only if the key is not on the host (for example, the baseline is verified
  from another machine). Shipping alerts off the host is an M2/M3 topic.
- **Watch limits.** Large recursive groups can exceed `fs.inotify.max_user_watches`; the watcher
  stops with a clear error rather than silently watching less, and the full scan still runs.
- **Mount namespaces and bind mounts:** inotify does not see changes made through another path
  to the same inode; the full scan does.
- **Unreadable files** (no permission) are reported as `unreadable`, not as unchanged.
- **Package updates (M2):** until M2 every update of a covered file is an alert.
