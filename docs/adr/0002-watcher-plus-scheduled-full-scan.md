# ADR 0002: A real-time watcher plus scheduled full scans, not one or the other

- **Status:** Accepted (M1)

## Context

Real-time watching (inotify) gives low latency but has known gaps: nothing is seen while the
monitor is not running, the kernel drops events when its queue overflows (`IN_Q_OVERFLOW`), a
new directory can receive files before a watch is added to it, and changes made through another
path to the same file (bind mounts, other mount namespaces) are not reported for the watched
path. Scheduled full scans (the AIDE model) have none of these gaps, but a change is found only
at the next scan.

## Decision

Run both. The monitor does a full scan (hashing every covered file) at startup, on every
`--rescan-every` interval and on every queue overflow. Between scans, the watcher's events only
say *which paths to re-read*; the verdict always comes from hashing and comparing with the
baseline, never from the event type. A new directory is walked as soon as it is reported. Each
difference state is alerted once, whichever path found it first, and the alert records which
one did (`startup-scan`, `inotify`, `poll`, `scheduled-scan`, `overflow-scan`).

On machines without inotify (the author's Windows machine, macOS) a polling watcher compares
cheap `lstat` keys instead. It cannot see a same-size change whose mtime was restored; the test
`test_full_scan_catches_a_change_with_size_and_mtime_restored` shows the full scan catching it.

## Consequences

- Detection does not depend on the watcher being perfect; the worst case is the scan interval.
- Full scans cost I/O proportional to the covered data; the interval is a flag, and the default
  policy covers binaries one level deep, not whole trees such as `/usr/lib`.
- One watch per covered directory and per pattern ancestor; very large policies can hit
  `fs.inotify.max_user_watches`, which stops the watcher with a clear error (fanotify is the
  alternative noted in RFC 0001).
- The real inotify path is tested only in CI (Linux); locally only event decoding and path
  mapping are tested.
