# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/file-integrity-monitor/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** a tampered baseline that still verifies; a covered change that is not reported
  (by the watcher and by the full scan); reads that follow a symlink or leave the `--root` tree;
  anything that makes the monitor write to a watched tree; a crafted file name or event buffer
  that crashes the monitor.
- **Out of scope:** an attacker who already has root and also holds the HMAC key (see the
  limits in the README), and bugs in the Linux kernel's inotify itself (report those upstream).

## How this repository protects itself

- The monitor only reads watched trees: files are opened read-only with `O_NOFOLLOW`, only after
  `lstat` shows a regular file, and the open file must be the one that was `lstat`-ed.
- Baselines are sealed (SHA-256, or HMAC-SHA256 with `--key-file`); a keyed baseline is never
  accepted with a plain digest.
- Every GitHub Action is pinned to a full commit SHA, and workflows run with read-only
  permissions and without persisted credentials.
- Dependabot update pull requests are paused (`open-pull-requests-limit: 0`) so the repository keeps a single `main` branch; dependencies are updated by hand and checked by the CI audit.
- CI runs lint, strict types, tests and a known-vulnerability check (pip-audit) on every push and pull request.
