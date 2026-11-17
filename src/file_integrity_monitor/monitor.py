"""Real-time monitoring: a watcher reports touched paths, scheduled full scans catch what it missed."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .baseline import Baseline
from .compare import Change, compare_one
from .inotify import Batch
from .policy import Policy
from .tree import Tree

MAX_ALERT_LOG_BYTES = 256 * 1024 * 1024


class Watcher(Protocol):
    """Anything that reports touched paths."""

    name: str

    def poll(self, timeout: float) -> Batch:
        """Wait up to `timeout` seconds and return what changed."""
        ...


class PollingWatcher:
    """Portable watcher: compares cheap lstat keys (no hashing) of every covered path."""

    name = "poll"

    def __init__(
        self,
        tree: Tree,
        policy: Policy,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Take the first snapshot."""
        self._tree = tree
        self._policy = policy
        self._sleep = sleep
        self._snap = self._snapshot()

    def _snapshot(self) -> dict[str, tuple[Any, ...]]:
        """Quick keys for every covered path and every directory that may hold one."""
        paths, _ = self._tree.walk(self._policy)
        snap: dict[str, tuple[Any, ...]] = {}
        for path in paths:
            key = self._tree.quick(path)
            if key is not None:
                snap[path] = key
        return snap

    def poll(self, timeout: float) -> Batch:
        """Sleep, then report paths whose key appeared, vanished or changed."""
        if timeout > 0:
            self._sleep(timeout)
        new = self._snapshot()
        changed = {p for p in set(self._snap) | set(new) if self._snap.get(p) != new.get(p)}
        self._snap = new
        return Batch(frozenset(changed))


@dataclass(frozen=True)
class Alert:
    """One emitted alert."""

    at: str
    source: str
    change: Change

    def to_dict(self) -> dict[str, Any]:
        """JSON-lines form."""
        head = {"type": "alert", "id": self.change.state_id(), "at": self.at, "source": self.source}
        return head | self.change.to_dict()


class AlertLog:
    """Append-only JSON-lines log of alerts and resolutions.

    Replaying it gives the differences still open, so a restarted monitor does not alert
    twice for a state it already reported.
    """

    def __init__(self, path: str | None) -> None:
        """Open (or create) the log and replay it."""
        self.path = path
        self.open: dict[str, str] = {}
        if path is None or not Path(path).exists():
            return
        p = Path(path)
        if p.stat().st_size > MAX_ALERT_LOG_BYTES:
            raise ValueError(f"{path}: alert log is larger than {MAX_ALERT_LOG_BYTES} bytes")
        for number, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                kind, target = record["type"], str(record["path"])
                if kind == "alert":
                    self.open[target] = str(record["id"])
                elif kind == "resolved":
                    self.open.pop(target, None)
                else:
                    raise KeyError(kind)
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                raise ValueError(f"{path} line {number}: not an alert log record") from exc

    def _append(self, record: dict[str, Any]) -> None:
        """Append one record with a single write, then fsync."""
        if self.path is None:
            return
        line = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)

    def write_alert(self, alert: Alert) -> None:
        """Log an alert and mark its path open."""
        record = alert.to_dict()
        self._append(record)
        self.open[alert.change.path] = record["id"]

    def write_resolved(self, path: str, at: str, source: str) -> None:
        """Log that a path matches the baseline again."""
        self._append({"type": "resolved", "path": path, "at": at, "source": source})
        self.open.pop(path, None)


@dataclass
class Stats:
    """Counters for one monitoring run."""

    polls: int = 0
    events: int = 0
    scans: int = 0
    overflows: int = 0
    alerts: int = 0
    by_source: dict[str, int] = field(default_factory=dict)


class Monitor:
    """Checks touched paths against the baseline and emits each new difference once."""

    def __init__(
        self,
        tree: Tree,
        baseline: Baseline,
        log: AlertLog,
        *,
        on_alert: Callable[[Alert], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind the tree, baseline and alert sink."""
        self.tree = tree
        self.baseline = baseline
        self.policy = baseline.policy
        self.log = log
        self.on_alert = on_alert
        self.clock = clock
        self.stats = Stats()
        self._lock = threading.Lock()

    def _emit(self, changes: Iterable[Change], clean: Iterable[str], source: str) -> list[Alert]:
        """Log resolved paths and emit alerts for difference states not yet reported."""
        out: list[Alert] = []
        with self._lock:
            now = datetime.now(UTC).isoformat(timespec="milliseconds")
            for path in clean:
                if path in self.log.open:
                    self.log.write_resolved(path, now, source)
            for change in changes:
                if self.log.open.get(change.path) == change.state_id():
                    continue
                alert = Alert(now, source, change)
                self.log.write_alert(alert)
                out.append(alert)
                self.stats.alerts += 1
                self.stats.by_source[source] = self.stats.by_source.get(source, 0) + 1
                if self.on_alert is not None:
                    self.on_alert(alert)
        return out

    def check_paths(self, paths: Iterable[str], source: str) -> list[Alert]:
        """Re-read touched paths (and everything under touched directories) and compare."""
        targets: set[str] = set()
        base = self.baseline.entries
        for path in paths:
            targets.add(path)
            prefix = path.rstrip("/") + "/"
            targets.update(p for p in base if p.startswith(prefix))
            if self.tree.is_dir(path):
                found, _ = self.tree.walk(self.policy, path)
                targets.update(found)
        changes: list[Change] = []
        clean: list[str] = []
        for path in sorted(targets):
            if self.policy.group_for(path) is None:
                continue
            change = compare_one(path, base.get(path), self.tree.entry(path), self.policy)
            if change is None:
                clean.append(path)
            else:
                changes.append(change)
        return self._emit(changes, clean, source)

    def full_scan(self, source: str = "scan") -> list[Alert]:
        """Hash everything the policy covers and compare with the baseline."""
        self.stats.scans += 1
        current = self.tree.scan(self.policy)
        base = self.baseline.entries
        changes: list[Change] = []
        clean: list[str] = []
        for path in sorted(set(base) | set(current)):
            change = compare_one(path, base.get(path), current.get(path), self.policy)
            if change is None:
                clean.append(path)
            else:
                changes.append(change)
        return self._emit(changes, clean, source)

    def run(
        self,
        watcher: Watcher,
        *,
        duration: float | None,
        rescan_every: float,
        poll_timeout: float = 1.0,
        stop: threading.Event | None = None,
    ) -> Stats:
        """Full scan, then watch until `duration` passes or `stop` is set, rescanning on schedule."""
        if rescan_every <= 0 or poll_timeout <= 0:
            raise ValueError("rescan_every and poll_timeout must be positive")
        start = self.clock()
        self.full_scan("startup-scan")
        next_scan = start + rescan_every
        while stop is None or not stop.is_set():
            now = self.clock()
            if duration is not None and now - start >= duration:
                break
            wait = min(poll_timeout, max(0.0, next_scan - now))
            if duration is not None:
                wait = min(wait, max(0.0, start + duration - now))
            batch = watcher.poll(wait)
            self.stats.polls += 1
            self.stats.events += len(batch.paths)
            if batch.overflow:
                self.stats.overflows += 1
                self.full_scan("overflow-scan")
            elif batch.paths:
                self.check_paths(batch.paths, watcher.name)
            if self.clock() >= next_scan:
                self.full_scan("scheduled-scan")
                next_scan = self.clock() + rescan_every
        return self.stats
