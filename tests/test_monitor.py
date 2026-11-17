"""Monitor: alerts once per state, resolutions, restart replay, scheduled and overflow scans."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest
from conftest import set_meta, write

from file_integrity_monitor import baseline as bl
from file_integrity_monitor.inotify import Batch
from file_integrity_monitor.monitor import Alert, AlertLog, Monitor, PollingWatcher
from file_integrity_monitor.policy import load
from file_integrity_monitor.tree import Tree


def make(host: Path, log: str | None = None) -> tuple[Tree, Monitor]:
    policy = load(None)
    tree = Tree(str(host))
    base = bl.create(policy, tree.scan(policy), str(host))
    return tree, Monitor(tree, base, AlertLog(log))


class FakeWatcher:
    """Returns scripted batches and advances a fake clock by each wait."""

    name = "fake"

    def __init__(self, batches: list[Batch]) -> None:
        self.batches = batches
        self.now = 0.0
        self.waits: list[float] = []

    def clock(self) -> float:
        return self.now

    def poll(self, timeout: float) -> Batch:
        self.waits.append(timeout)
        self.now += timeout if timeout > 0 else 0.01
        return self.batches.pop(0) if self.batches else Batch(frozenset())


def test_polling_watcher_reports_added_modified_removed_and_owner_changes(host: Path) -> None:
    tree = Tree(str(host))
    watcher = PollingWatcher(tree, load(None), sleep=lambda _s: None)
    assert watcher.poll(0).paths == frozenset()
    write(host, "/etc/cron.d/evil", "* * * * * root /tmp/x\n")
    write(host, "/usr/bin/ls", "a longer tampered body\n")
    (host / "etc" / "sudoers.d" / "90-admins").unlink()
    set_meta(host, "/etc/shadow", 0o644, 0, 0)
    paths = watcher.poll(0).paths
    assert {"/etc/cron.d/evil", "/usr/bin/ls", "/etc/sudoers.d/90-admins", "/etc/shadow"} <= paths
    # Only the touched files and their parent directories (whose mtime moved) are reported.
    assert paths - {"/etc/cron.d", "/etc/sudoers.d"} == {
        "/etc/cron.d/evil",
        "/usr/bin/ls",
        "/etc/sudoers.d/90-admins",
        "/etc/shadow",
    }


def test_polling_watcher_reports_each_change_once(host: Path) -> None:
    watcher = PollingWatcher(Tree(str(host)), load(None), sleep=lambda _s: None)
    write(host, "/root/.ssh/authorized_keys2", "ssh-ed25519 EXAMPLE-NOT-A-REAL-KEY x\n")
    first = watcher.poll(0).paths
    assert "/root/.ssh/authorized_keys2" in first
    assert watcher.poll(0).paths == frozenset()


def test_polling_watcher_sleeps_for_the_timeout(host: Path) -> None:
    slept: list[float] = []
    watcher = PollingWatcher(Tree(str(host)), load(None), sleep=slept.append)
    watcher.poll(0.25)
    watcher.poll(0)
    assert slept == [0.25]


def test_check_paths_alerts_once_per_state_then_resolves_and_realerts(host: Path) -> None:
    _, mon = make(host)
    write(host, "/usr/bin/ls", "tampered\n")
    first = mon.check_paths({"/usr/bin/ls"}, "test")
    assert [a.change.kinds for a in first] == [("content",)]
    assert mon.check_paths({"/usr/bin/ls"}, "test") == []  # same state: no duplicate
    write(host, "/usr/bin/ls", "tampered again\n")
    assert len(mon.check_paths({"/usr/bin/ls"}, "test")) == 1  # new state: new alert
    (host / "usr" / "bin" / "ls").write_bytes(
        (Path(__file__).parent / "fixtures" / "host" / "usr" / "bin" / "ls").read_bytes()
    )
    assert mon.check_paths({"/usr/bin/ls"}, "test") == []
    assert "/usr/bin/ls" not in mon.log.open  # resolved
    write(host, "/usr/bin/ls", "tampered\n")
    assert (
        len(mon.check_paths({"/usr/bin/ls"}, "test")) == 1
    )  # same state as the first, after a fix


def test_check_paths_ignores_uncovered_paths(host: Path) -> None:
    _, mon = make(host)
    write(host, "/etc/hostname", "renamed\n")
    write(host, "/etc/motd", "hi\n")
    assert mon.check_paths({"/etc/hostname", "/etc/motd"}, "test") == []


def test_a_removed_directory_reports_every_baseline_path_under_it(host: Path) -> None:
    _, mon = make(host)
    for name in ("90-admins",):
        (host / "etc" / "sudoers.d" / name).unlink()
    (host / "etc" / "sudoers.d").rmdir()
    alerts = mon.check_paths({"/etc/sudoers.d"}, "test")
    assert sorted((a.change.path, a.change.kinds) for a in alerts) == [
        ("/etc/sudoers.d", ("removed",)),
        ("/etc/sudoers.d/90-admins", ("removed",)),
    ]


def test_a_new_directory_is_walked_so_files_created_before_the_watch_are_seen(host: Path) -> None:
    _, mon = make(host)
    write(host, "/home/eve/.ssh/authorized_keys", "ssh-ed25519 EXAMPLE-NOT-A-REAL-KEY eve\n")
    alerts = mon.check_paths({"/home/eve"}, "test")
    assert sorted(a.change.path for a in alerts) == [
        "/home/eve/.ssh",
        "/home/eve/.ssh/authorized_keys",
    ]
    assert {a.change.severity for a in alerts} == {"critical"}


def test_full_scan_catches_a_change_with_size_and_mtime_restored(host: Path) -> None:
    tree, mon = make(host)
    target = host / "usr" / "sbin" / "sshd"
    st = os.stat(target)
    body = target.read_bytes()
    target.write_bytes(body.replace(b"FIXTURE", b"BACKDOR"))  # same size
    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns))
    watcher = PollingWatcher(tree, load(None), sleep=lambda _s: None)
    assert watcher.poll(0).paths == frozenset()  # the cheap watcher is blind to this
    alerts = mon.full_scan()
    assert [(a.change.path, a.change.kinds) for a in alerts] == [("/usr/sbin/sshd", ("content",))]


def test_alert_log_replay_prevents_duplicates_after_a_restart(host: Path, tmp_path: Path) -> None:
    log = str(tmp_path / "alerts.jsonl")
    policy = load(None)
    tree = Tree(str(host))
    base = bl.create(policy, tree.scan(policy), str(host))
    write(host, "/etc/crontab", "* * * * * root /tmp/evil\n")
    first = Monitor(tree, base, AlertLog(log))
    assert len(first.full_scan()) == 1
    second = Monitor(tree, base, AlertLog(log))  # restart: same state still open
    assert second.full_scan() == []
    write(
        host,
        "/etc/crontab",
        (Path(__file__).parent / "fixtures/host/etc/crontab").read_text("utf-8"),
    )
    assert second.full_scan() == []
    third = Monitor(tree, base, AlertLog(log))
    assert third.log.open == {}
    write(host, "/etc/crontab", "* * * * * root /tmp/evil\n")
    assert len(third.full_scan()) == 1  # re-tampered after being fixed: alerted again
    records = [json.loads(x) for x in Path(log).read_text("utf-8").splitlines()]
    assert [r["type"] for r in records] == ["alert", "resolved", "alert"]
    assert records[0]["at"].endswith("+00:00")


def test_alert_log_rejects_garbage(tmp_path: Path) -> None:
    bad = tmp_path / "a.jsonl"
    bad.write_text('{"type": "alert", "path": "/x", "id": "1"}\nnot json\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 2"):
        AlertLog(str(bad))
    bad.write_text('{"type": "other", "path": "/x"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 1"):
        AlertLog(str(bad))


def test_concurrent_checks_emit_one_alert_per_state(host: Path) -> None:
    _, mon = make(host)
    write(host, "/etc/shadow", "root:$6$EXAMPLE-NOT-A-HASH:1::::::\n")
    barrier = threading.Barrier(4)
    results: list[list[Alert]] = []

    def worker() -> None:
        barrier.wait()
        results.append(mon.check_paths({"/etc/shadow"}, "thread"))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert sum(len(r) for r in results) == 1


def test_run_scans_at_start_on_schedule_and_on_overflow(host: Path) -> None:
    _, mon = make(host)
    watcher = FakeWatcher([Batch(frozenset()), Batch(frozenset(), overflow=True)])
    mon.clock = watcher.clock
    stats = mon.run(watcher, duration=10.0, rescan_every=4.0, poll_timeout=1.0)
    assert stats.overflows == 1
    # startup + overflow + scheduled at t=4 and t=8
    assert stats.scans == 4
    assert max(watcher.waits) <= 1.0
    assert watcher.now == pytest.approx(10.0)


def test_run_reports_watcher_paths_and_stops_on_event(host: Path) -> None:
    _, mon = make(host)
    write(host, "/usr/bin/ls", "tampered\n")
    stop = threading.Event()
    seen: list[str] = []

    def on_alert(alert: Alert) -> None:
        seen.append(f"{alert.source}:{alert.change.path}")
        if alert.source == "fake":
            stop.set()

    mon.on_alert = on_alert
    write(host, "/usr/sbin/sshd", "tampered too\n")
    watcher = FakeWatcher([Batch(frozenset({"/usr/bin/ls"}))])
    mon.clock = watcher.clock
    mon.full_scan = lambda source="scan": []  # type: ignore[method-assign]
    stats = mon.run(watcher, duration=None, rescan_every=100.0, stop=stop)
    assert seen == ["fake:/usr/bin/ls"]
    assert stats.by_source == {"fake": 1}


def test_run_rejects_non_positive_intervals(host: Path) -> None:
    _, mon = make(host)
    with pytest.raises(ValueError, match="positive"):
        mon.run(FakeWatcher([]), duration=1, rescan_every=0)
