"""Demo on a copy of the fixture host: baseline, live watch, simulated tampering, detection latency.

usage: python scripts/demo.py [--workdir .tmp/demo] [--backend poll|inotify] [--interval 0.1]
Only the copy under the repository's .tmp/ folder is read and changed.
"""

from __future__ import annotations

import argparse
import shutil
import statistics
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

from file_integrity_monitor import baseline as bl
from file_integrity_monitor.inotify import InotifyWatcher
from file_integrity_monitor.monitor import Alert, AlertLog, Monitor, PollingWatcher, Watcher
from file_integrity_monitor.policy import load
from file_integrity_monitor.tree import Tree

REPO = Path(__file__).resolve().parent.parent
FIXTURE = REPO / "tests" / "fixtures" / "host"


def set_meta(root: Path, path: str, mode: int, uid: int, gid: int) -> None:
    """Change a path's mode and owner in the fixture's stat manifest."""
    manifest = root / ".fim-meta" / "stat.tsv"
    lines = [x for x in manifest.read_text("utf-8").splitlines() if not x.endswith("\t" + path)]
    lines.append(f"{mode:04o}\t{uid}\t{gid}\t{path}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def write(root: Path, path: str, text: str) -> None:
    """Write a file at an absolute Linux path inside the copy."""
    target = root.joinpath(*path.strip("/").split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")


def tampers(root: Path) -> list[tuple[str, str, Callable[[], None]]]:
    """The simulated intrusion steps: (label, path expected in the alert, action)."""
    key = "ssh-ed25519 EXAMPLE-NOT-A-REAL-KEY intruder@example.test\n"
    return [
        (
            "new SSH key for root",
            "/root/.ssh/authorized_keys",
            lambda: write(
                root,
                "/root/.ssh/authorized_keys",
                "ssh-ed25519 EXAMPLE-NOT-A-REAL-KEY admin@example.test\n" + key,
            ),
        ),
        (
            "modified binary",
            "/usr/sbin/sshd",
            lambda: write(root, "/usr/sbin/sshd", "FIXTURE BINARY: modified sshd (inert text)\n"),
        ),
        (
            "new cron job",
            "/etc/cron.d/updater",
            lambda: write(root, "/etc/cron.d/updater", "*/5 * * * * root /var/tmp/.u\n"),
        ),
        (
            "setuid bit on a binary",
            "/usr/bin/ls",
            lambda: set_meta(root, "/usr/bin/ls", 0o4755, 0, 0),
        ),
        (
            "new user with an SSH key",
            "/home/eve/.ssh/authorized_keys",
            lambda: write(root, "/home/eve/.ssh/authorized_keys", key),
        ),
        (
            "shadow file owner changed",
            "/etc/shadow",
            lambda: set_meta(root, "/etc/shadow", 0o640, 1000, 42),
        ),
    ]


def main() -> int:
    """Run the demo and print one line per tamper with its detection latency."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default=str(REPO / ".tmp" / "demo"))
    ap.add_argument("--backend", choices=["poll", "inotify"], default="poll")
    ap.add_argument("--interval", type=float, default=0.1)
    args = ap.parse_args()
    work = Path(args.workdir).resolve()
    if not work.is_relative_to(REPO / ".tmp"):
        print("demo: --workdir must be inside the repository's .tmp/ folder", file=sys.stderr)
        return 2
    if work.exists():
        shutil.rmtree(work)
    root = work / "host"
    shutil.copytree(FIXTURE, root)

    policy = load(None)
    tree = Tree(str(root))
    base = bl.create(policy, tree.scan(policy), str(root))
    bl.save(str(work / "baseline.json"), base, None)
    print(f"baseline: {len(base.entries)} entries of the fixture copy at .tmp/{work.name}/host")

    seen: dict[str, float] = {}
    got = threading.Condition()

    def on_alert(alert: Alert) -> None:
        with got:
            seen.setdefault(alert.change.path, time.monotonic())
            got.notify_all()
            print(
                f"  alert [{alert.source}] {alert.change.severity:8} "
                f"{','.join(alert.change.kinds):8} {alert.change.path}"
            )

    monitor = Monitor(tree, base, AlertLog(str(work / "alerts.jsonl")), on_alert=on_alert)
    watcher: Watcher = (
        InotifyWatcher(tree, policy) if args.backend == "inotify" else PollingWatcher(tree, policy)
    )
    stop = threading.Event()
    runner = threading.Thread(
        target=monitor.run,
        args=(watcher,),
        kwargs={
            "duration": None,
            "rescan_every": 3600.0,
            "poll_timeout": args.interval,
            "stop": stop,
        },
    )
    runner.start()
    latencies: list[float] = []
    missed: list[str] = []
    try:
        time.sleep(0.5)
        for label, path, action in tampers(root):
            started = time.monotonic()
            action()
            with got:
                got.wait_for(lambda p=path: p in seen, timeout=5.0)  # type: ignore[misc]
            if path in seen:
                latencies.append(seen[path] - started)
                print(f"{label:28} detected in {1000 * (seen[path] - started):6.1f} ms")
            else:
                missed.append(label)
                print(f"{label:28} NOT detected within 5 s")
    finally:
        stop.set()
        runner.join(10)
    stats = monitor.stats
    print(
        f"watch ({watcher.name}, interval {args.interval:g} s): {len(latencies)}/{len(latencies) + len(missed)} "
        f"tampers detected, median {1000 * statistics.median(latencies):.1f} ms, "
        f"max {1000 * max(latencies):.1f} ms, {stats.alerts} alerts, {stats.scans} full scans"
    )
    return 0 if not missed else 1


if __name__ == "__main__":
    sys.exit(main())
