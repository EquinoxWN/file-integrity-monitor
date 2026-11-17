"""Command line: `fim baseline`, `fim scan`, `fim watch`, `fim policy check`."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Callable, Sequence

from . import __version__
from . import baseline as bl
from .compare import Change, compare
from .inotify import InotifyError, InotifyWatcher
from .monitor import Alert, AlertLog, Monitor, PollingWatcher, Watcher
from .policy import PolicyError, load
from .tree import Tree, TreeError

EXIT_OK, EXIT_CHANGED, EXIT_INPUT, EXIT_READ = 0, 1, 2, 3


def _bounded(low: float, high: float) -> Callable[[str], float]:
    """argparse type for a float within [low, high]."""

    def parse(text: str) -> float:
        """Parse and range-check."""
        try:
            value = float(text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"not a number: {text!r}") from exc
        if not (low <= value <= high):
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return value

    return parse


def _parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    p = argparse.ArgumentParser(prog="fim", description="File integrity monitor for Linux hosts.")
    p.add_argument("--version", action="version", version=f"fim {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        """Options shared by every command that reads a tree."""
        sp.add_argument("--root", default="/", help="tree to read (default /, Linux only)")
        sp.add_argument("--key-file", help="HMAC key file for sealing or verifying the baseline")

    sp = sub.add_parser("baseline", help="record hashes, modes and owners of covered paths")
    common(sp)
    sp.add_argument("--policy", help="policy TOML (default: the bundled linux-default policy)")
    sp.add_argument("--out", required=True, help="baseline JSON to write (atomically)")

    sp = sub.add_parser("scan", help="full rescan compared with the baseline")
    common(sp)
    sp.add_argument("--baseline", required=True)
    sp.add_argument("--json", help="write the changes as JSON (atomically)")

    sp = sub.add_parser("watch", help="watch in real time, with scheduled full scans")
    common(sp)
    sp.add_argument("--baseline", required=True)
    sp.add_argument("--alerts", help="append alerts as JSON lines to this file")
    sp.add_argument("--backend", choices=["auto", "inotify", "poll"], default="auto")
    sp.add_argument("--poll-interval", type=_bounded(0.05, 3600), default=1.0)
    sp.add_argument("--rescan-every", type=_bounded(1, 86400 * 7), default=3600.0)
    sp.add_argument("--duration", type=_bounded(0.1, 86400 * 365), help="stop after N seconds")

    sp = sub.add_parser("policy", help="policy tools")
    psub = sp.add_subparsers(dest="policy_cmd", required=True)
    pc = psub.add_parser("check", help="validate a policy file")
    pc.add_argument("policy", nargs="?", help="policy TOML (default: the bundled policy)")
    return p


def _describe(change: Change) -> str:
    """One text line per change."""
    return f"{change.severity.upper():8} {','.join(change.kinds):24} {change.path}"


def _print_alert(alert: Alert) -> None:
    """Print one alert as it is emitted."""
    print(f"[{alert.source}] {_describe(alert.change)}", flush=True)


def cmd_baseline(args: argparse.Namespace) -> int:
    """Record a new baseline."""
    policy = load(args.policy)
    key = bl.read_key(args.key_file)
    tree = Tree(args.root)
    started = time.perf_counter()
    entries = tree.scan(policy)
    elapsed = time.perf_counter() - started
    bl.save(args.out, bl.create(policy, entries, str(tree.root)), key)
    kinds = Counter(e.kind for e in entries.values())
    errors = [e for e in entries.values() if e.error]
    for e in errors:
        print(f"unreadable: {e.path}: {e.error}", file=sys.stderr)
    seal = "hmac-sha256" if key else "sha256"
    print(
        f"baseline: {len(entries)} entries ({kinds['file']} files, {kinds['dir']} dirs, "
        f"{kinds['symlink']} links, {kinds['other']} other), {len(errors)} unreadable, "
        f"sealed {seal}, {elapsed:.3f} s -> {args.out}"
    )
    return EXIT_READ if errors else EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    """Rescan everything and print the differences."""
    base = bl.load(args.baseline, bl.read_key(args.key_file))
    tree = Tree(args.root)
    started = time.perf_counter()
    current = tree.scan(base.policy)
    changes = compare(base.entries, current, base.policy)
    elapsed = time.perf_counter() - started
    for change in changes:
        print(_describe(change))
    if args.json:
        payload = {"tool": f"fim {__version__}", "changes": [c.to_dict() for c in changes]}
        bl.write_atomic(args.json, json.dumps(payload, indent=1, sort_keys=True) + "\n")
    by_sev = Counter(c.severity for c in changes)
    summary = ", ".join(
        f"{by_sev[s]} {s}" for s in ("critical", "high", "medium", "low") if by_sev[s]
    )
    print(
        f"scan: {len(current)} entries checked, {len(changes)} changed"
        + (f" ({summary})" if summary else "")
        + f", {elapsed:.3f} s"
    )
    return EXIT_CHANGED if changes else EXIT_OK


def _watcher(backend: str, tree: Tree, monitor: Monitor) -> Watcher:
    """Pick the watcher backend."""
    if backend == "inotify" or (backend == "auto" and sys.platform == "linux"):
        return InotifyWatcher(tree, monitor.policy)
    return PollingWatcher(tree, monitor.policy)


def cmd_watch(args: argparse.Namespace) -> int:
    """Watch until --duration passes (or Ctrl-C)."""
    base = bl.load(args.baseline, bl.read_key(args.key_file))
    tree = Tree(args.root)
    monitor = Monitor(tree, base, AlertLog(args.alerts), on_alert=_print_alert)
    watcher = _watcher(args.backend, tree, monitor)
    print(f"watching with {watcher.name}; full scan every {args.rescan_every:g} s", flush=True)
    try:
        stats = monitor.run(
            watcher,
            duration=args.duration,
            rescan_every=args.rescan_every,
            poll_timeout=args.poll_interval,
        )
    except KeyboardInterrupt:
        stats = monitor.stats
    finally:
        if isinstance(watcher, InotifyWatcher):
            watcher.close()
    print(
        f"watch: {stats.alerts} alerts, {stats.scans} full scans, {stats.polls} polls, "
        f"{stats.overflows} overflows"
    )
    return EXIT_CHANGED if stats.alerts else EXIT_OK


def cmd_policy(args: argparse.Namespace) -> int:
    """Validate a policy and list its groups."""
    policy = load(args.policy)
    for g in policy.groups:
        flag = "recursive" if g.recursive else "one level"
        print(f"{g.name:12} {g.severity:8} {flag:9} {' '.join(g.patterns)}")
    print(f"policy: {len(policy.groups)} groups valid")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the exit code."""
    args = _parser().parse_args(argv)
    handlers = {
        "baseline": cmd_baseline,
        "scan": cmd_scan,
        "watch": cmd_watch,
        "policy": cmd_policy,
    }
    try:
        return handlers[args.cmd](args)
    except (PolicyError, TreeError, bl.BaselineError, ValueError) as exc:
        print(f"fim: error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except (InotifyError, OSError) as exc:
        print(f"fim: error: {exc}", file=sys.stderr)
        return EXIT_READ


if __name__ == "__main__":
    sys.exit(main())
