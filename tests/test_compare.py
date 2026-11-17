"""Change detection between baseline and current entries."""

from __future__ import annotations

from dataclasses import replace

import pytest

from file_integrity_monitor.compare import compare, compare_one, escalate
from file_integrity_monitor.policy import load
from file_integrity_monitor.tree import Entry

POLICY = load(None)
FILE = Entry("/usr/bin/ls", "file", 0o755, 0, 0, 10, "a" * 64)


def kinds(before: Entry | None, after: Entry | None, path: str = "/usr/bin/ls") -> tuple[str, ...]:
    change = compare_one(path, before, after, POLICY)
    return () if change is None else change.kinds


def test_identical_entries_are_not_a_change() -> None:
    assert compare_one("/usr/bin/ls", FILE, replace(FILE), POLICY) is None


@pytest.mark.parametrize(
    ("after", "expected"),
    [
        (replace(FILE, sha256="b" * 64), ("content",)),
        (replace(FILE, mode=0o775), ("mode",)),
        (replace(FILE, uid=1000), ("owner",)),
        (replace(FILE, gid=1000), ("owner",)),
        (replace(FILE, sha256="b" * 64, mode=0o700, uid=5), ("content", "mode", "owner")),
        (replace(FILE, kind="symlink", sha256=None, target="/tmp/x"), ("type",)),
        (replace(FILE, sha256=None, error="Permission denied"), ("unreadable",)),
    ],
)
def test_each_difference_is_named(after: Entry, expected: tuple[str, ...]) -> None:
    assert kinds(FILE, after) == expected


def test_added_removed_and_link_target() -> None:
    assert kinds(None, FILE) == ("added",)
    assert kinds(FILE, None) == ("removed",)
    link = Entry("/usr/bin/sh", "symlink", 0o777, 0, 0, target="dash")
    assert kinds(link, replace(link, target="/tmp/evil"), "/usr/bin/sh") == ("link_target",)
    assert compare_one("/usr/bin/ls", None, None, POLICY) is None


def test_uncovered_paths_are_ignored() -> None:
    other = replace(FILE, path="/etc/hostname")
    assert compare_one("/etc/hostname", None, other, POLICY) is None


def test_severity_comes_from_the_group() -> None:
    key = Entry("/root/.ssh/authorized_keys", "file", 0o600, 0, 0, 1, "a" * 64)
    change = compare_one(key.path, None, key, POLICY)
    assert change is not None and (change.group, change.severity) == ("ssh-keys", "critical")
    host = Entry("/etc/hosts", "file", 0o644, 0, 0, 1, "a" * 64)
    change = compare_one(host.path, host, replace(host, sha256="c" * 64), POLICY)
    assert change is not None and (change.group, change.severity) == ("configs", "medium")


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (0o755, 0o4755, "critical"),  # setuid added
        (0o755, 0o2755, "critical"),  # setgid added
        (0o644, 0o646, "critical"),  # world-writable
        (0o4755, 0o4755, "medium"),  # already setuid: not newly risky
        (0o4755, 0o755, "medium"),  # removing setuid is not escalated
        (0o644, 0o640, "medium"),
    ],
)
def test_escalate_on_new_setuid_setgid_or_world_write(old: int, new: int, expected: str) -> None:
    before = replace(FILE, mode=old)
    assert escalate("medium", before, replace(FILE, mode=new)) == expected


def test_escalate_counts_a_new_file_born_setuid_and_skips_links() -> None:
    assert escalate("high", None, replace(FILE, mode=0o4755)) == "critical"
    assert escalate("high", None, replace(FILE, mode=0o755)) == "high"
    link = Entry("/usr/bin/x", "symlink", 0o777, 0, 0, target="y")
    assert escalate("high", None, link) == "high"
    assert escalate("high", FILE, None) == "high"


def test_compare_sorts_most_severe_first_then_by_path() -> None:
    base = {
        "/usr/bin/ls": FILE,
        "/etc/hosts": Entry("/etc/hosts", "file", 0o644, 0, 0, 1, "a" * 64),
    }
    current = {
        "/usr/bin/ls": replace(FILE, sha256="b" * 64),
        "/root/.ssh/authorized_keys": Entry(
            "/root/.ssh/authorized_keys", "file", 0o600, 0, 0, 1, "a" * 64
        ),
        "/etc/hosts": replace(base["/etc/hosts"], mode=0o600),
        "/etc/hostname": Entry("/etc/hostname", "file", 0o644, 0, 0, 1, "a" * 64),
    }
    changes = compare(base, current, POLICY)
    assert [(c.path, c.severity) for c in changes] == [
        ("/root/.ssh/authorized_keys", "critical"),
        ("/usr/bin/ls", "high"),
        ("/etc/hosts", "medium"),
    ]


def test_state_id_differs_per_state_and_is_stable() -> None:
    a = compare_one("/usr/bin/ls", FILE, replace(FILE, sha256="b" * 64), POLICY)
    b = compare_one("/usr/bin/ls", FILE, replace(FILE, sha256="b" * 64), POLICY)
    c = compare_one("/usr/bin/ls", FILE, replace(FILE, sha256="c" * 64), POLICY)
    assert a is not None and b is not None and c is not None
    assert a.state_id() == b.state_id() != c.state_id()
    assert a.to_dict()["kinds"] == ["content"]
