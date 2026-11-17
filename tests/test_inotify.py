"""inotify: event decoding and path mapping (portable); the real watcher on Linux (CI)."""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

import pytest
from conftest import write

from file_integrity_monitor import inotify as ino
from file_integrity_monitor.policy import load
from file_integrity_monitor.tree import Tree

linux = pytest.mark.skipif(sys.platform != "linux", reason="inotify needs Linux; runs in CI")


def record(wd: int, mask: int, name: str = "", cookie: int = 0, pad: int = 16) -> bytes:
    """Encode one struct inotify_event the way the kernel does (NUL-padded name)."""
    raw = name.encode()
    length = 0 if not raw else ((len(raw) // pad) + 1) * pad
    return struct.pack("iIII", wd, mask, cookie, length) + raw.ljust(length, b"\0")


def test_parse_events_decodes_several_records_with_padding() -> None:
    buf = (
        record(1, ino.IN_MODIFY, "passwd")
        + record(2, ino.IN_CREATE, "x" * 20, 7)
        + record(3, ino.IN_DELETE_SELF)
    )
    events = ino.parse_events(buf)
    assert events == [
        ino.RawEvent(1, ino.IN_MODIFY, 0, "passwd"),
        ino.RawEvent(2, ino.IN_CREATE, 7, "x" * 20),
        ino.RawEvent(3, ino.IN_DELETE_SELF, 0, ""),
    ]
    assert ino.parse_events(b"") == []


def test_parse_events_rejects_truncated_records() -> None:
    whole = record(1, ino.IN_MODIFY, "passwd")
    with pytest.raises(ino.InotifyError, match="header"):
        ino.parse_events(whole[:10])
    with pytest.raises(ino.InotifyError, match="name"):
        ino.parse_events(whole[:-1])


def test_to_batch_maps_names_to_absolute_paths() -> None:
    dirs = {1: "/etc", 2: "/root/.ssh"}
    events = [
        ino.RawEvent(1, ino.IN_CLOSE_WRITE, 0, "passwd"),
        ino.RawEvent(2, ino.IN_CREATE, 0, "authorized_keys"),
        ino.RawEvent(9, ino.IN_MODIFY, 0, "unknown-wd"),
    ]
    batch = ino.to_batch(events, dirs)
    assert batch.paths == {"/etc/passwd", "/root/.ssh/authorized_keys"}
    assert not batch.overflow and not batch.rewatch


def test_to_batch_flags_overflow_new_directories_and_dropped_watches() -> None:
    dirs = {1: "/home", 2: "/etc/cron.d"}
    batch = ino.to_batch(
        [
            ino.RawEvent(-1, ino.IN_Q_OVERFLOW, 0, ""),
            ino.RawEvent(1, ino.IN_CREATE | ino.IN_ISDIR, 0, "eve"),
            ino.RawEvent(2, ino.IN_IGNORED, 0, ""),
        ],
        dirs,
    )
    assert batch.overflow and batch.rewatch
    assert batch.paths == {"/home/eve"}
    assert batch.ignored == {2}
    plain_file = ino.to_batch([ino.RawEvent(1, ino.IN_CREATE, 0, "f")], dirs)
    assert not plain_file.rewatch


@pytest.mark.parametrize("how", [ino.IN_CREATE, ino.IN_MOVED_TO])
def test_a_new_directory_alone_asks_for_new_watches(how: int) -> None:
    batch = ino.to_batch([ino.RawEvent(1, how | ino.IN_ISDIR, 0, "eve")], {1: "/home"})
    assert batch.rewatch
    assert batch.paths == {"/home/eve"}


def test_to_batch_reports_the_directory_itself_when_it_is_moved_or_deleted() -> None:
    batch = ino.to_batch([ino.RawEvent(1, ino.IN_MOVE_SELF, 0, "")], {1: "/etc/ssh"})
    assert batch.paths == {"/etc/ssh"} and batch.rewatch


def test_watch_mask_never_follows_links_and_covers_writes_and_renames() -> None:
    for bit in (
        ino.IN_DONT_FOLLOW,
        ino.IN_CLOSE_WRITE,
        ino.IN_ATTRIB,
        ino.IN_MOVED_TO,
        ino.IN_DELETE,
    ):
        assert ino.WATCH_MASK & bit


def test_watch_dirs_include_covered_dirs_and_pattern_ancestors(host: Path) -> None:
    dirs = ino.watch_dirs(Tree(str(host)), load(None))
    for expected in (
        "/etc",
        "/etc/ssh",
        "/etc/cron.d",
        "/home",
        "/home/alice",
        "/home/alice/.ssh",
        "/root/.ssh",
        "/usr/bin",
    ):
        assert expected in dirs
    assert "/" not in dirs
    assert "/etc/passwd" not in dirs


@pytest.mark.skipif(sys.platform == "linux", reason="checks the off-Linux refusal")
def test_inotify_watcher_is_refused_off_linux(host: Path) -> None:
    with pytest.raises(ino.InotifyError, match="needs Linux"):
        ino.InotifyWatcher(Tree(str(host)), load(None))


def _drain(watcher: ino.InotifyWatcher, want: str, tries: int = 20) -> set[str]:
    seen: set[str] = set()
    for _ in range(tries):
        seen |= watcher.poll(0.2).paths
        if want in seen:
            break
    return seen


@pytest.mark.linux
@linux
def test_real_inotify_reports_a_modified_file(host: Path) -> None:
    watcher = ino.InotifyWatcher(Tree(str(host)), load(None))
    try:
        write(host, "/usr/bin/ls", "tampered\n")
        assert "/usr/bin/ls" in _drain(watcher, "/usr/bin/ls")
    finally:
        watcher.close()


@pytest.mark.linux
@linux
def test_real_inotify_follows_a_new_user_home_to_a_new_ssh_key(host: Path) -> None:
    watcher = ino.InotifyWatcher(Tree(str(host)), load(None))
    try:
        (host / "home" / "eve").mkdir()
        assert "/home/eve" in _drain(watcher, "/home/eve")
        (host / "home" / "eve" / ".ssh").mkdir()
        assert "/home/eve/.ssh" in _drain(watcher, "/home/eve/.ssh")
        write(host, "/home/eve/.ssh/authorized_keys", "ssh-ed25519 EXAMPLE-NOT-A-REAL-KEY eve\n")
        assert "/home/eve/.ssh/authorized_keys" in _drain(watcher, "/home/eve/.ssh/authorized_keys")
    finally:
        watcher.close()


@pytest.mark.linux
@linux
def test_real_inotify_sees_an_atomic_rename_over_a_file(host: Path) -> None:
    watcher = ino.InotifyWatcher(Tree(str(host)), load(None))
    try:
        tmp = host / "etc" / ".passwd.new"
        tmp.write_text("root:x:0:0::/root:/bin/sh\nmallory:x:0:0::/:/bin/sh\n", encoding="utf-8")
        os.replace(tmp, host / "etc" / "passwd")
        assert "/etc/passwd" in _drain(watcher, "/etc/passwd")
    finally:
        watcher.close()
