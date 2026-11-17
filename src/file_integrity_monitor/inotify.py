"""Linux inotify through ctypes: event parsing (portable, tested everywhere) and the watcher (Linux)."""

from __future__ import annotations

import ctypes
import errno
import os
import select
import struct
import sys
from dataclasses import dataclass

from .policy import Policy
from .tree import Tree

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_ISDIR = 0x40000000
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000

WATCH_MASK = (
    IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_ONLYDIR
    | IN_DONT_FOLLOW
)
_HEADER = struct.Struct("iIII")
READ_BYTES = 64 * 1024


class InotifyError(OSError):
    """inotify is unavailable or a watch could not be added."""


@dataclass(frozen=True)
class RawEvent:
    """One `struct inotify_event`."""

    wd: int
    mask: int
    cookie: int
    name: str


@dataclass(frozen=True)
class Batch:
    """Paths reported by a watcher in one poll; `overflow` means events were lost."""

    paths: frozenset[str]
    overflow: bool = False
    rewatch: bool = False
    ignored: frozenset[int] = frozenset()


def parse_events(buf: bytes) -> list[RawEvent]:
    """Decode a read() buffer of inotify events; raises on a truncated record."""
    events: list[RawEvent] = []
    offset = 0
    while offset < len(buf):
        if offset + _HEADER.size > len(buf):
            raise InotifyError(errno.EIO, "truncated inotify event header")
        wd, mask, cookie, length = _HEADER.unpack_from(buf, offset)
        offset += _HEADER.size
        if offset + length > len(buf):
            raise InotifyError(errno.EIO, "truncated inotify event name")
        raw = buf[offset : offset + length].split(b"\0", 1)[0]
        offset += length
        events.append(RawEvent(wd, mask, cookie, os.fsdecode(raw)))
    return events


def to_batch(events: list[RawEvent], dirs: dict[int, str]) -> Batch:
    """Map events to absolute paths using the watch-descriptor table."""
    paths: set[str] = set()
    ignored: set[int] = set()
    overflow = rewatch = False
    for ev in events:
        if ev.mask & IN_Q_OVERFLOW:
            overflow = True
            continue
        base = dirs.get(ev.wd)
        if base is None:
            continue
        if ev.mask & IN_IGNORED:
            ignored.add(ev.wd)
            rewatch = True
            continue
        if ev.name:
            path = f"{'' if base == '/' else base}/{ev.name}"
            paths.add(path)
            if ev.mask & IN_ISDIR and ev.mask & (IN_CREATE | IN_MOVED_TO):
                rewatch = True
        else:
            paths.add(base)
            if ev.mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                rewatch = True
    return Batch(frozenset(paths), overflow, rewatch, frozenset(ignored))


def watch_dirs(tree: Tree, policy: Policy) -> list[str]:
    """Directories to watch: covered directories and the existing ancestors of each pattern."""
    out: set[str] = set()
    paths, _ = tree.walk(policy)
    for path in paths:
        if tree.is_dir(path):
            out.add(path)
        parent = path.rsplit("/", 1)[0] or "/"
        if parent != "/" and tree.is_dir(parent):
            out.add(parent)
    for group in policy.groups:
        for pattern in group.patterns:
            parts = pattern[1:].split("/")
            for depth in range(1, len(parts)):
                for found in tree.expand("/" + "/".join(parts[:depth])):
                    if tree.is_dir(found):
                        out.add(found)
    return sorted(out)


class InotifyWatcher:
    """Real-time watcher over inotify (Linux only)."""

    name = "inotify"
    _libc: ctypes.CDLL
    _fd: int
    _tree: Tree
    _policy: Policy
    dirs: dict[int, str]
    errors: list[str]

    def __init__(self, tree: Tree, policy: Policy) -> None:
        """Create the inotify instance and add the initial watches."""
        if sys.platform != "linux":
            raise InotifyError(errno.ENOSYS, "inotify needs Linux; use --backend poll")
        self._libc = ctypes.CDLL(None, use_errno=True)
        fd = self._libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if fd < 0:
            err = ctypes.get_errno()
            raise InotifyError(err, f"inotify_init1 failed: {os.strerror(err)}")
        self._fd = fd
        self._tree = tree
        self._policy = policy
        self.dirs: dict[int, str] = {}
        self.errors: list[str] = []
        self.rewatch()

    def rewatch(self) -> None:
        """Add watches for every directory that should be watched now (idempotent)."""
        for path in watch_dirs(self._tree, self._policy):
            real = os.fsencode(self._tree.real(path))
            wd = self._libc.inotify_add_watch(self._fd, real, WATCH_MASK)
            if wd < 0:
                err = ctypes.get_errno()
                if err == errno.ENOSPC:
                    raise InotifyError(
                        err, "inotify watch limit reached (fs.inotify.max_user_watches)"
                    )
                if err in (errno.ENOENT, errno.ENOTDIR):
                    continue
                self.errors.append(f"{path}: {os.strerror(err)}")
                continue
            self.dirs[wd] = path

    def poll(self, timeout: float) -> Batch:
        """Wait up to `timeout` seconds for events."""
        ready, _, _ = select.select([self._fd], [], [], max(0.0, timeout))
        if not ready:
            return Batch(frozenset())
        try:
            buf = os.read(self._fd, READ_BYTES)
        except BlockingIOError:
            return Batch(frozenset())
        batch = to_batch(parse_events(buf), self.dirs)
        for wd in batch.ignored:
            self.dirs.pop(wd, None)
        if batch.rewatch:
            self.rewatch()
        return batch

    def close(self) -> None:
        """Release the inotify file descriptor."""
        os.close(self._fd)
