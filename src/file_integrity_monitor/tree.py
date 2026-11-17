"""Read-only view of a file tree: the real `/` on Linux, or a fixture directory standing in for it."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .policy import Policy, check_logical, has_glob, split

META_DIR = ".fim-meta"
META_FILE = "stat.tsv"
MAX_META_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 200_000
CHUNK = 1024 * 1024
_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)


class TreeError(ValueError):
    """The tree root or its metadata manifest is unusable."""


@dataclass(frozen=True)
class Entry:
    """Recorded state of one path; `error` is set when it could not be read."""

    path: str
    kind: str  # file | dir | symlink | other
    mode: int
    uid: int
    gid: int
    size: int | None = None
    sha256: str | None = None
    target: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON form (mode as an octal string)."""
        out: dict[str, Any] = {
            "path": self.path,
            "kind": self.kind,
            "mode": f"{self.mode:04o}",
            "uid": self.uid,
            "gid": self.gid,
        }
        for key in ("size", "sha256", "target", "error"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out

    @staticmethod
    def from_dict(data: Any) -> Entry:
        """Parse the JSON form, validating every field."""
        if not isinstance(data, dict):
            raise TreeError("entry must be an object")
        try:
            path = check_logical(data["path"])
            kind = data["kind"]
            if kind not in ("file", "dir", "symlink", "other"):
                raise TreeError(f"{path}: unknown kind {kind!r}")
            mode = int(data["mode"], 8)
            uid, gid = data["uid"], data["gid"]
            if not (0 <= mode <= 0o7777) or not all(
                isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (uid, gid)
            ):
                raise TreeError(f"{path}: bad mode, uid or gid")
            size, digest = data.get("size"), data.get("sha256")
            target, error = data.get("target"), data.get("error")
        except (KeyError, TypeError, ValueError) as exc:
            raise TreeError(f"malformed entry: {exc}") from exc
        if size is not None and (not isinstance(size, int) or size < 0):
            raise TreeError(f"{path}: bad size")
        if digest is not None and (not isinstance(digest, str) or len(digest) != 64):
            raise TreeError(f"{path}: bad sha256")
        if target is not None and not isinstance(target, str):
            raise TreeError(f"{path}: bad symlink target")
        if error is not None and not isinstance(error, str):
            raise TreeError(f"{path}: bad error")
        return Entry(path, kind, mode, uid, gid, size, digest, target, error)


def parse_meta(text: str) -> dict[str, tuple[int, int, int]]:
    """Parse a stat manifest: `mode<TAB>uid<TAB>gid<TAB>path` per line, mode in octal."""
    out: dict[str, tuple[int, int, int]] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            raise TreeError(f"{META_FILE} line {number}: expected 4 tab-separated fields")
        try:
            mode, uid, gid = int(fields[0], 8), int(fields[1]), int(fields[2])
        except ValueError as exc:
            raise TreeError(f"{META_FILE} line {number}: {exc}") from exc
        if not (0 <= mode <= 0o7777) or uid < 0 or gid < 0:
            raise TreeError(f"{META_FILE} line {number}: mode, uid or gid out of range")
        try:
            path = check_logical(fields[3])
        except ValueError as exc:
            raise TreeError(f"{META_FILE} line {number}: {exc}") from exc
        out[path] = (mode, uid, gid)
    return out


def kind_of(mode: int) -> str:
    """File kind from st_mode."""
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    return "other"


class Tree:
    """Maps absolute Linux paths onto a root directory; never follows symlinks, never writes."""

    def __init__(self, root: str) -> None:
        """Open a tree; off Linux the root must be a directory, never a drive root."""
        real = Path(root).resolve()
        if not real.is_dir():
            raise TreeError(f"root is not a directory: {root}")
        is_fs_root = real == Path(real.anchor)
        if is_fs_root and sys.platform != "linux":
            raise TreeError("off Linux --root must be a fixture directory, not a drive root")
        self.root = real
        self.is_real_root = is_fs_root
        self._meta: dict[str, tuple[int, int, int]] = {}
        self._meta_key: tuple[int, int] | None = None

    def real(self, path: str) -> str:
        """OS path for an absolute Linux path."""
        parts = split(check_logical(path))
        return str(self.root.joinpath(*parts)) if parts else str(self.root)

    def _overlay(self) -> dict[str, tuple[int, int, int]]:
        """The fixture manifest, reloaded when it changes; empty on a real root."""
        if self.is_real_root:
            return {}
        manifest = self.root / META_DIR / META_FILE
        try:
            st = manifest.stat()
        except FileNotFoundError:
            self._meta, self._meta_key = {}, None
            return self._meta
        key = (st.st_mtime_ns, st.st_size)
        if key != self._meta_key:
            if st.st_size > MAX_META_BYTES:
                raise TreeError(f"{META_FILE} is larger than {MAX_META_BYTES} bytes")
            self._meta = parse_meta(manifest.read_text(encoding="utf-8"))
            self._meta_key = key
        return self._meta

    def lstat(self, path: str) -> os.stat_result | None:
        """lstat of a path, or None when it does not exist."""
        try:
            return os.lstat(self.real(path))
        except (FileNotFoundError, NotADirectoryError):
            return None

    def quick(self, path: str) -> tuple[Any, ...] | None:
        """Cheap change key (no hashing) used by the polling watcher."""
        st = self.lstat(path)
        if st is None:
            return None
        mode, uid, gid = self._overlay().get(path, (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid))
        return (kind_of(st.st_mode), mode, uid, gid, st.st_size, st.st_mtime_ns, st.st_ino)

    def entry(self, path: str) -> Entry | None:
        """Full state of one path (hashing regular files), or None when it does not exist."""
        try:
            st = self.lstat(path)
        except OSError as exc:
            return Entry(path, "other", 0, 0, 0, error=exc.strerror or str(exc))
        if st is None:
            return None
        kind = kind_of(st.st_mode)
        mode, uid, gid = self._overlay().get(path, (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid))
        if kind == "symlink":
            try:
                return Entry(path, kind, mode, uid, gid, target=os.readlink(self.real(path)))
            except OSError as exc:
                return Entry(path, kind, mode, uid, gid, error=exc.strerror or str(exc))
        if kind != "file":
            return Entry(path, kind, mode, uid, gid)
        try:
            size, digest = self._hash(path, st)
        except OSError as exc:
            return Entry(path, kind, mode, uid, gid, error=exc.strerror or str(exc))
        return Entry(path, kind, mode, uid, gid, size=size, sha256=digest)

    def _hash(self, path: str, before: os.stat_result) -> tuple[int, str]:
        """SHA-256 of a regular file opened without following links; refuses a swapped file."""
        fd = os.open(self.real(path), _OPEN_FLAGS)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                raise OSError(0, "file was replaced while it was being read")
            digest = hashlib.sha256()
            size = 0
            while chunk := os.read(fd, CHUNK):
                digest.update(chunk)
                size += len(chunk)
            return size, digest.hexdigest()
        finally:
            os.close(fd)

    def children(self, path: str) -> list[str]:
        """Names in a directory (sorted); empty when it is not a readable directory."""
        try:
            with os.scandir(self.real(path)) as it:
                names = sorted(e.name for e in it)
        except (FileNotFoundError, NotADirectoryError):
            return []
        if path == "/" and not self.is_real_root:
            names = [n for n in names if n != META_DIR]
        return names

    def is_dir(self, path: str) -> bool:
        """A real directory (not a link to one)."""
        st = self.lstat(path)
        return st is not None and stat.S_ISDIR(st.st_mode)

    def expand(self, pattern: str) -> list[str]:
        """Existing paths matching a pattern whose components may hold globs."""
        found = ["/"]
        for part in split(pattern):
            nxt: list[str] = []
            for base in found:
                prefix = "" if base == "/" else base
                if has_glob(part):
                    if not self.is_dir(base):
                        continue
                    nxt += [
                        f"{prefix}/{n}" for n in self.children(base) if fnmatch.fnmatchcase(n, part)
                    ]
                elif self.lstat(f"{prefix}/{part}") is not None:
                    nxt.append(f"{prefix}/{part}")
            found = nxt
        return found

    def walk(self, policy: Policy, start: str | None = None) -> tuple[list[str], dict[str, str]]:
        """Covered existing paths (or those under `start`), sorted, and directories not listable."""
        out: set[str] = set()
        errors: dict[str, str] = {}
        stack: list[str] = []
        if start is not None:
            stack.append(check_logical(start))
        else:
            for group in policy.groups:
                for pattern in group.patterns:
                    stack += self.expand(pattern)
        seen: set[str] = set()
        while stack:
            path = stack.pop()
            if path in seen:
                continue
            seen.add(path)
            if policy.group_for(path) is not None and self.lstat(path) is not None:
                out.add(path)
                if len(out) > MAX_ENTRIES:
                    raise TreeError(f"more than {MAX_ENTRIES} paths match the policy")
            if self.is_dir(path) and (path in out or policy.may_contain(path)):
                prefix = "" if path == "/" else path
                try:
                    stack += [f"{prefix}/{n}" for n in self.children(path)]
                except OSError as exc:
                    errors[path] = f"cannot list directory: {exc.strerror or exc}"
        return sorted(out), errors

    def scan(self, policy: Policy, start: str | None = None) -> dict[str, Entry]:
        """Entries for every covered path (or those under `start`)."""
        paths, errors = self.walk(policy, start)
        out: dict[str, Entry] = {}
        for path in paths:
            entry = self.entry(path)
            if entry is not None:
                out[path] = replace(entry, error=errors[path]) if path in errors else entry
        return out
