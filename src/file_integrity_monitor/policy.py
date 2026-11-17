"""Watch policy: which paths are critical, how deep to look and how severe a change is."""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
MAX_POLICY_BYTES = 256 * 1024
_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
_GLOB = re.compile(r"[*?\[]")
_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class PolicyError(ValueError):
    """The policy file is missing, unreadable or malformed."""


def check_logical(path: str) -> str:
    """Validate an absolute POSIX path (no `..`, `.`, empty parts or control characters)."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise PolicyError(f"path must be absolute: {path!r}")
    if _BAD_CHARS.search(path) or "\\" in path:
        raise PolicyError(f"path has a control character or backslash: {path!r}")
    if path == "/":
        return path
    parts = path[1:].split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise PolicyError(f"path has an empty, '.' or '..' part: {path!r}")
    return path


def split(path: str) -> list[str]:
    """Components of a validated absolute path."""
    return [] if path == "/" else path[1:].split("/")


@dataclass(frozen=True)
class Group:
    """A named set of path patterns sharing a severity."""

    name: str
    severity: str
    patterns: tuple[str, ...]
    recursive: bool
    exclude: tuple[str, ...]

    def covers(self, path: str) -> bool:
        """Whether this group watches the given absolute path."""
        parts = split(path)
        if parts and any(fnmatch.fnmatchcase(parts[-1], e) for e in self.exclude):
            return False
        for pattern in self.patterns:
            pat = split(pattern)
            if len(parts) < len(pat):
                continue
            if not all(fnmatch.fnmatchcase(p, q) for p, q in zip(parts, pat, strict=False)):
                continue
            extra = len(parts) - len(pat)
            if extra == 0 or self.recursive or extra == 1:
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Plain form stored inside a baseline."""
        return {
            "name": self.name,
            "severity": self.severity,
            "paths": list(self.patterns),
            "recursive": self.recursive,
            "exclude": list(self.exclude),
        }


@dataclass(frozen=True)
class Policy:
    """All groups; a path belongs to the most severe group that covers it."""

    groups: tuple[Group, ...]

    def group_for(self, path: str) -> Group | None:
        """The most severe covering group (first wins on ties), or None."""
        best: Group | None = None
        for group in self.groups:
            if group.covers(path) and (
                best is None or SEVERITIES.index(group.severity) > SEVERITIES.index(best.severity)
            ):
                best = group
        return best

    def may_contain(self, path: str) -> bool:
        """Whether a directory at this path could hold a covered path (a pattern's ancestor)."""
        parts = split(path)
        for group in self.groups:
            for pattern in group.patterns:
                pat = split(pattern)
                if len(parts) < len(pat) and all(
                    fnmatch.fnmatchcase(p, q) for p, q in zip(parts, pat, strict=False)
                ):
                    return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Plain form stored inside a baseline."""
        return {"version": 1, "group": [g.to_dict() for g in self.groups]}


def _strings(value: Any, field: str, where: str, *, allow_empty: bool) -> tuple[str, ...]:
    """A list of strings, or a PolicyError."""
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where}: '{field}' must be a list of strings")
    if not value and not allow_empty:
        raise PolicyError(f"{where}: '{field}' must not be empty")
    return tuple(value)


def _group(raw: Any, index: int) -> Group:
    """Parse and validate one [[group]] table."""
    where = f"group #{index + 1}"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: must be a table")
    unknown = set(raw) - {"name", "severity", "paths", "recursive", "exclude"}
    if unknown:
        raise PolicyError(f"{where}: unknown keys {sorted(unknown)}")
    name = raw.get("name")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise PolicyError(f"{where}: 'name' must match {_NAME.pattern}")
    severity = raw.get("severity")
    if severity not in SEVERITIES:
        raise PolicyError(f"{where} ({name}): 'severity' must be one of {list(SEVERITIES)}")
    recursive = raw.get("recursive", False)
    if not isinstance(recursive, bool):
        raise PolicyError(f"{where} ({name}): 'recursive' must be true or false")
    patterns = _strings(raw.get("paths"), "paths", f"{where} ({name})", allow_empty=False)
    for pattern in patterns:
        check_logical(pattern)
        if pattern == "/":
            raise PolicyError(f"{where} ({name}): watching '/' is not allowed")
    exclude = _strings(raw.get("exclude", []), "exclude", f"{where} ({name})", allow_empty=True)
    for item in exclude:
        if not item or "/" in item or _BAD_CHARS.search(item):
            raise PolicyError(f"{where} ({name}): exclude {item!r} must be a file-name pattern")
    return Group(str(name), str(severity), patterns, recursive, exclude)


def from_dict(data: Any) -> Policy:
    """Build a policy from parsed TOML or a baseline's stored copy."""
    if not isinstance(data, dict):
        raise PolicyError("policy must be a table")
    unknown = set(data) - {"version", "group"}
    if unknown:
        raise PolicyError(f"unknown top-level keys {sorted(unknown)}")
    if data.get("version") != 1:
        raise PolicyError("policy 'version' must be 1")
    raw_groups = data.get("group")
    if not isinstance(raw_groups, list) or not raw_groups:
        raise PolicyError("policy needs at least one [[group]]")
    groups = tuple(_group(g, i) for i, g in enumerate(raw_groups))
    names = [g.name for g in groups]
    if len(set(names)) != len(names):
        raise PolicyError("group names must be unique")
    return Policy(groups)


def has_glob(part: str) -> bool:
    """Whether a path component is a glob pattern."""
    return bool(_GLOB.search(part))


def loads(text: str) -> Policy:
    """Parse a policy from TOML text."""
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise PolicyError(f"policy is larger than {MAX_POLICY_BYTES} bytes")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"policy is not valid TOML: {exc}") from exc
    return from_dict(data)


def load(path: str | None) -> Policy:
    """Load a policy file, or the bundled Linux default when path is None."""
    if path is None:
        text = resources.files("file_integrity_monitor").joinpath("policies/linux-default.toml")
        return loads(text.read_text(encoding="utf-8"))
    p = Path(path)
    try:
        if p.stat().st_size > MAX_POLICY_BYTES:
            raise PolicyError(f"{path}: larger than {MAX_POLICY_BYTES} bytes")
        return loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"{path}: cannot read policy: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise PolicyError(f"{path}: policy is not UTF-8") from exc
