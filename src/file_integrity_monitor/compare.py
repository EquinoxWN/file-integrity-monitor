"""Compare current entries with the baseline and describe each change."""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from typing import Any

from .policy import SEVERITIES, Policy
from .tree import Entry

KINDS = ("added", "removed", "type", "content", "link_target", "mode", "owner", "unreadable")
_RISKY_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_IWOTH


@dataclass(frozen=True)
class Change:
    """One path that differs from the baseline."""

    path: str
    group: str
    severity: str
    kinds: tuple[str, ...]
    before: Entry | None
    after: Entry | None

    def state_id(self) -> str:
        """Identifies this exact difference, so the same state is alerted once."""
        after = self.after.to_dict() if self.after else None
        data = json.dumps([self.path, after], sort_keys=True).encode()
        return hashlib.sha256(data).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {
            "path": self.path,
            "group": self.group,
            "severity": self.severity,
            "kinds": list(self.kinds),
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
        }


def escalate(severity: str, before: Entry | None, after: Entry | None) -> str:
    """Raise to critical when setuid, setgid or world-write bits appear."""
    if after is None or after.kind not in ("file", "dir"):
        return severity
    old = before.mode if before is not None else 0
    if (after.mode & ~old) & _RISKY_BITS:
        return "critical"
    return severity


def compare_one(
    path: str, before: Entry | None, after: Entry | None, policy: Policy
) -> Change | None:
    """The change at one path, or None when it matches the baseline."""
    group = policy.group_for(path)
    if group is None or (before is None and after is None):
        return None
    kinds: list[str] = []
    if before is None:
        kinds.append("added")
    elif after is None:
        kinds.append("removed")
    else:
        if after.error is not None:
            kinds.append("unreadable")
        if before.kind != after.kind:
            kinds.append("type")
        else:
            if after.error is None and before.sha256 != after.sha256:
                kinds.append("content")
            if before.target != after.target:
                kinds.append("link_target")
        if before.mode != after.mode:
            kinds.append("mode")
        if (before.uid, before.gid) != (after.uid, after.gid):
            kinds.append("owner")
    if not kinds:
        return None
    severity = escalate(group.severity, before, after)
    return Change(path, group.name, severity, tuple(kinds), before, after)


def compare(baseline: dict[str, Entry], current: dict[str, Entry], policy: Policy) -> list[Change]:
    """Every change between two snapshots, most severe first, then by path."""
    changes = [
        c
        for p in sorted(set(baseline) | set(current))
        if (c := compare_one(p, baseline.get(p), current.get(p), policy)) is not None
    ]
    changes.sort(key=lambda c: (-SEVERITIES.index(c.severity), c.path))
    return changes
