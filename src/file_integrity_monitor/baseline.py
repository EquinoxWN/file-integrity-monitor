"""Baseline file: the policy plus every recorded entry, sealed by a SHA-256 digest or an HMAC."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .policy import Policy, PolicyError, from_dict
from .tree import Entry, TreeError

FORMAT = "fim-baseline"
MAX_BASELINE_BYTES = 512 * 1024 * 1024
MIN_KEY_BYTES = 16


class BaselineError(ValueError):
    """The baseline is missing, malformed, or its seal does not match."""


@dataclass(frozen=True)
class Baseline:
    """A sealed snapshot of the policy's paths."""

    policy: Policy
    entries: dict[str, Entry]
    created_at: str
    root: str


def read_key(path: str | None) -> bytes | None:
    """Read an HMAC key file (at least 16 bytes after stripping one trailing newline)."""
    if path is None:
        return None
    try:
        key = Path(path).read_bytes()
    except OSError as exc:
        raise BaselineError(f"{path}: cannot read key: {exc.strerror or exc}") from exc
    key = key.removesuffix(b"\n").removesuffix(b"\r")
    if len(key) < MIN_KEY_BYTES:
        raise BaselineError(f"{path}: key must be at least {MIN_KEY_BYTES} bytes")
    return key


def _canonical(body: dict[str, Any]) -> bytes:
    """Stable bytes for sealing."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def seal(body: dict[str, Any], key: bytes | None) -> str:
    """`sha256:<hex>` without a key, `hmac-sha256:<hex>` with one."""
    data = _canonical(body)
    if key is None:
        return "sha256:" + hashlib.sha256(data).hexdigest()
    return "hmac-sha256:" + hmac.new(key, data, hashlib.sha256).hexdigest()


def to_body(
    policy: Policy, entries: dict[str, Entry], root: str, created_at: str
) -> dict[str, Any]:
    """The unsealed JSON body."""
    return {
        "format": FORMAT,
        "version": 1,
        "tool": f"file-integrity-monitor {__version__}",
        "created_at": created_at,
        "root": root,
        "policy": policy.to_dict(),
        "entries": [entries[p].to_dict() for p in sorted(entries)],
    }


def dumps(baseline: Baseline, key: bytes | None) -> str:
    """Serialise and seal a baseline."""
    body = to_body(baseline.policy, baseline.entries, baseline.root, baseline.created_at)
    body["seal"] = seal(body, key)
    return json.dumps(body, indent=1, sort_keys=True) + "\n"


def create(policy: Policy, entries: dict[str, Entry], root: str) -> Baseline:
    """A new baseline stamped with the current UTC time."""
    now = datetime.now(UTC).isoformat(timespec="seconds")
    return Baseline(policy, dict(entries), now, root)


def write_atomic(path: str, text: str) -> None:
    """Write via a temp file in the same folder, fsync, then rename over the target."""
    target = Path(path)
    fd, tmp = tempfile.mkstemp(
        dir=target.parent or Path("."), prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def save(path: str, baseline: Baseline, key: bytes | None) -> None:
    """Write a sealed baseline atomically."""
    write_atomic(path, dumps(baseline, key))


def loads(text: str, key: bytes | None) -> Baseline:
    """Parse a baseline and verify its seal; a keyed seal needs the key, and vice versa."""
    try:
        body = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline is not valid JSON: {exc}") from exc
    if not isinstance(body, dict) or body.get("format") != FORMAT or body.get("version") != 1:
        raise BaselineError("not a version 1 fim baseline")
    stored = body.pop("seal", None)
    if not isinstance(stored, str):
        raise BaselineError("baseline has no seal")
    if stored.startswith("hmac-sha256:") and key is None:
        raise BaselineError("baseline is HMAC-sealed: pass --key-file")
    if stored.startswith("sha256:") and key is not None:
        raise BaselineError(
            "baseline is not HMAC-sealed but a key was given (refusing a downgrade)"
        )
    if not hmac.compare_digest(stored, seal(body, key)):
        raise BaselineError(
            "baseline seal does not match: the file was changed or the key is wrong"
        )
    try:
        policy = from_dict(body.get("policy"))
        raw = body.get("entries")
        if not isinstance(raw, list):
            raise BaselineError("baseline 'entries' must be a list")
        entries = {e.path: e for e in (Entry.from_dict(item) for item in raw)}
    except (PolicyError, TreeError) as exc:
        raise BaselineError(f"baseline content is invalid: {exc}") from exc
    if len(entries) != len(raw):
        raise BaselineError("baseline has duplicate paths")
    created_at, root = body.get("created_at"), body.get("root")
    if not isinstance(created_at, str) or not isinstance(root, str):
        raise BaselineError("baseline 'created_at' and 'root' must be strings")
    return Baseline(policy, entries, created_at, root)


def load(path: str, key: bytes | None) -> Baseline:
    """Read and verify a baseline file."""
    p = Path(path)
    try:
        if p.stat().st_size > MAX_BASELINE_BYTES:
            raise BaselineError(f"{path}: larger than {MAX_BASELINE_BYTES} bytes")
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"{path}: cannot read baseline: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise BaselineError(f"{path}: baseline is not UTF-8") from exc
    return loads(text, key)
