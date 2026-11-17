"""Baseline sealing, verification, keys and atomic writes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from file_integrity_monitor import baseline as bl
from file_integrity_monitor.policy import load
from file_integrity_monitor.tree import Tree

KEY = b"0123456789abcdef-test-key"


def _make(host: Path) -> bl.Baseline:
    policy = load(None)
    return bl.create(policy, Tree(str(host)).scan(policy), str(host))


def _reseal(body: dict[str, Any]) -> str:
    body.pop("seal", None)
    body["seal"] = bl.seal(body, None)
    return json.dumps(body)


def test_round_trip_preserves_policy_and_entries(host: Path) -> None:
    base = _make(host)
    again = bl.loads(bl.dumps(base, None), None)
    assert again.entries == base.entries
    assert again.policy == base.policy
    assert again.created_at.endswith("+00:00")
    assert len(again.entries) == 27


def test_any_edit_breaks_the_plain_seal(host: Path) -> None:
    text = bl.dumps(_make(host), None)
    body = json.loads(text)
    body["entries"][0]["mode"] = "0777"
    with pytest.raises(bl.BaselineError, match="seal does not match"):
        bl.loads(json.dumps(body), None)
    body = json.loads(text)
    body["policy"]["group"][0]["severity"] = "low"
    with pytest.raises(bl.BaselineError, match="seal does not match"):
        bl.loads(json.dumps(body), None)


def test_hmac_seal_needs_the_right_key(host: Path) -> None:
    text = bl.dumps(_make(host), KEY)
    assert json.loads(text)["seal"].startswith("hmac-sha256:")
    assert bl.loads(text, KEY).entries
    with pytest.raises(bl.BaselineError, match="pass --key-file"):
        bl.loads(text, None)
    with pytest.raises(bl.BaselineError, match="seal does not match"):
        bl.loads(text, b"another-key-of-16-bytes")


def test_an_attacker_cannot_reseal_a_keyed_baseline_with_a_plain_digest(host: Path) -> None:
    body = json.loads(bl.dumps(_make(host), KEY))
    body["entries"][0]["sha256"] = "0" * 64
    forged = _reseal(body)  # edited, then sealed with a recomputed plain digest
    with pytest.raises(bl.BaselineError, match="downgrade"):
        bl.loads(forged, KEY)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("not json", "not valid JSON"),
        ("[]", "version 1"),
        ('{"format": "other", "version": 1}', "version 1"),
        ('{"format": "fim-baseline", "version": 1}', "no seal"),
    ],
)
def test_malformed_baselines_are_rejected(text: str, message: str) -> None:
    with pytest.raises(bl.BaselineError, match=message):
        bl.loads(text, None)


def test_sealed_but_invalid_content_is_rejected() -> None:
    body: dict[str, Any] = {
        "format": "fim-baseline",
        "version": 1,
        "policy": {"version": 1, "group": []},
        "entries": [],
        "created_at": "x",
        "root": "/",
    }
    with pytest.raises(bl.BaselineError, match="content is invalid"):
        bl.loads(_reseal(body), None)


def test_duplicate_paths_are_rejected(host: Path) -> None:
    body = json.loads(bl.dumps(_make(host), None))
    body["entries"].append(body["entries"][0])
    with pytest.raises(bl.BaselineError, match="duplicate"):
        bl.loads(_reseal(body), None)


def test_save_is_atomic_and_rewrites_identically(host: Path, tmp_path: Path) -> None:
    base = _make(host)
    out = tmp_path / "b.json"
    bl.save(str(out), base, None)
    first = out.read_bytes()
    bl.save(str(out), base, None)
    assert out.read_bytes() == first
    assert sorted(p.name for p in tmp_path.iterdir()) == ["b.json", "host"]
    assert bl.load(str(out), None).entries == base.entries


def test_failed_write_leaves_no_temp_file_and_keeps_the_old_file(
    host: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "b.json"
    out.write_text("old", encoding="utf-8")

    def boom(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("file_integrity_monitor.baseline.os.replace", boom)
    with pytest.raises(OSError, match="disk full"):
        bl.save(str(out), _make(host), None)
    assert out.read_text(encoding="utf-8") == "old"
    assert not list(tmp_path.glob("*.tmp"))


def test_read_key_rules(tmp_path: Path) -> None:
    assert bl.read_key(None) is None
    short = tmp_path / "short.key"
    short.write_bytes(b"123456789012345\n")
    with pytest.raises(bl.BaselineError, match="at least 16"):
        bl.read_key(str(short))
    good = tmp_path / "good.key"
    good.write_bytes(KEY + b"\n")
    assert bl.read_key(str(good)) == KEY
    with pytest.raises(bl.BaselineError, match="cannot read key"):
        bl.read_key(str(tmp_path / "missing.key"))


def test_load_errors(tmp_path: Path) -> None:
    with pytest.raises(bl.BaselineError, match="cannot read baseline"):
        bl.load(str(tmp_path / "missing.json"), None)
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\xff")
    with pytest.raises(bl.BaselineError, match="UTF-8"):
        bl.load(str(bad), None)
