"""End to end through the CLI on a copy of the fixture host."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from conftest import set_meta, write

from file_integrity_monitor.cli import main

KEY = b"cli-test-key-0123456789"


def _baseline(host: Path, tmp_path: Path, *extra: str) -> str:
    out = str(tmp_path / "baseline.json")
    assert main(["baseline", "--root", str(host), "--out", out, *extra]) == 0
    return out


def tamper(host: Path) -> None:
    """The simulated intrusion: new SSH key, modified binary, new cron job, setuid, owner change."""
    write(
        host,
        "/root/.ssh/authorized_keys",
        "ssh-ed25519 EXAMPLE-NOT-A-REAL-KEY admin@example.test\n"
        "ssh-ed25519 EXAMPLE-NOT-A-REAL-KEY intruder@example.test\n",
    )
    write(host, "/usr/sbin/sshd", "FIXTURE BINARY: modified sshd with a backdoor (inert text)\n")
    write(host, "/etc/cron.d/updater", "*/5 * * * * root /var/tmp/.u\n")
    set_meta(host, "/etc/cron.d/updater", 0o644, 0, 0)  # same mode on Windows and Linux
    set_meta(host, "/usr/bin/ls", 0o4755, 0, 0)
    set_meta(host, "/etc/shadow", 0o640, 1000, 42)
    write(host, "/etc/hostname", "uncovered change\n")


def test_baseline_then_clean_scan_exits_zero(
    host: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _baseline(host, tmp_path)
    assert (
        "baseline: 27 entries (17 files, 10 dirs, 0 links, 0 other), 0 unreadable"
        in capsys.readouterr().out
    )
    assert main(["scan", "--root", str(host), "--baseline", out]) == 0
    assert "27 entries checked, 0 changed" in capsys.readouterr().out


def test_scan_finds_exactly_the_simulated_tampering(
    host: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _baseline(host, tmp_path)
    tamper(host)
    report = tmp_path / "changes.json"
    capsys.readouterr()
    assert main(["scan", "--root", str(host), "--baseline", out, "--json", str(report)]) == 1
    text = capsys.readouterr().out
    assert "28 entries checked, 5 changed (3 critical, 2 high)" in text
    data = json.loads(report.read_text("utf-8"))["changes"]
    changes = {c["path"]: (c["severity"], c["kinds"]) for c in data}
    assert changes == {
        "/root/.ssh/authorized_keys": ("critical", ["content"]),
        "/usr/bin/ls": ("critical", ["mode"]),  # setuid added: escalated from high
        "/etc/shadow": ("critical", ["owner"]),
        "/usr/sbin/sshd": ("high", ["content"]),
        "/etc/cron.d/updater": ("high", ["added"]),
    }
    assert [c["severity"] for c in data] == ["critical"] * 3 + ["high"] * 2


def test_watch_with_the_poll_backend_reports_alerts_and_writes_the_log(
    host: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _baseline(host, tmp_path)
    tamper(host)
    alerts = tmp_path / "alerts.jsonl"
    args = [
        "watch",
        "--root",
        str(host),
        "--baseline",
        out,
        "--backend",
        "poll",
        "--alerts",
        str(alerts),
        "--duration",
        "0.3",
        "--poll-interval",
        "0.1",
    ]
    assert main(args) == 1
    text = capsys.readouterr().out
    assert "watching with poll" in text
    assert "[startup-scan] CRITICAL" in text
    records = [json.loads(line) for line in alerts.read_text("utf-8").splitlines()]
    assert {r["path"] for r in records} >= {
        "/root/.ssh/authorized_keys",
        "/usr/sbin/sshd",
        "/etc/cron.d/updater",
    }
    count = len(records)
    assert main(args) == 0  # restart: same open states, nothing new
    assert len(alerts.read_text("utf-8").splitlines()) == count


def test_hmac_baseline_round_trip_and_wrong_key(
    host: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = tmp_path / "k"
    key.write_bytes(KEY)
    out = _baseline(host, tmp_path, "--key-file", str(key))
    assert "sealed hmac-sha256" in capsys.readouterr().out
    assert main(["scan", "--root", str(host), "--baseline", out, "--key-file", str(key)]) == 0
    assert main(["scan", "--root", str(host), "--baseline", out]) == 2
    assert "pass --key-file" in capsys.readouterr().err
    other = tmp_path / "other"
    other.write_bytes(b"x" * 32)
    assert main(["scan", "--root", str(host), "--baseline", out, "--key-file", str(other)]) == 2


def test_edited_baseline_is_refused(
    host: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = Path(_baseline(host, tmp_path))
    body = json.loads(out.read_text("utf-8"))
    body["entries"] = [e for e in body["entries"] if e["path"] != "/etc/cron.d/logrotate"]
    out.write_text(json.dumps(body), encoding="utf-8")
    assert main(["scan", "--root", str(host), "--baseline", str(out)]) == 2
    assert "seal does not match" in capsys.readouterr().err


def test_policy_check_lists_groups(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["policy", "check"]) == 0
    assert "policy: 5 groups valid" in capsys.readouterr().out
    bad = tmp_path / "p.toml"
    bad.write_text("version = 3\n", encoding="utf-8")
    assert main(["policy", "check", str(bad)]) == 2


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "--root", "{host}", "--baseline", "{tmp}/missing.json"],
        ["baseline", "--root", "{tmp}/no-such-dir", "--out", "{tmp}/b.json"],
        ["baseline", "--root", "{host}", "--out", "{tmp}/b.json", "--policy", "{tmp}/none.toml"],
        ["baseline", "--root", "{host}", "--out", "{tmp}/b.json", "--key-file", "{tmp}/none.key"],
    ],
)
def test_bad_input_exits_two(host: Path, tmp_path: Path, args: list[str]) -> None:
    filled = [a.format(host=host, tmp=tmp_path) for a in args]
    assert main(filled) == 2


@pytest.mark.parametrize(
    "flag", [["--poll-interval", "0"], ["--rescan-every", "-1"], ["--duration", "abc"]]
)
def test_out_of_range_watch_options_are_rejected(
    host: Path, tmp_path: Path, flag: list[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["watch", "--root", str(host), "--baseline", "b.json", *flag])
    assert exc.value.code == 2


@pytest.mark.skipif(sys.platform == "linux", reason="checks the off-Linux refusal")
def test_default_root_is_refused_off_linux(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["baseline", "--out", str(tmp_path / "b.json")]) == 2
    assert "drive root" in capsys.readouterr().err
    assert not (tmp_path / "b.json").exists()


@pytest.mark.skipif(sys.platform == "linux", reason="checks the off-Linux refusal")
def test_inotify_backend_is_refused_off_linux(
    host: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _baseline(host, tmp_path)
    assert (
        main(
            [
                "watch",
                "--root",
                str(host),
                "--baseline",
                out,
                "--backend",
                "inotify",
                "--duration",
                "1",
            ]
        )
        == 3
    )
    assert "needs Linux" in capsys.readouterr().err
