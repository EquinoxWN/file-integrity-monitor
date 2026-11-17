"""Policy parsing, validation and path coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from file_integrity_monitor.policy import PolicyError, check_logical, load, loads

GOOD = """
version = 1
[[group]]
name = "keys"
severity = "critical"
paths = ["/home/*/.ssh", "/root/.ssh"]
recursive = true
exclude = ["*.swp"]

[[group]]
name = "bins"
severity = "high"
paths = ["/usr/bin"]

[[group]]
name = "etc"
severity = "medium"
paths = ["/etc"]
recursive = true
"""


def test_bundled_policy_loads_and_covers_the_four_areas() -> None:
    policy = load(None)
    names = {g.name for g in policy.groups}
    assert names == {"ssh-keys", "accounts", "cron", "binaries", "configs"}
    assert policy.group_for("/root/.ssh/authorized_keys").name == "ssh-keys"  # type: ignore[union-attr]
    assert policy.group_for("/etc/cron.d/backup").name == "cron"  # type: ignore[union-attr]
    assert policy.group_for("/usr/bin/passwd").name == "binaries"  # type: ignore[union-attr]
    assert policy.group_for("/etc/hostname") is None


def test_recursive_glob_group_covers_the_subtree_but_not_siblings() -> None:
    policy = loads(GOOD)
    keys = policy.groups[0]
    assert keys.covers("/home/alice/.ssh")
    assert keys.covers("/home/alice/.ssh/authorized_keys")
    assert keys.covers("/home/alice/.ssh/sub/deep")
    assert not keys.covers("/home/alice/.bashrc")
    assert not keys.covers("/home/alice")
    assert not keys.covers("/home")


def test_non_recursive_group_covers_one_level_only() -> None:
    bins = loads(GOOD).groups[1]
    assert bins.covers("/usr/bin")
    assert bins.covers("/usr/bin/ls")
    assert not bins.covers("/usr/bin/sub/ls")
    assert not bins.covers("/usr/binx")


def test_exclude_matches_the_file_name_only() -> None:
    keys = loads(GOOD).groups[0]
    assert not keys.covers("/root/.ssh/.authorized_keys.swp")
    assert keys.covers("/root/.ssh/authorized_keys")


def test_most_severe_group_wins_and_first_wins_on_ties() -> None:
    text = (
        GOOD
        + '\n[[group]]\nname = "dup"\nseverity = "critical"\npaths = ["/etc/ssh"]\nrecursive = true\n'
    )
    policy = loads(text)
    assert policy.group_for("/etc/ssh/sshd_config").name == "dup"  # type: ignore[union-attr]
    assert policy.group_for("/etc/hosts").name == "etc"  # type: ignore[union-attr]
    both = loads(
        'version = 1\n[[group]]\nname = "a"\nseverity = "high"\npaths = ["/etc"]\nrecursive = true\n'
        '[[group]]\nname = "b"\nseverity = "high"\npaths = ["/etc/ssh"]\nrecursive = true\n'
    )
    assert both.group_for("/etc/ssh/x").name == "a"  # type: ignore[union-attr]


def test_may_contain_is_true_only_for_pattern_ancestors() -> None:
    policy = loads(GOOD)
    assert policy.may_contain("/")
    assert policy.may_contain("/home")
    assert policy.may_contain("/home/bob")
    assert not policy.may_contain("/home/bob/.ssh")  # covered, not an ancestor
    assert not policy.may_contain("/var")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("version = 2\n[[group]]\n", "version"),
        ("version = 1\n", "at least one"),
        ("version = 1\nextra = 1\n[[group]]\n", "unknown top-level"),
        ('version = 1\n[[group]]\nname = "Bad Name"\nseverity = "low"\npaths = ["/etc"]\n', "name"),
        ('version = 1\n[[group]]\nname = "a"\nseverity = "urgent"\npaths = ["/etc"]\n', "severity"),
        ('version = 1\n[[group]]\nname = "a"\nseverity = "low"\npaths = []\n', "must not be empty"),
        (
            'version = 1\n[[group]]\nname = "a"\nseverity = "low"\npaths = "/etc"\n',
            "list of strings",
        ),
        ('version = 1\n[[group]]\nname = "a"\nseverity = "low"\npaths = ["etc"]\n', "absolute"),
        (
            'version = 1\n[[group]]\nname = "a"\nseverity = "low"\npaths = ["/etc/../root"]\n',
            "'..'",
        ),
        ('version = 1\n[[group]]\nname = "a"\nseverity = "low"\npaths = ["/"]\n', "'/' is not"),
        (
            'version = 1\n[[group]]\nname = "a"\nseverity = "low"\npaths = ["/etc"]\nrecursive = "yes"\n',
            "true or false",
        ),
        (
            'version = 1\n[[group]]\nname = "a"\nseverity = "low"\npaths = ["/etc"]\nexclude = ["a/b"]\n',
            "file-name pattern",
        ),
        (
            'version = 1\n[[group]]\nname = "a"\nseverity = "low"\npaths = ["/etc"]\nmode = 1\n',
            "unknown keys",
        ),
        (
            'version = 1\n[[group]]\nname = "a"\nseverity = "low"\npaths = ["/etc"]\n[[group]]\nname = "a"\nseverity = "low"\npaths = ["/var"]\n',
            "unique",
        ),
        ("version = 1\n[[group]\n", "not valid TOML"),
        (
            'version = 1\n[[group]]\nname = "a"\nseverity = "low"\npaths = ["/etc\\u0001x"]\n',
            "control character",
        ),
    ],
)
def test_malformed_policies_are_rejected_with_a_reason(text: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        loads(text)


@pytest.mark.parametrize(
    "path", ["", "relative", "/a//b", "/a/./b", "/a/../b", "/a/b/", "/a\\b", "/a\nb", "/a\x00b"]
)
def test_check_logical_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(PolicyError):
        check_logical(path)


def test_check_logical_accepts_plain_paths_and_spaces() -> None:
    assert check_logical("/") == "/"
    assert check_logical("/etc/cron.d/my job") == "/etc/cron.d/my job"


def test_policy_file_errors(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        load(str(tmp_path / "missing.toml"))
    big = tmp_path / "big.toml"
    big.write_text("#" * (300 * 1024), encoding="utf-8")
    with pytest.raises(PolicyError, match="larger than"):
        load(str(big))
    bad = tmp_path / "bad.toml"
    bad.write_bytes(b"\xff\xfe")
    with pytest.raises(PolicyError, match="UTF-8"):
        load(str(bad))
    ok = tmp_path / "ok.toml"
    ok.write_text(GOOD, encoding="utf-8")
    assert len(load(str(ok)).groups) == 3
