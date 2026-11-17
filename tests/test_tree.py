"""Tree reads: hashing, the stat manifest, globs, the walk, root safety and entry parsing."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest
from conftest import set_meta, write

from file_integrity_monitor.policy import load, loads
from file_integrity_monitor.tree import Entry, Tree, TreeError, kind_of, parse_meta

linux = pytest.mark.skipif(sys.platform != "linux", reason="needs Linux; runs in CI")


def test_file_entry_has_the_sha256_size_and_manifest_owner(host: Path) -> None:
    tree = Tree(str(host))
    entry = tree.entry("/etc/shadow")
    data = (host / "etc" / "shadow").read_bytes()
    assert entry is not None
    assert entry.kind == "file"
    assert entry.sha256 == hashlib.sha256(data).hexdigest()
    assert entry.size == len(data)
    assert (entry.mode, entry.uid, entry.gid) == (0o640, 0, 42)
    assert entry.error is None


def test_setuid_mode_comes_from_the_manifest_and_missing_path_is_none(host: Path) -> None:
    tree = Tree(str(host))
    passwd = tree.entry("/usr/bin/passwd")
    assert passwd is not None and passwd.mode == 0o4755
    assert tree.entry("/etc/does-not-exist") is None
    assert tree.entry("/etc/passwd/child") is None  # a file is not a directory


def test_manifest_is_reloaded_when_it_changes(host: Path) -> None:
    tree = Tree(str(host))
    before = tree.entry("/etc/passwd")
    assert before is not None and before.uid == 0
    set_meta(host, "/etc/passwd", 0o666, 1000, 1000)
    after = tree.entry("/etc/passwd")
    assert after is not None and (after.mode, after.uid, after.gid) == (0o666, 1000, 1000)


def test_large_file_hash_streams_in_chunks(host: Path) -> None:
    blob = os.urandom(3 * 1024 * 1024 + 7)
    (host / "usr" / "bin" / "big").write_bytes(blob)
    entry = Tree(str(host)).entry("/usr/bin/big")
    assert entry is not None and entry.sha256 == hashlib.sha256(blob).hexdigest()
    assert entry.size == len(blob)


def test_a_file_swapped_between_lstat_and_open_is_an_error(host: Path) -> None:
    tree = Tree(str(host))
    other = os.lstat(host / "etc" / "group")
    with pytest.raises(OSError, match="replaced"):
        tree._hash("/etc/passwd", other)


def test_expand_matches_globs_per_component(host: Path) -> None:
    write(host, "/home/bob/.ssh/authorized_keys", "k\n")
    write(host, "/home/carol/notes", "n\n")
    tree = Tree(str(host))
    assert tree.expand("/home/*/.ssh") == ["/home/alice/.ssh", "/home/bob/.ssh"]
    assert tree.expand("/etc/passwd") == ["/etc/passwd"]
    assert tree.expand("/nope/*") == []
    assert tree.expand("/etc/passwd/*") == []


def test_walk_covers_the_policy_and_skips_uncovered_and_manifest(host: Path) -> None:
    paths, errors = Tree(str(host)).walk(load(None))
    assert errors == {}
    assert "/etc/hostname" not in paths
    assert not any(p.startswith("/.fim-meta") for p in paths)
    for expected in (
        "/etc/passwd",
        "/etc/sudoers.d/90-admins",
        "/root/.ssh/authorized_keys",
        "/home/alice/.ssh/authorized_keys",
        "/var/spool/cron/crontabs/alice",
        "/usr/bin/passwd",
        "/usr/bin",
    ):
        assert expected in paths
    assert len(paths) == 27


def test_walk_from_a_new_directory_finds_covered_paths_below_it(host: Path) -> None:
    write(host, "/home/eve/.ssh/authorized_keys", "ssh-ed25519 EXAMPLE-NOT-A-REAL-KEY eve\n")
    write(host, "/home/eve/junk/file", "x\n")
    paths, _ = Tree(str(host)).walk(load(None), "/home/eve")
    assert paths == ["/home/eve/.ssh", "/home/eve/.ssh/authorized_keys"]


def test_a_top_level_glob_never_reports_the_fixture_manifest(host: Path) -> None:
    policy = loads(
        'version = 1\n[[group]]\nname = "all"\nseverity = "low"\npaths = ["/*"]\nrecursive = true\n'
    )
    tree = Tree(str(host))
    assert tree.expand("/*") == ["/etc", "/home", "/root", "/usr", "/var"]
    paths, _ = tree.walk(policy)
    assert "/etc/hostname" in paths
    assert not any(p.startswith("/.fim-meta") for p in paths)


def test_non_recursive_group_stops_after_one_level(host: Path) -> None:
    write(host, "/usr/bin/sub/deep", "x\n")
    paths, _ = Tree(str(host)).walk(load(None))
    assert "/usr/bin/sub" in paths
    assert "/usr/bin/sub/deep" not in paths


def test_walk_refuses_more_paths_than_the_cap(host: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("file_integrity_monitor.tree.MAX_ENTRIES", 5)
    with pytest.raises(TreeError, match="more than 5"):
        Tree(str(host)).walk(load(None))


def test_root_must_be_a_directory(tmp_path: Path) -> None:
    with pytest.raises(TreeError, match="not a directory"):
        Tree(str(tmp_path / "missing"))


@pytest.mark.skipif(sys.platform == "linux", reason="checks the off-Linux refusal")
def test_drive_root_is_refused_off_linux() -> None:
    with pytest.raises(TreeError, match="drive root"):
        Tree(Path.cwd().anchor)


def test_real_path_mapping_stays_under_the_root(host: Path) -> None:
    tree = Tree(str(host))
    assert Path(tree.real("/etc/passwd")) == host.resolve() / "etc" / "passwd"
    assert Path(tree.real("/")) == host.resolve()
    with pytest.raises(ValueError, match=r"'\.\.'"):
        tree.real("/etc/../../outside")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("0644\t0\t0\n", "4 tab-separated"),
        ("06x4\t0\t0\t/etc/a\n", "line 1"),
        ("0644\t-1\t0\t/etc/a\n", "out of range"),
        ("17777\t0\t0\t/etc/a\n", "out of range"),
        ("0644\t0\t0\tetc/a\n", "absolute"),
    ],
)
def test_parse_meta_rejects_bad_lines(text: str, message: str) -> None:
    with pytest.raises(TreeError, match=message):
        parse_meta(text)


def test_parse_meta_skips_comments_and_blank_lines() -> None:
    assert parse_meta("# c\n\n0600\t1\t2\t/a b\n") == {"/a b": (0o600, 1, 2)}


def test_oversized_manifest_is_refused(host: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("file_integrity_monitor.tree.MAX_META_BYTES", 10)
    with pytest.raises(TreeError, match="larger than"):
        Tree(str(host)).entry("/etc/passwd")


def test_entry_round_trips_and_rejects_bad_fields() -> None:
    e = Entry("/etc/a", "file", 0o4755, 0, 0, 3, "a" * 64)
    assert Entry.from_dict(e.to_dict()) == e
    assert e.to_dict()["mode"] == "4755"
    good = e.to_dict()
    bad_inputs: list[tuple[object, str]] = [
        ({**good, "kind": "pipe"}, "unknown kind"),
        ({**good, "mode": "17777"}, "bad mode"),
        ({**good, "mode": "9"}, "malformed entry"),
        ({**good, "uid": -1}, "bad mode"),
        ({**good, "uid": True}, "bad mode"),
        ({**good, "sha256": "abc"}, "bad sha256"),
        ({**good, "size": -1}, "bad size"),
        ({**good, "path": "../x"}, "absolute"),
        ({k: v for k, v in good.items() if k != "gid"}, "malformed entry"),
        ("not a dict", "must be an object"),
    ]
    for bad, message in bad_inputs:
        with pytest.raises(ValueError, match=message):  # TreeError and PolicyError
            Entry.from_dict(bad)


def test_kind_of_maps_mode_bits() -> None:
    assert kind_of(0o100644) == "file"
    assert kind_of(0o040755) == "dir"
    assert kind_of(0o120777) == "symlink"
    assert kind_of(0o010644) == "other"


@pytest.mark.linux
@linux
def test_symlink_is_recorded_and_not_followed(host: Path) -> None:
    os.symlink("/etc/shadow", host / "usr" / "bin" / "link")
    entry = Tree(str(host)).entry("/usr/bin/link")
    assert entry is not None and entry.kind == "symlink" and entry.target == "/etc/shadow"
    assert entry.sha256 is None


@pytest.mark.linux
@linux
def test_fifo_is_recorded_without_opening_it(host: Path) -> None:
    os.mkfifo(host / "usr" / "bin" / "pipe")  # type: ignore[attr-defined,unused-ignore]
    entry = Tree(str(host)).entry("/usr/bin/pipe")
    assert entry is not None and entry.kind == "other" and entry.sha256 is None


@pytest.mark.linux
@linux
def test_unlistable_directory_is_reported_not_skipped(host: Path) -> None:
    locked = host / "etc" / "cron.d"
    locked.chmod(0)
    try:
        if os.access(locked, os.R_OK):
            pytest.skip("running as root: every directory is listable")
        policy = loads(
            'version = 1\n[[group]]\nname = "c"\nseverity = "high"\n'
            'paths = ["/etc/cron.d"]\nrecursive = true\n'
        )
        entries = Tree(str(host)).scan(policy)
    finally:
        locked.chmod(0o755)
    assert entries["/etc/cron.d"].error is not None
