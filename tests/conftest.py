"""Shared fixtures: a private copy of the fixture host tree for each test."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "host"


@pytest.fixture
def host(tmp_path: Path) -> Path:
    """A writable copy of tests/fixtures/host (under the repo's .tmp/pytest)."""
    dest = tmp_path / "host"
    shutil.copytree(FIXTURE, dest)
    return dest


def write(root: Path, path: str, text: str) -> None:
    """Create or overwrite a file at an absolute Linux path inside the tree."""
    target = root.joinpath(*path.strip("/").split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")


def set_meta(root: Path, path: str, mode: int, uid: int, gid: int) -> None:
    """Set (or add) a path's mode and owner in the tree's stat manifest."""
    manifest = root / ".fim-meta" / "stat.tsv"
    lines = [
        line
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if not line.endswith("\t" + path)
    ]
    lines.append(f"{mode:04o}\t{uid}\t{gid}\t{path}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
