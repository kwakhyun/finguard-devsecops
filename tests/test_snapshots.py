from __future__ import annotations

import os
from pathlib import Path

import pytest

from finguard.errors import FinGuardError
from finguard.snapshots import InputSnapshot


def test_oversized_input_is_rejected_before_creating_destination(tmp_path: Path) -> None:
    source = tmp_path / "large.json"
    source.write_bytes(b"x" * 9)
    target = tmp_path / "private/input.json"
    with pytest.raises(FinGuardError, match="file limit"):
        InputSnapshot(max_file_bytes=8).copy_file(source, target)
    assert not target.parent.exists()


def test_snapshot_shares_total_size_and_entry_limits(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.write_bytes(b"1234")
    copier = InputSnapshot(max_file_bytes=4, max_total_bytes=8, max_files=3)
    copier.copy_file(source, tmp_path / "first")
    copier.copy_file(source, tmp_path / "second")
    with pytest.raises(FinGuardError, match="total limit"):
        copier.copy_file(source, tmp_path / "third")
    assert not (tmp_path / "third").exists()

    source.write_bytes(b"")
    copier = InputSnapshot(max_files=1)
    copier.copy_file(source, tmp_path / "empty")
    with pytest.raises(FinGuardError, match="input entries"):
        copier.copy_file(source, tmp_path / "too-many")


@pytest.mark.parametrize("limit", ["file", "total"])
def test_input_growth_during_copy_is_bounded_and_partial_file_removed(
    tmp_path: Path, monkeypatch, limit: str
) -> None:
    source = tmp_path / "growing"
    source.write_bytes(b"1234")
    original_fstat = os.fstat

    def grow_after_stat(descriptor):
        info = original_fstat(descriptor)
        with source.open("ab") as handle:
            handle.write(b"56789")
        return info

    monkeypatch.setattr("finguard.snapshots.os.fstat", grow_after_stat)
    copier = InputSnapshot(
        max_file_bytes=8 if limit == "file" else 100, max_total_bytes=8 if limit == "total" else 100
    )
    target = tmp_path / "snapshot"
    with pytest.raises(FinGuardError, match="while copying"):
        copier.copy_file(source, target)
    assert not target.exists()
    assert copier.total_bytes <= 8


def test_snapshot_never_overwrites_an_existing_target(tmp_path: Path) -> None:
    source, target = tmp_path / "source", tmp_path / "target"
    source.write_text("new")
    target.write_text("preserve")
    with pytest.raises(FinGuardError, match="cannot snapshot"):
        InputSnapshot().copy_file(source, target)
    assert target.read_text() == "preserve"


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_snapshot_rejects_nonregular_files_without_reading(tmp_path: Path, kind: str) -> None:
    source = tmp_path / "unsafe"
    if kind == "symlink":
        source.symlink_to(tmp_path / "missing")
    else:
        os.mkfifo(source)
    with pytest.raises(FinGuardError):
        InputSnapshot().copy_file(source, tmp_path / "snapshot")


def test_directory_snapshot_counts_empty_directories_and_rejects_links(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "a/b").mkdir(parents=True)
    with pytest.raises(FinGuardError, match="input entries"):
        InputSnapshot(max_files=1).copy_directory(source, tmp_path / "limited")
    (source / "link").symlink_to(tmp_path / "missing")
    with pytest.raises(FinGuardError, match="symlink"):
        InputSnapshot().copy_directory(source, tmp_path / "linked")
