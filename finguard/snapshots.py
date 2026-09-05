"""Bounded private copies of untrusted inputs used throughout one command."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import FinGuardError
from .safeio import assert_no_symlink_components

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_INPUT_FILES = 2048


@dataclass
class InputSnapshot:
    """Share a byte and entry budget across all inputs, including empty files."""

    max_file_bytes: int = MAX_FILE_BYTES
    max_total_bytes: int = MAX_TOTAL_BYTES
    max_files: int = MAX_INPUT_FILES
    total_bytes: int = 0
    entries: int = 0

    def _reserve_entry(self) -> None:
        if self.entries >= self.max_files:
            raise FinGuardError(f"snapshot exceeds {self.max_files} input entries")
        self.entries += 1

    def copy_file(self, source: Path, target: Path) -> Path:
        created = False
        try:
            assert_no_symlink_components(source, context="snapshot input")
            self._reserve_entry()
            # Nonblocking open avoids hanging if a regular file is replaced by a
            # FIFO; O_NOFOLLOW rejects a last-component symlink replacement.
            descriptor = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as reader:
                info = os.fstat(reader.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise FinGuardError(f"snapshot input is not a regular file: {source}")
                self._check_size(info.st_size)
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as writer:
                    created = True
                    copied = 0
                    while True:
                        # Read at most one byte beyond the remaining allowance,
                        # including when the source grows after fstat.
                        remaining = min(
                            self.max_file_bytes - copied,
                            self.max_total_bytes - self.total_bytes,
                        )
                        chunk = reader.read(min(1024 * 1024, remaining + 1))
                        if not chunk:
                            break
                        if len(chunk) > remaining:
                            raise FinGuardError("snapshot input exceeds byte limit while copying")
                        writer.write(chunk)
                        copied += len(chunk)
                        self.total_bytes += len(chunk)
        except BaseException as exc:
            if created:
                target.unlink(missing_ok=True)
            if isinstance(exc, OSError):
                raise FinGuardError(f"cannot snapshot input {source}: {exc}") from exc
            raise
        return target

    def _check_size(self, size: int) -> None:
        if size > self.max_file_bytes:
            raise FinGuardError(f"snapshot input exceeds {self.max_file_bytes} byte file limit")
        if size > self.max_total_bytes - self.total_bytes:
            raise FinGuardError(f"snapshot exceeds {self.max_total_bytes} byte total limit")

    def copy_optional(self, source: Path | None, target: Path) -> Path | None:
        return self.copy_file(source, target) if source is not None else None

    def copy_directory(self, source: Path, target: Path) -> Path:
        assert_no_symlink_components(source, context="snapshot input")
        if not source.is_dir():
            raise FinGuardError(f"evidence directory does not exist: {source}")
        target.mkdir(parents=True, exist_ok=False)
        pending = [(source, target)]
        try:
            while pending:
                directory, destination = pending.pop()
                assert_no_symlink_components(directory, context="snapshot input")
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if entry.is_symlink():
                            raise FinGuardError(f"evidence contains a symlink: {entry.path}")
                        source_path, target_path = Path(entry.path), destination / entry.name
                        if entry.is_dir(follow_symlinks=False):
                            self._reserve_entry()
                            target_path.mkdir()
                            pending.append((source_path, target_path))
                        else:
                            self.copy_file(source_path, target_path)
        except OSError as exc:
            raise FinGuardError(f"cannot snapshot evidence {source}: {exc}") from exc
        return target


def snapshot_file(source: Path, target: Path) -> Path:
    return InputSnapshot().copy_file(source, target)


def snapshot_evidence_directory(source: Path, target: Path) -> Path:
    return InputSnapshot().copy_directory(source, target)
