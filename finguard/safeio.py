"""Small atomic-write primitive for user-selected FinGuard output paths."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .errors import ConfigurationError


def atomic_write_text(path: Path, content: str, *, context: str) -> None:
    """Replace one regular file atomically without traversing a symlink component."""

    output = path.expanduser()
    assert_no_symlink_components(output, context=context)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        assert_no_symlink_components(output, context=context)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=str(output.parent)
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
    except OSError as exc:
        raise ConfigurationError(f"cannot write {context} {path}: {exc}") from exc


def assert_no_symlink_components(path: Path, *, context: str) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ConfigurationError(f"refusing symlink {context} path: {path}")
