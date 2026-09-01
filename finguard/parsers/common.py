"""Shared parser helpers."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from finguard.errors import ReportParseError
from finguard.jsonio import strict_json_loads

MAX_REPORT_BYTES = 50 * 1024 * 1024


def load_json(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            raise ReportParseError(f"JSON report exceeds 50 MiB limit: {path}")
        return strict_json_loads(path.read_text(encoding="utf-8"))
    except ReportParseError:
        raise
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ReportParseError(f"cannot parse JSON report {path}: {exc}") from exc


def generated_at(path: Path) -> str:
    try:
        timestamp = path.stat().st_mtime
    except OSError as exc:
        raise ReportParseError(f"cannot stat report {path}: {exc}") from exc
    return dt.datetime.fromtimestamp(timestamp, tz=dt.UTC).isoformat()


def location(path: object, line: object = None, column: object = None) -> str:
    result = str(path or "")
    if line not in (None, ""):
        result += f":{line}"
        if column not in (None, ""):
            result += f":{column}"
    return result
