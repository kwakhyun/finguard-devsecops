from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def current_pass_change(project_root: Path, tmp_path: Path) -> Path:
    source = project_root / "examples/scenarios/pass/change.toml"
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    start = now - dt.timedelta(minutes=5)
    end = start + dt.timedelta(hours=1)
    text = source.read_text(encoding="utf-8")
    lines = []
    for line in text.splitlines():
        if line.startswith("window_start ="):
            line = f"window_start = {start.isoformat()}"
        elif line.startswith("window_end ="):
            line = f"window_end = {end.isoformat()}"
        lines.append(line)
    output = tmp_path / "current-pass-change.toml"
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output
