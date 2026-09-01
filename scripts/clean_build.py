#!/usr/bin/env python3
"""Remove only this repository's conventional build directory."""

from __future__ import annotations

import shutil
from pathlib import Path


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    target = (project_root / "build").resolve()
    if target.parent != project_root or target.name != "build":
        raise SystemExit("refusing to clean anything except the repository build directory")
    shutil.rmtree(target, ignore_errors=True)


if __name__ == "__main__":
    main()
