#!/usr/bin/env python3
"""Fail before Compose starts unless every infrastructure image is digest-pinned."""

from __future__ import annotations

import os

from finguard.errors import FinGuardError
from finguard.release import validate_image_reference


def main() -> None:
    for variable in ("POSTGRES_IMAGE", "SONARQUBE_IMAGE"):
        value = os.environ.get(variable, "")
        validate_image_reference(value, context=variable)
    print("on-prem infrastructure image references are immutable")


if __name__ == "__main__":
    try:
        main()
    except FinGuardError as exc:
        raise SystemExit(f"finguard: {exc}") from exc
