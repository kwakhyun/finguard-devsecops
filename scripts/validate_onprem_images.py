#!/usr/bin/env python3
"""Fail before Compose starts unless infrastructure images are pinned and verified."""

from __future__ import annotations

import os
import subprocess

from finguard.errors import FinGuardError
from finguard.release import validate_image_reference


def _verify_image_signature(variable: str, image: str, verification_key: str) -> None:
    command = ["cosign", "verify", "--key", verification_key, image]
    try:
        subprocess.run(  # noqa: S603, S607 - fixed command resolved from the managed PATH
            command,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise FinGuardError("cosign executable not found; install cosign before onprem-up") from exc
    except subprocess.CalledProcessError as exc:
        detail = " ".join((exc.stderr or "").split())[:300]
        suffix = f": {detail}" if detail else ""
        raise FinGuardError(f"{variable} signature verification failed{suffix}") from exc


def main() -> None:
    images: list[tuple[str, str]] = []
    for variable in ("POSTGRES_IMAGE", "SONARQUBE_IMAGE"):
        value = os.environ.get(variable, "")
        validate_image_reference(value, context=variable)
        images.append((variable, value))

    verification_key = os.environ.get("FINGUARD_TOOL_IMAGE_COSIGN_PUBLIC_KEY", "").strip()
    if not verification_key:
        raise FinGuardError("FINGUARD_TOOL_IMAGE_COSIGN_PUBLIC_KEY must be set")
    for variable, image in images:
        _verify_image_signature(variable, image, verification_key)
    print("on-prem infrastructure images are immutable and signatures are verified")


if __name__ == "__main__":
    try:
        main()
    except FinGuardError as exc:
        raise SystemExit(f"finguard: {exc}") from exc
