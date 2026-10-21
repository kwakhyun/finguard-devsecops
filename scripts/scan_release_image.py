"""Scan a GitLab release image with registry-scoped, temporary credentials."""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from finguard.errors import FinGuardError
from finguard.release import validate_image_reference


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--format", choices=("json", "cyclonedx"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("config/trivy.yaml"))
    args = parser.parse_args()
    validate_image_reference(args.image)
    registry = os.environ.get("CI_REGISTRY", "")
    username = os.environ.get("CI_REGISTRY_USER", "")
    password = os.environ.get("CI_REGISTRY_PASSWORD", "")
    if not all((registry, username, password)):
        raise FinGuardError("CI registry authentication requires registry, username, and password")
    if args.image.split("/", 1)[0] != registry:
        raise FinGuardError("release image must belong to CI_REGISTRY")

    with tempfile.TemporaryDirectory(prefix="finguard-sca-auth-") as temporary:
        config = Path(temporary) / "config.json"
        auth = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"auths": {registry: {"auth": auth}}}, stream)
        environment = os.environ.copy()
        environment["DOCKER_CONFIG"] = temporary
        for variable in (
            "CI_REGISTRY_PASSWORD",
            "TRIVY_USERNAME",
            "TRIVY_PASSWORD",
            "TRIVY_REGISTRY_TOKEN",
        ):
            environment.pop(variable, None)
        command = ["trivy", "--config", str(args.config), "image"]
        if args.format == "json":
            command.extend(["--scanners", "vuln,misconfig,secret,license", "--license-full"])
        command.extend(["--format", args.format, "--output", str(args.output), args.image])
        result = subprocess.run(  # noqa: S603 - fixed scanner, validated image; no shell
            command, env=environment, check=False, timeout=600
        )
        return result.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FinGuardError, OSError, subprocess.SubprocessError) as exc:
        print(f"release image scan failed: {exc}", file=sys.stderr)
        raise SystemExit(3) from exc
