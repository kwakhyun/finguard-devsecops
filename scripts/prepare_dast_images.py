"""Pull digest-pinned DAST images into this job's Podman storage before --pull=never."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

from finguard.release import validate_image_reference


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", nargs="+")
    args = parser.parse_args()
    for image in args.images:
        validate_image_reference(image)
    registry = os.environ.get("CI_REGISTRY", "")
    username = os.environ.get("CI_REGISTRY_USER", "")
    password = os.environ.get("CI_REGISTRY_PASSWORD", "")
    if any((registry, username, password)) and not all((registry, username, password)):
        parser.error("CI registry authentication requires registry, username, and password")
    with tempfile.TemporaryDirectory(prefix="finguard-dast-auth-") as temporary:
        auth = ["--authfile", str(Path(temporary) / "auth.json")] if registry else []
        if registry:
            subprocess.run(  # noqa: S603 - fixed executable, no shell; secret on stdin
                ["podman", "login", *auth, "--username", username, "--password-stdin", registry],  # noqa: S607
                input=password,
                text=True,
                check=True,
                timeout=120,
            )
        for image in args.images:
            subprocess.run(  # noqa: S603 - validated digest, no shell
                ["podman", "pull", *auth, image],  # noqa: S607 - trusted CI runner PATH
                check=True,
                timeout=300,
            )


if __name__ == "__main__":
    main()
