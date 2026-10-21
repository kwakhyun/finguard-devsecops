"""Run the standard ZAP image with a private, writable scan directory."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from finguard.errors import FinGuardError
from finguard.release import validate_image_reference

ZAP_UID = 1000
ZAP_GID = 1000


def cleanup_scan(
    container: str,
    work: Path,
    *,
    primary_error: BaseException | None,
    scan_status: int | None,
) -> None:
    try:
        subprocess.run(  # noqa: S603 - fixed executable and generated container name
            ["podman", "rm", "--force", "--ignore", container],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Only remove the bind mount after the container is confirmed stopped.
        shutil.rmtree(work)
    except (OSError, subprocess.SubprocessError) as exc:
        detail = f"ZAP cleanup failed; retained scan directory {work}: {exc}"
        if primary_error is not None:
            primary_error.add_note(detail)
            print(detail, file=sys.stderr)
        elif scan_status is not None and scan_status not in (0, 1, 2):
            print(detail, file=sys.stderr)
        else:
            raise FinGuardError(detail) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--rules", type=Path, default=Path("config/zap-rules.conf"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    validate_image_reference(args.image)
    output = args.output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".finguard-zap-", dir=output.parent))
    container = f"finguard-zap-{uuid.uuid4().hex}"
    scan_status = None
    started = False
    try:
        rules = work / "zap-rules.conf"
        shutil.copyfile(args.rules, rules)
        rules.chmod(0o644)
        command = ["podman", "run", "--rm", "--name", container, "--network", args.network]
        if os.geteuid() == 0:
            # Rootful local runners can give only this private directory to zap.
            os.chown(work, ZAP_UID, ZAP_GID)
        else:
            # Map the host CI user to zap, so 0700 remains writable without chmod 777.
            command.append(f"--userns=keep-id:uid={ZAP_UID},gid={ZAP_GID}")
        command.extend(
            [
                "--user",
                f"{ZAP_UID}:{ZAP_GID}",
                "--volume",
                f"{work}:/zap/wrk:rw,Z",
                "--pull=never",
                args.image,
                "zap-baseline.py",
                "-t",
                args.target,
                "-c",
                rules.name,
                "-J",
                "zap.json",
            ]
        )
        started = True
        result = subprocess.run(  # noqa: S603 - fixed command and argv; no shell
            command, check=False, timeout=600
        )
        scan_status = result.returncode
        report = work / "zap.json"
        if report.is_symlink() or not report.is_file():
            raise FinGuardError("ZAP did not produce a regular zap.json report")
        shutil.copyfile(report, output)
        return result.returncode
    finally:
        if started:
            cleanup_scan(container, work, primary_error=sys.exception(), scan_status=scan_status)
        else:
            shutil.rmtree(work)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FinGuardError, OSError, subprocess.SubprocessError) as exc:
        print(f"ZAP scan failed: {exc}", file=sys.stderr)
        raise SystemExit(3) from exc
