"""Evidence filesystem ownership, publication and shared encoding primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .errors import ConfigurationError, EvidenceVerificationError
from .jsonio import strict_json_loads

BUNDLE_MARKER = ".finguard-evidence"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise EvidenceVerificationError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _validate_output_target(output: Path, *, force: bool) -> None:
    protected = {Path(output.anchor).resolve(), Path.home().resolve(), Path.cwd().resolve()}
    for candidate in (Path.cwd(), *Path.cwd().parents):
        if (candidate / ".git").exists():
            protected.add(candidate.resolve())
    if output in protected or len(output.parts) < 3:
        raise ConfigurationError(f"refusing unsafe evidence output path: {output}")
    if output.is_symlink():
        raise ConfigurationError(f"refusing symlink evidence output path: {output}")
    if output.exists() and not output.is_dir():
        raise ConfigurationError(f"evidence output exists and is not a directory: {output}")
    if output.exists() and any(output.iterdir()):
        if not force:
            raise ConfigurationError(f"evidence output is not empty (use --force): {output}")
        if not _owned_bundle(output, verify_core=True):
            raise ConfigurationError(
                f"refusing to replace directory not owned by FinGuard: {output}"
            )


def _publish_bundle(staging: Path, output: Path, *, force: bool) -> None:
    _validate_output_target(output, force=force)
    if not output.exists():
        os.replace(staging, output)
        return
    backup = output.parent / f".{output.name}.backup-{uuid.uuid4().hex}"
    os.replace(output, backup)
    try:
        os.replace(staging, output)
    except BaseException:
        os.replace(backup, output)
        raise
    _remove_replaced_target(backup)


def _remove_replaced_target(path: Path) -> None:
    if path.is_symlink():
        path.unlink()
        return
    if not path.is_dir():
        raise ConfigurationError(f"unexpected evidence backup type: {path}")
    if any(path.iterdir()):
        if not _owned_bundle(path, verify_core=True):
            raise ConfigurationError(f"refusing to remove unowned evidence backup: {path}")
        shutil.rmtree(path)
    else:
        path.rmdir()


def _owned_bundle(path: Path, *, verify_core: bool = False) -> bool:
    marker = path / BUNDLE_MARKER
    manifest_path = path / "manifest.json"
    if (
        path.is_symlink()
        or marker.is_symlink()
        or manifest_path.is_symlink()
        or not marker.is_file()
        or not manifest_path.is_file()
    ):
        return False
    try:
        value = strict_json_loads(marker.read_text(encoding="utf-8"))
        manifest = strict_json_loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return False
    if not (
        isinstance(value, dict)
        and isinstance(manifest, dict)
        and value.get("schema_version") == "2.0"
        and manifest.get("schema_version") == "3.0"
        and value.get("bundle_type") == "finguard-evidence"
        and manifest.get("bundle_type") == "finguard-evidence"
        and isinstance(value.get("bundle_id"), str)
        and value.get("bundle_id") == manifest.get("bundle_id")
        and len(str(value.get("bundle_id"))) == 32
        and all(character in "0123456789abcdef" for character in str(value["bundle_id"]))
    ):
        return False
    files = manifest.get("files")
    if not isinstance(files, dict):
        return False
    required = {
        BUNDLE_MARKER,
        "decision.json",
        "summary.md",
        "audit.jsonl",
        "inputs/policy.toml",
    }
    if not required.issubset(files):
        return False
    if not verify_core:
        return True
    for relative in required:
        expected = files.get(relative)
        artifact = path / relative
        if (
            not isinstance(expected, dict)
            or artifact.is_symlink()
            or not artifact.is_file()
            or not isinstance(expected.get("sha256"), str)
            or isinstance(expected.get("size"), bool)
            or not isinstance(expected.get("size"), int)
        ):
            return False
        try:
            if not hmac.compare_digest(sha256_file(artifact), expected["sha256"]):
                return False
            if artifact.stat().st_size != expected["size"]:
                return False
        except (OSError, EvidenceVerificationError):
            return False
    return True


def _copy_input(source: Path, destination: Path, name: str) -> Path:
    _assert_no_symlink_components(source, context="evidence input")
    if not source.is_file():
        raise ConfigurationError(f"evidence input does not exist: {source}")
    target = destination / name
    shutil.copy2(source, target)
    return target


def _assert_no_symlink_components(path: Path, *, context: str) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ConfigurationError(f"refusing symlink {context} path: {path}")


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
