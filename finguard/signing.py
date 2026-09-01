"""External asymmetric signing adapter for evidence manifests."""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

from .errors import ConfigurationError, EvidenceVerificationError
from .safeio import assert_no_symlink_components

Runner = Callable[..., subprocess.CompletedProcess[str]]


def cosign_sign_blob(
    blob: Path,
    bundle: Path,
    *,
    key: str,
    runner: Runner = subprocess.run,
    force: bool = False,
) -> None:
    """Sign a blob using a Cosign key path, KMS URI, or Vault URI."""

    if not key.strip():
        raise EvidenceVerificationError("Cosign signing key or KMS URI is required")
    try:
        safe_blob = _regular_file(blob, context="Cosign signing input")
        assert_no_symlink_components(bundle, context="Cosign bundle output")
        bundle.parent.mkdir(parents=True, exist_ok=True)
        assert_no_symlink_components(bundle, context="Cosign bundle output")
        safe_bundle = bundle.resolve()
        if safe_bundle == safe_blob:
            raise ConfigurationError("Cosign input and bundle output paths must differ")
        if safe_bundle.exists() and not force:
            raise ConfigurationError("Cosign bundle output already exists")
        if safe_bundle.exists() and not safe_bundle.is_file():
            raise ConfigurationError("Cosign bundle output must be a regular file")
    except (ConfigurationError, OSError) as exc:
        raise EvidenceVerificationError(f"unsafe Cosign bundle output: {bundle}") from exc
    descriptor, staging_name = tempfile.mkstemp(
        prefix=f".{safe_bundle.name}.", suffix=".tmp", dir=str(safe_bundle.parent)
    )
    os.close(descriptor)
    staging = Path(staging_name)
    try:
        command = [
            "cosign",
            "sign-blob",
            "--yes",
            "--key",
            key,
            "--bundle",
            str(staging),
            str(safe_blob),
        ]
        _run(runner, command)
        if not staging.is_file() or staging.stat().st_size == 0:
            raise EvidenceVerificationError("Cosign did not create the requested signature bundle")
        if force:
            os.replace(staging, safe_bundle)
        else:
            # A hard link publishes the fully written file without replacing a
            # result created by a concurrent process between validation and publish.
            os.link(staging, safe_bundle)
            staging.unlink()
    except FileExistsError as exc:
        raise EvidenceVerificationError("Cosign bundle output already exists") from exc
    except OSError as exc:
        raise EvidenceVerificationError("cannot publish Cosign signature bundle") from exc
    finally:
        staging.unlink(missing_ok=True)


def cosign_verify_blob(
    blob: Path,
    bundle: Path,
    *,
    key: str = "",
    certificate_identity: str = "",
    certificate_oidc_issuer: str = "",
    runner: Runner = subprocess.run,
) -> None:
    """Verify a key-backed or keyless Cosign bundle without shell interpolation."""

    key_backed = bool(key.strip())
    keyless_options = bool(certificate_identity or certificate_oidc_issuer)
    if key_backed and keyless_options:
        raise EvidenceVerificationError(
            "Cosign verification cannot mix a public key with keyless identity constraints"
        )
    if not key_backed and bool(certificate_identity) != bool(certificate_oidc_issuer):
        raise EvidenceVerificationError(
            "keyless Cosign verification requires identity and OIDC issuer"
        )
    try:
        safe_blob = _regular_file(blob, context="Cosign verification input")
        safe_bundle = _regular_file(bundle, context="Cosign verification bundle")
        if safe_blob == safe_bundle:
            raise ConfigurationError("Cosign input and verification bundle must differ")
    except (ConfigurationError, OSError) as exc:
        raise EvidenceVerificationError("Cosign evidence input is missing or unsafe") from exc
    command = ["cosign", "verify-blob", "--bundle", str(safe_bundle)]
    if key_backed:
        command.extend(["--key", key])
    else:
        if not certificate_identity or not certificate_oidc_issuer:
            raise EvidenceVerificationError(
                "keyless Cosign verification requires certificate identity and OIDC issuer"
            )
        command.extend(
            [
                "--certificate-identity",
                certificate_identity,
                "--certificate-oidc-issuer",
                certificate_oidc_issuer,
            ]
        )
    command.append(str(safe_blob))
    _run(runner, command)


def _regular_file(path: Path, *, context: str) -> Path:
    expanded = path.expanduser()
    assert_no_symlink_components(expanded, context=context)
    resolved = expanded.resolve(strict=True)
    if not resolved.is_file():
        raise OSError(f"not a regular file: {path}")
    return resolved


def _run(runner: Runner, command: Sequence[str]) -> None:
    try:
        runner(
            list(command),
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        # Command output can contain signer or environment details and is not persisted.
        raise EvidenceVerificationError(f"Cosign operation failed: {type(exc).__name__}") from exc
