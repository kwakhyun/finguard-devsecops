"""Creation and verification of report-bound scan attestations."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .errors import ConfigurationError, EvidenceVerificationError
from .jsonio import strict_json_loads
from .models import ScanProvenance
from .safeio import atomic_write_text

PREDICATE_TYPE = "https://finguard.dev/attestations/scan/v3"
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise EvidenceVerificationError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def create_scan_attestation(
    output: Path,
    *,
    report_path: Path,
    scanner: str,
    category: str,
    scanner_version: str,
    scanner_uri: str,
    source_commit: str,
    image_digest: str,
    ruleset_sha256: str,
    database_sha256: str = "",
    database_updated_at: str = "",
    command_sha256: str,
    ci_job_id: str,
    runner_id: str,
    exit_code: int,
    complete: bool,
    target_uri: str,
    started_at: dt.datetime,
    finished_at: dt.datetime,
    signing_key: bytes | None = None,
    key_id: str = "",
) -> Path:
    """Write a deterministic envelope bound to one immutable report file."""

    normalized_key_id = key_id.strip()
    if signing_key is not None and not normalized_key_id:
        raise EvidenceVerificationError("attestation key_id is required when signing")
    if signing_key is None and normalized_key_id:
        raise EvidenceVerificationError("attestation key_id requires a signing key")
    payload = _payload(
        report_sha256=sha256_path(report_path),
        scanner=scanner,
        category=category,
        scanner_version=scanner_version,
        scanner_uri=scanner_uri,
        source_commit=source_commit,
        image_digest=image_digest,
        ruleset_sha256=ruleset_sha256,
        database_sha256=database_sha256,
        database_updated_at=database_updated_at,
        command_sha256=command_sha256,
        ci_job_id=ci_job_id,
        runner_id=runner_id,
        exit_code=exit_code,
        complete=complete,
        target_uri=target_uri,
        started_at=started_at,
        finished_at=finished_at,
        key_id=normalized_key_id,
    )
    # Validate before writing so malformed CI metadata can never be attested.
    ScanProvenance.from_dict(payload, signature_present=signing_key is not None)
    envelope: dict[str, Any] = {"payload": payload}
    if signing_key is not None:
        signature = hmac.new(signing_key, _canonical(payload), hashlib.sha256).hexdigest()
        envelope["signature"] = {
            "algorithm": "hmac-sha256",
            "key_id": normalized_key_id,
            "value": signature,
        }
    _write_atomic(output, envelope)
    return output


def load_scan_attestation(
    path: Path,
    *,
    report_path: Path | None = None,
    signing_key: bytes | None = None,
) -> ScanProvenance:
    try:
        envelope = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise EvidenceVerificationError(f"cannot read scan attestation {path}: {exc}") from exc
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
        raise EvidenceVerificationError(f"invalid scan attestation envelope: {path}")
    _exact_keys(envelope, {"payload", "signature"}, "scan attestation envelope")
    payload = envelope["payload"]
    _exact_keys(
        payload,
        {
            "schema_version",
            "predicate_type",
            "report_sha256",
            "scanner",
            "category",
            "scanner_version",
            "scanner_uri",
            "source_commit",
            "image_digest",
            "ruleset_sha256",
            "database_sha256",
            "database_updated_at",
            "command_sha256",
            "ci_job_id",
            "runner_id",
            "exit_code",
            "target_uri",
            "started_at",
            "finished_at",
            "complete",
            "key_id",
        },
        "scan attestation payload",
    )
    if payload.get("schema_version") != "3.0" or payload.get("predicate_type") != PREDICATE_TYPE:
        raise EvidenceVerificationError("unsupported scan attestation schema")
    payload_key_id_raw = payload.get("key_id")
    if not isinstance(payload_key_id_raw, str):
        raise EvidenceVerificationError("scan attestation key_id must be a string")
    payload_key_id = payload_key_id_raw.strip()
    signature = envelope.get("signature")
    if signature is not None and not isinstance(signature, dict):
        raise EvidenceVerificationError("scan attestation signature must be an object")
    signature_present = signature is not None
    signature_mapping: Mapping[str, Any] = signature if isinstance(signature, dict) else {}
    signature_verified = False
    if signature_present:
        _exact_keys(
            signature_mapping,
            {"algorithm", "key_id", "value"},
            "scan attestation signature",
        )
        if signature_mapping.get("algorithm") != "hmac-sha256":
            raise EvidenceVerificationError("unsupported scan attestation signature algorithm")
        if not payload_key_id:
            raise EvidenceVerificationError("signed scan attestation key_id is missing")
        if str(signature_mapping.get("key_id", "")) != payload_key_id:
            raise EvidenceVerificationError(
                "scan attestation signature key_id does not match signed payload"
            )
    if signing_key is not None:
        if not signature_present:
            raise EvidenceVerificationError("scan attestation signature is missing")
        expected = hmac.new(signing_key, _canonical(payload), hashlib.sha256).hexdigest()
        supplied = str(signature_mapping.get("value", ""))
        if not hmac.compare_digest(supplied, expected):
            raise EvidenceVerificationError("scan attestation signature mismatch")
        signature_verified = True

    provenance = ScanProvenance.from_dict(
        payload,
        signature_present=signature_present,
        signature_verified=signature_verified,
    )
    if report_path is not None:
        actual = sha256_path(report_path)
        if not hmac.compare_digest(actual, provenance.report_sha256):
            raise EvidenceVerificationError(
                f"scan attestation does not match report: {report_path}"
            )
    return provenance


def load_attestation_directory(
    directory: Path,
    report_paths: Iterable[Path],
    *,
    signing_key: bytes | None = None,
) -> tuple[dict[str, ScanProvenance], list[Path]]:
    if not directory.is_dir():
        raise EvidenceVerificationError(f"attestation directory does not exist: {directory}")
    reports = {sha256_path(path): path for path in report_paths}
    result: dict[str, ScanProvenance] = {}
    used_paths: list[Path] = []
    for path in sorted(directory.glob("*.json")):
        provenance = load_scan_attestation(path, signing_key=signing_key)
        report_path = reports.get(provenance.report_sha256)
        if report_path is None:
            raise EvidenceVerificationError(
                f"scan attestation references an unknown report: {path}"
            )
        if provenance.report_sha256 in result:
            raise EvidenceVerificationError(f"duplicate scan attestation for report: {report_path}")
        # Re-check through the same verifier to keep the binding explicit.
        provenance = load_scan_attestation(path, report_path=report_path, signing_key=signing_key)
        result[provenance.report_sha256] = provenance
        used_paths.append(path)
    return result, used_paths


def _payload(
    *,
    report_sha256: str,
    scanner: str,
    category: str,
    scanner_version: str,
    scanner_uri: str,
    source_commit: str,
    image_digest: str,
    ruleset_sha256: str,
    database_sha256: str,
    database_updated_at: str,
    command_sha256: str,
    ci_job_id: str,
    runner_id: str,
    exit_code: int,
    complete: bool,
    target_uri: str,
    started_at: dt.datetime,
    finished_at: dt.datetime,
    key_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": "3.0",
        "predicate_type": PREDICATE_TYPE,
        "report_sha256": report_sha256.lower(),
        "scanner": scanner,
        "category": category,
        "scanner_version": scanner_version,
        "scanner_uri": scanner_uri,
        "source_commit": source_commit.lower(),
        "image_digest": image_digest.lower(),
        "ruleset_sha256": ruleset_sha256.lower(),
        "database_sha256": database_sha256.lower(),
        "database_updated_at": database_updated_at,
        "command_sha256": command_sha256.lower(),
        "ci_job_id": ci_job_id,
        "runner_id": runner_id,
        "exit_code": exit_code,
        "target_uri": target_uri,
        "started_at": _as_utc(started_at).isoformat(),
        "finished_at": _as_utc(finished_at).isoformat(),
        "complete": complete,
        "key_id": key_id,
    }


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_sha256(value: str, field: str) -> None:
    if not _SHA256.fullmatch(value):
        raise EvidenceVerificationError(f"{field} must be 64 hexadecimal characters")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        raise EvidenceVerificationError("attestation timestamps must include a timezone")
    return value.astimezone(dt.UTC)


def _write_atomic(output: Path, value: Mapping[str, Any]) -> None:
    try:
        atomic_write_text(
            output,
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            context="scan attestation",
        )
    except ConfigurationError as exc:
        raise EvidenceVerificationError(str(exc)) from exc


def _exact_keys(value: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted(allowed - set(value))
    # Signature is optional only at the envelope level.
    if context == "scan attestation envelope":
        missing = [item for item in missing if item != "signature"]
    if unknown or missing:
        details = []
        if unknown:
            details.append(f"unknown: {', '.join(unknown)}")
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        raise EvidenceVerificationError(f"{context} fields are invalid ({'; '.join(details)})")
