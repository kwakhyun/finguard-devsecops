"""Verify bundle contents, signatures and audit consistency."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .errors import ConfigurationError, EvidenceVerificationError
from .evidence_storage import (
    _assert_no_symlink_components,
    _canonical_json,
    _owned_bundle,
    sha256_file,
)
from .jsonio import strict_json_loads
from .release import ReleaseSubject
from .signing import Runner, cosign_verify_blob


def verify_evidence_bundle(
    output: Path,
    signing_key: bytes | None = None,
    *,
    cosign_verification_key: str = "",
    cosign_certificate_identity: str = "",
    cosign_certificate_oidc_issuer: str = "",
    cosign_runner: Runner | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    _assert_no_symlink_components(output.expanduser(), context="evidence bundle")
    output = output.resolve()
    if not _owned_bundle(output):
        raise EvidenceVerificationError("evidence ownership marker is missing or invalid")
    manifest_path = output / "manifest.json"
    try:
        manifest = strict_json_loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise EvidenceVerificationError(f"cannot read evidence manifest: {exc}") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "3.0"
        or manifest.get("bundle_type") != "finguard-evidence"
    ):
        raise EvidenceVerificationError("not a FinGuard evidence manifest")
    _verify_manifest_shape(manifest)
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise EvidenceVerificationError("manifest.files must be an object")
    _verify_closed_world(output, set(files))

    verified_files = 0
    for relative, expected in files.items():
        if not isinstance(relative, str) or not isinstance(expected, dict):
            raise EvidenceVerificationError("manifest contains an invalid file entry")
        relative_path = Path(relative)
        if (
            relative_path.is_absolute()
            or relative_path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in relative_path.parts)
        ):
            raise EvidenceVerificationError(f"manifest contains an unsafe path: {relative}")
        expected_hash = expected.get("sha256")
        expected_size = expected.get("size")
        if (
            set(expected) != {"sha256", "size"}
            or not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(character not in "0123456789abcdef" for character in expected_hash)
            or isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
        ):
            raise EvidenceVerificationError(f"manifest metadata is invalid: {relative}")
        artifact = (output / relative).resolve()
        if output not in artifact.parents:
            raise EvidenceVerificationError(f"manifest path escapes bundle: {relative}")
        if not artifact.is_file():
            raise EvidenceVerificationError(f"evidence file is missing: {relative}")
        actual_hash = sha256_file(artifact)
        if not hmac.compare_digest(actual_hash, expected_hash):
            raise EvidenceVerificationError(f"evidence hash mismatch: {relative}")
        if artifact.stat().st_size != expected_size:
            raise EvidenceVerificationError(f"evidence size mismatch: {relative}")
        verified_files += 1

    signature_path = output / "manifest.sig"
    signature_present = signature_path.is_file()
    signature_verified = False
    signature_key_id = ""
    signature_envelope: Mapping[str, Any] | None = None
    if signature_present:
        signature_envelope = _load_evidence_hmac_signature(
            signature_path,
            manifest=manifest,
            manifest_path=manifest_path,
        )
        signature_key_id = str(signature_envelope["key_id"])
    if signing_key is not None:
        if signature_envelope is None:
            raise EvidenceVerificationError("signing key supplied but manifest.sig is missing")
        signed_payload = {
            key: signature_envelope[key]
            for key in (
                "schema_version",
                "algorithm",
                "key_id",
                "signed_at",
                "manifest_sha256",
            )
        }
        expected_signature = hmac.new(
            signing_key, _canonical_json(signed_payload), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(str(signature_envelope.get("value", "")), expected_signature):
            raise EvidenceVerificationError("evidence signature mismatch")
        signature_verified = True

    cosign_bundle = output / "manifest.sigstore.json"
    cosign_bundle_present = cosign_bundle.is_file()
    cosign_verified = False
    if cosign_verification_key or cosign_certificate_identity or cosign_certificate_oidc_issuer:
        if cosign_runner is None:
            cosign_verify_blob(
                manifest_path,
                cosign_bundle,
                key=cosign_verification_key,
                certificate_identity=cosign_certificate_identity,
                certificate_oidc_issuer=cosign_certificate_oidc_issuer,
            )
        else:
            cosign_verify_blob(
                manifest_path,
                cosign_bundle,
                key=cosign_verification_key,
                certificate_identity=cosign_certificate_identity,
                certificate_oidc_issuer=cosign_certificate_oidc_issuer,
                runner=cosign_runner,
            )
        cosign_verified = True

    if require_signature and not (signature_verified or cosign_verified):
        raise EvidenceVerificationError("a verified evidence signature is required")

    subject_raw = manifest.get("release_subject")
    release_subject: ReleaseSubject | None = None
    if subject_raw is not None:
        if not isinstance(subject_raw, dict):
            raise EvidenceVerificationError("manifest release_subject must be an object")
        try:
            release_subject = ReleaseSubject.from_mapping(
                subject_raw, context="manifest.release_subject"
            )
        except ConfigurationError as exc:
            raise EvidenceVerificationError(str(exc)) from exc
        if release_subject.digest != str(manifest.get("release_subject_sha256", "")):
            raise EvidenceVerificationError("release subject digest mismatch")

    _verify_decision_consistency(output / "decision.json", manifest)
    audit_records = _verify_audit_log(output / "audit.jsonl", manifest)
    policy_metadata = files["inputs/policy.toml"]
    return {
        "verified": True,
        "file_count": verified_files,
        "audit_record_count": audit_records,
        "signature_present": signature_present,
        "signature_verified": signature_verified,
        "signature_key_id": signature_key_id,
        "cosign_bundle_present": cosign_bundle_present,
        "cosign_verified": cosign_verified,
        "decision": manifest.get("decision", "unknown"),
        "policy": manifest.get("policy", {}),
        "policy_sha256": policy_metadata["sha256"],
        "change_id": manifest.get("change_id", ""),
        "evaluated_at": manifest["evaluated_at"],
        "release_subject": release_subject.to_dict() if release_subject else None,
        "release_subject_sha256": release_subject.digest if release_subject else "",
    }


def _verify_closed_world(output: Path, manifested: set[str]) -> None:
    allowed = {*manifested, "manifest.json", "manifest.sig", "manifest.sigstore.json"}
    actual: set[str] = set()
    for root, directories, filenames in os.walk(output, followlinks=False):
        root_path = Path(root)
        for directory in directories:
            candidate = root_path / directory
            if candidate.is_symlink():
                raise EvidenceVerificationError(f"evidence contains a symlink: {candidate}")
        for filename in filenames:
            candidate = root_path / filename
            if candidate.is_symlink():
                raise EvidenceVerificationError(f"evidence contains a symlink: {candidate}")
            actual.add(str(candidate.relative_to(output)))
    extras = sorted(actual - allowed)
    if extras:
        raise EvidenceVerificationError(
            f"evidence contains unmanifested files: {', '.join(extras)}"
        )


def _verify_decision_consistency(path: Path, manifest: Mapping[str, Any]) -> None:
    try:
        decision = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise EvidenceVerificationError(f"cannot read evidence decision: {exc}") from exc
    if not isinstance(decision, dict):
        raise EvidenceVerificationError("evidence decision must be an object")
    expected = {
        "decision": manifest.get("decision"),
        "policy": manifest.get("policy"),
        "change_id": manifest.get("change_id"),
        "release_subject_sha256": manifest.get("release_subject_sha256"),
    }
    mismatches = sorted(name for name, value in expected.items() if decision.get(name) != value)
    if mismatches:
        raise EvidenceVerificationError(f"manifest and decision disagree: {', '.join(mismatches)}")


def _verify_manifest_shape(manifest: Mapping[str, Any]) -> None:
    allowed = {
        "schema_version",
        "bundle_type",
        "bundle_id",
        "decision",
        "policy",
        "change_id",
        "release_subject",
        "release_subject_sha256",
        "evaluated_at",
        "shadow_policy",
        "files",
    }
    if set(manifest) != allowed:
        raise EvidenceVerificationError("evidence manifest fields are invalid")
    bundle_id = manifest.get("bundle_id")
    if (
        not isinstance(bundle_id, str)
        or len(bundle_id) != 32
        or any(character not in "0123456789abcdef" for character in bundle_id)
    ):
        raise EvidenceVerificationError("evidence manifest bundle_id is invalid")
    if manifest.get("decision") not in {"pass", "fail"}:
        raise EvidenceVerificationError("evidence manifest decision is invalid")
    policy = manifest.get("policy")
    if (
        not isinstance(policy, dict)
        or set(policy) != {"id", "version"}
        or not all(isinstance(policy.get(field), str) and policy[field] for field in policy)
    ):
        raise EvidenceVerificationError("evidence manifest policy is invalid")
    if not isinstance(manifest.get("change_id"), str):
        raise EvidenceVerificationError("evidence manifest change_id must be a string")
    evaluated_at = manifest.get("evaluated_at")
    if not isinstance(evaluated_at, str) or not evaluated_at:
        raise EvidenceVerificationError("evidence manifest evaluated_at is invalid")
    try:
        parsed_evaluated_at = dt.datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceVerificationError("evidence manifest evaluated_at is invalid") from exc
    if parsed_evaluated_at.tzinfo is None:
        raise EvidenceVerificationError("evidence manifest evaluated_at needs a timezone")
    shadow = manifest.get("shadow_policy")
    if shadow is not None and (
        not isinstance(shadow, dict)
        or set(shadow) != {"id", "version"}
        or not all(isinstance(shadow.get(field), str) and shadow[field] for field in shadow)
    ):
        raise EvidenceVerificationError("evidence manifest shadow_policy is invalid")
    subject = manifest.get("release_subject")
    subject_digest = manifest.get("release_subject_sha256")
    if subject is None:
        if subject_digest != "":
            raise EvidenceVerificationError("evidence manifest release subject is inconsistent")
    elif (
        not isinstance(subject, dict)
        or not isinstance(subject_digest, str)
        or len(subject_digest) != 64
        or any(character not in "0123456789abcdef" for character in subject_digest)
    ):
        raise EvidenceVerificationError("evidence manifest release subject is invalid")


def _load_evidence_hmac_signature(
    path: Path,
    *,
    manifest: Mapping[str, Any],
    manifest_path: Path,
) -> Mapping[str, Any]:
    """Validate the unsigned structure before optionally authenticating its HMAC."""

    try:
        envelope = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise EvidenceVerificationError(f"cannot read evidence signature: {exc}") from exc
    required = {
        "schema_version",
        "algorithm",
        "key_id",
        "signed_at",
        "manifest_sha256",
        "value",
    }
    if not isinstance(envelope, dict) or set(envelope) != required:
        raise EvidenceVerificationError("unsupported evidence signature format")
    if envelope.get("schema_version") != "2.0" or envelope.get("algorithm") != "hmac-sha256":
        raise EvidenceVerificationError("unsupported evidence signature format")
    key_id = envelope.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip() or key_id != key_id.strip():
        raise EvidenceVerificationError("evidence signature key_id is invalid")
    signed_at = envelope.get("signed_at")
    if not isinstance(signed_at, str):
        raise EvidenceVerificationError("evidence signature signed_at is invalid")
    try:
        parsed_signed_at = dt.datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceVerificationError("evidence signature signed_at is invalid") from exc
    if parsed_signed_at.tzinfo is None or signed_at != manifest.get("evaluated_at"):
        raise EvidenceVerificationError("evidence signature signed_at does not match manifest")
    manifest_digest = envelope.get("manifest_sha256")
    if not isinstance(manifest_digest, str) or not hmac.compare_digest(
        manifest_digest, sha256_file(manifest_path)
    ):
        raise EvidenceVerificationError("evidence signature manifest digest mismatch")
    signature = envelope.get("value")
    if (
        not isinstance(signature, str)
        or len(signature) != 64
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        raise EvidenceVerificationError("evidence signature value is invalid")
    return envelope


def _verify_audit_log(path: Path, manifest: Mapping[str, Any]) -> int:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise EvidenceVerificationError(f"cannot read audit log: {exc}") from exc
    previous = "0" * 64
    records: list[dict[str, Any]] = []
    for expected_sequence, line in enumerate(lines, start=1):
        try:
            record = strict_json_loads(line)
        except ValueError as exc:
            raise EvidenceVerificationError("audit log contains invalid JSON") from exc
        if not isinstance(record, dict):
            raise EvidenceVerificationError("audit log record must be an object")
        if record.get("sequence") != expected_sequence or record.get("previous_hash") != previous:
            raise EvidenceVerificationError("audit log chain is out of order")
        claimed_hash = str(record.pop("record_hash", ""))
        canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        actual_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(claimed_hash, actual_hash):
            raise EvidenceVerificationError("audit log record hash mismatch")
        previous = actual_hash
        records.append(record)
    if len(records) < 2:
        raise EvidenceVerificationError("audit log is incomplete")
    first = records[0]
    last = records[-1]
    policy = manifest["policy"]
    if (
        first.get("event") != "policy.loaded"
        or first.get("policy_id") != policy["id"]
        or first.get("policy_version") != policy["version"]
    ):
        raise EvidenceVerificationError("audit log policy event is inconsistent")
    if (
        last.get("event") != "gate.evaluated"
        or last.get("decision") != manifest.get("decision")
        or last.get("change_id") != manifest.get("change_id")
    ):
        raise EvidenceVerificationError("audit log gate event is inconsistent")
    return len(records)
