"""Tamper-evident evidence bundle generation and verification."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import shutil
import tempfile
import uuid
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .errors import ConfigurationError, EvidenceVerificationError
from .jsonio import strict_json_loads
from .models import GateResult
from .release import ReleaseSubject
from .reporting import compare_gate_results
from .signing import Runner, cosign_sign_blob, cosign_verify_blob

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


def create_evidence_bundle(
    output: Path,
    *,
    result: GateResult,
    shadow_result: GateResult | None = None,
    policy_path: Path,
    report_paths: Iterable[Path],
    attestation_paths: Iterable[Path] = (),
    approval_attestation_path: Path | None = None,
    approval_signature_path: Path | None = None,
    vex_attestation_path: Path | None = None,
    vex_signature_path: Path | None = None,
    change_path: Path | None = None,
    exceptions_path: Path | None = None,
    signing_key: bytes | None = None,
    signing_key_id: str = "local-hmac",
    cosign_signing_key: str = "",
    cosign_runner: Runner | None = None,
    force: bool = False,
) -> Path:
    """Create a self-contained evidence directory and return its manifest path."""

    requested_output = output.expanduser()
    _assert_no_symlink_components(requested_output, context="evidence output")
    output = requested_output.resolve()
    _validate_output_target(output, force=force)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=str(output.parent))
    ).resolve()
    try:
        _write_bundle(
            staging,
            result=result,
            shadow_result=shadow_result,
            policy_path=policy_path,
            report_paths=report_paths,
            attestation_paths=attestation_paths,
            approval_attestation_path=approval_attestation_path,
            approval_signature_path=approval_signature_path,
            vex_attestation_path=vex_attestation_path,
            vex_signature_path=vex_signature_path,
            change_path=change_path,
            exceptions_path=exceptions_path,
            signing_key=signing_key,
            signing_key_id=signing_key_id,
            cosign_signing_key=cosign_signing_key,
            cosign_runner=cosign_runner,
        )
        _publish_bundle(staging, output, force=force)
    except BaseException:
        if staging.exists() and staging.parent == output.parent:
            shutil.rmtree(staging)
        raise
    return output / "manifest.json"


def _write_bundle(
    output: Path,
    *,
    result: GateResult,
    shadow_result: GateResult | None,
    policy_path: Path,
    report_paths: Iterable[Path],
    attestation_paths: Iterable[Path],
    approval_attestation_path: Path | None,
    approval_signature_path: Path | None,
    vex_attestation_path: Path | None,
    vex_signature_path: Path | None,
    change_path: Path | None,
    exceptions_path: Path | None,
    signing_key: bytes | None,
    signing_key_id: str,
    cosign_signing_key: str,
    cosign_runner: Runner | None,
) -> None:
    bundle_id = uuid.uuid4().hex
    _write_json(
        output / BUNDLE_MARKER,
        {
            "schema_version": "2.0",
            "bundle_type": "finguard-evidence",
            "bundle_id": bundle_id,
        },
    )
    inputs = output / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)

    copied: list[tuple[str, Path]] = []
    copied.append(("policy", _copy_input(policy_path, inputs, "policy.toml")))
    if change_path is not None:
        copied.append(("change", _copy_input(change_path, inputs, "change.toml")))
    if approval_attestation_path is not None:
        copied.append(
            (
                "approval_attestation",
                _copy_input(
                    approval_attestation_path,
                    inputs,
                    "approval-attestation.json",
                ),
            )
        )
    if approval_signature_path is not None:
        copied.append(
            (
                "approval_signature",
                _copy_input(
                    approval_signature_path,
                    inputs,
                    "approval-attestation.sigstore.json",
                ),
            )
        )
    if vex_attestation_path is not None:
        copied.append(
            (
                "vex_attestation",
                _copy_input(vex_attestation_path, inputs, "vex-attestation.json"),
            )
        )
    if vex_signature_path is not None:
        copied.append(
            (
                "vex_signature",
                _copy_input(vex_signature_path, inputs, "vex-attestation.sigstore.json"),
            )
        )
    if exceptions_path is not None:
        copied.append(("exceptions", _copy_input(exceptions_path, inputs, "exceptions.toml")))
    for index, report in enumerate(sorted(report_paths, key=lambda item: str(item))):
        safe_name = f"report-{index + 1:02d}-{report.name}"
        copied.append(("report", _copy_input(report, inputs, safe_name)))
    for index, attestation in enumerate(sorted(attestation_paths, key=lambda item: str(item))):
        safe_name = f"attestation-{index + 1:02d}-{attestation.name}"
        copied.append(("attestation", _copy_input(attestation, inputs, safe_name)))

    if result.release_subject is not None:
        _write_json(output / "release-subject.json", result.release_subject.to_dict())

    decision_path = output / "decision.json"
    _write_json(decision_path, result.to_dict())
    if shadow_result is not None:
        _write_json(output / "shadow-decision.json", shadow_result.to_dict())
        _write_json(
            output / "policy-comparison.json",
            compare_gate_results(result, shadow_result),
        )
    summary_path = output / "summary.md"
    summary_path.write_text(_render_summary(result), encoding="utf-8")
    audit_path = output / "audit.jsonl"
    _write_audit_log(audit_path, result, copied)

    files = sorted(
        path for path in output.rglob("*") if path.is_file() and path.name != "manifest.json"
    )
    manifest_payload: dict[str, Any] = {
        "schema_version": "3.0",
        "bundle_type": "finguard-evidence",
        "bundle_id": bundle_id,
        "decision": result.decision.value,
        "policy": {"id": result.policy_id, "version": result.policy_version},
        "change_id": result.change_id,
        "release_subject": (result.release_subject.to_dict() if result.release_subject else None),
        "release_subject_sha256": (result.release_subject.digest if result.release_subject else ""),
        "evaluated_at": result.evaluated_at,
        "shadow_policy": (
            {"id": shadow_result.policy_id, "version": shadow_result.policy_version}
            if shadow_result
            else None
        ),
        "files": {
            str(path.relative_to(output)): {
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
            for path in files
        },
    }
    manifest_path = output / "manifest.json"
    _write_json(manifest_path, manifest_payload)
    if signing_key:
        normalized_key_id = signing_key_id.strip()
        if not normalized_key_id:
            raise ConfigurationError("signing_key_id is required when signing evidence")
        signed_payload = {
            "schema_version": "2.0",
            "algorithm": "hmac-sha256",
            "key_id": normalized_key_id,
            "signed_at": result.evaluated_at,
            "manifest_sha256": sha256_file(manifest_path),
        }
        signature = hmac.new(
            signing_key, _canonical_json(signed_payload), hashlib.sha256
        ).hexdigest()
        _write_json(
            output / "manifest.sig",
            {
                **signed_payload,
                "value": signature,
            },
        )
    if cosign_signing_key:
        bundle = output / "manifest.sigstore.json"
        if cosign_runner is None:
            cosign_sign_blob(manifest_path, bundle, key=cosign_signing_key)
        else:
            cosign_sign_blob(
                manifest_path,
                bundle,
                key=cosign_signing_key,
                runner=cosign_runner,
            )


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


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _write_audit_log(path: Path, result: GateResult, inputs: list[tuple[str, Path]]) -> None:
    events: list[dict[str, Any]] = [
        {
            "event": "policy.loaded",
            "at": result.evaluated_at,
            "policy_id": result.policy_id,
            "policy_version": result.policy_version,
        }
    ]
    events.extend(
        {
            "event": "input.captured",
            "at": result.evaluated_at,
            "input_type": input_type,
            "file": str(path.name),
            "sha256": sha256_file(path),
        }
        for input_type, path in inputs
    )
    events.append(
        {
            "event": "gate.evaluated",
            "at": result.evaluated_at,
            "decision": result.decision.value,
            "violation_count": len(result.violations),
            "active_finding_count": len(result.active_findings),
            "excepted_finding_count": len(result.excepted_findings),
            "vexed_finding_count": len(result.vexed_findings),
            "change_id": result.change_id,
        }
    )

    previous = "0" * 64
    lines: list[str] = []
    for sequence, event in enumerate(events, start=1):
        payload = {"sequence": sequence, "previous_hash": previous, **event}
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        record_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        record = {**payload, "record_hash": record_hash}
        lines.append(json.dumps(record, ensure_ascii=False, sort_keys=True))
        previous = record_hash
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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


def _render_summary(result: GateResult) -> str:
    counts = result.metrics.get("severity_counts", {})
    lines = [
        "# FinGuard 품질 게이트 결과",
        "",
        f"- 판정: **{result.decision.value.upper()}**",
        f"- 정책: `{result.policy_id}` v{result.policy_version}",
        f"- 변경 요청: `{result.change_id or '없음'}`",
        f"- 평가 시각: {result.evaluated_at}",
        f"- 조치 대상 이슈: {len(result.active_findings)}건",
        f"- 승인된 예외: {len(result.excepted_findings)}건",
        f"- VEX로 영향 없음 확인: {len(result.vexed_findings)}건",
        (
            "- 외부 승인 서명 검증: "
            f"{'완료' if result.metrics.get('approval_attestation_verified') else '미확인'}"
        ),
        (
            f"- 릴리스 대상 SHA-256: `{result.release_subject.digest}`"
            if result.release_subject
            else "- 릴리스 대상 SHA-256: `없음`"
        ),
        f"- 커버리지: {float(result.metrics.get('coverage_percent', 0)):.2f}%",
        "",
        "## 심각도별 탐지 결과",
        "",
        "| 심각도 | 건수 |",
        "| --- | ---: |",
    ]
    for severity in ("critical", "high", "medium", "low", "info", "unknown"):
        lines.append(f"| {severity} | {counts.get(severity, 0)} |")
    lines.extend(["", "## 정책 위반 코드와 원본 메시지", ""])
    if result.violations:
        lines.extend(f"- `{item.code}`: {item.message}" for item in result.violations)
    else:
        lines.append("정책 위반이 없습니다.")
    lines.extend(
        [
            "",
            "## 무결성",
            "",
            "`manifest.json`과 `audit.jsonl`로 입력 및 판정 이력을 검증할 수 있습니다.",
            "",
        ]
    )
    return "\n".join(lines)
