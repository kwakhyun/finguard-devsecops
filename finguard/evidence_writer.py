"""Build and sign evidence bundles in private staging directories."""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import tempfile
import uuid
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .evidence_storage import (
    BUNDLE_MARKER,
    _assert_no_symlink_components,
    _canonical_json,
    _copy_input,
    _publish_bundle,
    _validate_output_target,
    _write_json,
    sha256_file,
)
from .models import GateResult
from .reporting import compare_gate_results, render_gate_summary
from .signing import Runner, cosign_sign_blob


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
    summary_path.write_text(render_gate_summary(result), encoding="utf-8")
    audit_path = output / "audit.jsonl"
    input_hashes = {path: sha256_file(path) for _, path in copied}
    _write_audit_log(audit_path, result, copied, input_hashes)

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
                "sha256": input_hashes[path] if path in input_hashes else sha256_file(path),
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


def _write_audit_log(
    path: Path,
    result: GateResult,
    inputs: list[tuple[str, Path]],
    input_hashes: Mapping[Path, str],
) -> None:
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
            "sha256": input_hashes[path],
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
