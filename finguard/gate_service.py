"""Application service for snapshotting, evaluating and recording a policy gate."""

from __future__ import annotations

import datetime as dt
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .approvals import ApprovalAttestation, load_approval_attestation
from .attestation import load_attestation_directory
from .change import ChangeRequest
from .config import Policy, load_exceptions
from .errors import FinGuardError
from .evidence import create_evidence_bundle
from .gate import PolicyEngine
from .models import GateResult
from .parsers import discover_reports, parse_report
from .release import ReleaseSubject
from .reporting import compare_gate_results
from .safeio import assert_no_symlink_components
from .signing import cosign_verify_blob
from .snapshots import MAX_INPUT_FILES, InputSnapshot
from .vex import VexAttestation, load_vex_attestation


@dataclass(frozen=True)
class GateRequest:
    """Application inputs independent of argparse and environment lookup."""

    policy: Path
    output: Path
    reports: Path | None = None
    report: tuple[str, ...] = ()
    shadow_policy: Path | None = None
    change: Path | None = None
    subject: Path | None = None
    exceptions: Path | None = None
    expected_commit: str = ""
    attestations: Path | None = None
    attestation_key: bytes | None = field(default=None, repr=False)
    approval_attestation: Path | None = None
    approval_key: bytes | None = field(default=None, repr=False)
    approval_cosign_bundle: Path | None = None
    approval_cosign_verification_key: str = ""
    approval_cosign_certificate_identity: str = ""
    approval_cosign_certificate_oidc_issuer: str = ""
    approval_cosign_key_id: str = ""
    vex_attestation: Path | None = None
    vex_key: bytes | None = field(default=None, repr=False)
    vex_cosign_bundle: Path | None = None
    vex_cosign_verification_key: str = ""
    vex_cosign_certificate_identity: str = ""
    vex_cosign_certificate_oidc_issuer: str = ""
    vex_cosign_key_id: str = ""
    signing_key: bytes | None = field(default=None, repr=False)
    signing_key_id: str = "local-hmac"
    cosign_signing_key: str = field(default="", repr=False)
    force: bool = False


@dataclass(frozen=True)
class GateExecution:
    result: GateResult
    manifest: Path
    comparison: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, object]:
        result = self.result
        payload: dict[str, object] = {
            "decision": result.decision.value,
            "violation_count": len(result.violations),
            "violations": [
                {"code": violation.code, "message": violation.message}
                for violation in result.violations
            ],
            "active_finding_count": len(result.active_findings),
            "excepted_finding_count": len(result.excepted_findings),
            "manifest": str(self.manifest),
        }
        if self.comparison is not None:
            payload["shadow"] = self.comparison
        return payload


def execute_gate(request: GateRequest, *, now: dt.datetime | None = None) -> GateExecution:
    """Evaluate and archive the same bounded, private snapshot of every trust input."""
    with tempfile.TemporaryDirectory(prefix="finguard-gate-") as temporary:
        snapshot = _snapshot_request(request, Path(temporary).resolve())
        return _evaluate_snapshot(snapshot, now=now or dt.datetime.now(dt.UTC))


def _evaluate_snapshot(args: GateRequest, *, now: dt.datetime) -> GateExecution:
    report_entries = _report_entries(args.reports, args.report)
    if not report_entries:
        raise FinGuardError("at least one --reports directory or --report file is required")
    report_paths = [path for _, path in report_entries]
    scans = [parse_report(path, report_type) for report_type, path in report_entries]
    policy = Policy.load(args.policy)
    change = ChangeRequest.load(args.change) if args.change else None
    release_subject = ReleaseSubject.load(args.subject) if args.subject else None
    attestation_paths: list[Path] = []
    if args.attestations:
        attestations, attestation_paths = load_attestation_directory(
            args.attestations,
            report_paths,
            signing_key=args.attestation_key,
        )
        for scan in scans:
            scan.provenance = attestations.get(scan.input_sha256)
    exceptions = load_exceptions(args.exceptions)
    approval_attestation = _load_external_approval(args)
    vex_attestation = _load_external_vex(args)
    evaluated_at = now
    result = PolicyEngine(policy).evaluate(
        scans,
        exceptions=exceptions,
        change=change,
        release_subject=release_subject,
        approval_attestation=approval_attestation,
        vex_attestation=vex_attestation,
        expected_commit=args.expected_commit,
        now=evaluated_at,
    )
    shadow_result = None
    if args.shadow_policy:
        shadow_result = PolicyEngine(Policy.load(args.shadow_policy)).evaluate(
            scans,
            exceptions=exceptions,
            change=change,
            release_subject=release_subject,
            approval_attestation=approval_attestation,
            vex_attestation=vex_attestation,
            expected_commit=args.expected_commit,
            now=evaluated_at,
        )
    signing_key = args.signing_key
    manifest = create_evidence_bundle(
        args.output,
        result=result,
        shadow_result=shadow_result,
        policy_path=args.policy,
        report_paths=report_paths,
        attestation_paths=attestation_paths,
        approval_attestation_path=args.approval_attestation,
        approval_signature_path=args.approval_cosign_bundle,
        vex_attestation_path=args.vex_attestation,
        vex_signature_path=args.vex_cosign_bundle,
        change_path=args.change,
        exceptions_path=args.exceptions,
        signing_key=signing_key,
        signing_key_id=args.signing_key_id,
        cosign_signing_key=args.cosign_signing_key,
        force=args.force,
    )
    return GateExecution(
        result,
        manifest,
        compare_gate_results(result, shadow_result) if shadow_result is not None else None,
    )


def _snapshot_request(args: GateRequest, snapshot_root: Path) -> GateRequest:
    """Copy every gate trust input into a private, immutable-for-this-run workspace."""

    copier = InputSnapshot()
    updates: dict[str, Any] = {}
    updates["policy"] = copier.copy_file(args.policy, snapshot_root / "policy.toml")
    updates["shadow_policy"] = (
        copier.copy_file(args.shadow_policy, snapshot_root / "shadow-policy.toml")
        if args.shadow_policy
        else None
    )

    report_specs: list[str] = []
    for index, (report_type, source) in enumerate(
        _report_entries(args.reports, args.report), start=1
    ):
        target = copier.copy_file(
            source,
            snapshot_root / "reports" / f"{index:03d}-{source.name}",
        )
        report_specs.append(f"{report_type}={target}" if report_type else str(target))
    updates["reports"] = None
    updates["report"] = tuple(report_specs)

    updates["change"] = copier.copy_optional(args.change, snapshot_root / "change.toml")
    updates["subject"] = copier.copy_optional(args.subject, snapshot_root / "release-subject.json")
    updates["exceptions"] = copier.copy_optional(args.exceptions, snapshot_root / "exceptions.toml")
    updates["approval_attestation"] = copier.copy_optional(
        args.approval_attestation,
        snapshot_root / "approval-attestation.json",
    )
    updates["approval_cosign_bundle"] = copier.copy_optional(
        args.approval_cosign_bundle,
        snapshot_root / "approval-attestation.sigstore.json",
    )
    updates["vex_attestation"] = copier.copy_optional(
        args.vex_attestation,
        snapshot_root / "vex-attestation.json",
    )
    updates["vex_cosign_bundle"] = copier.copy_optional(
        args.vex_cosign_bundle,
        snapshot_root / "vex-attestation.sigstore.json",
    )

    if args.attestations:
        source_directory: Path = args.attestations
        assert_no_symlink_components(source_directory, context="gate attestation input")
        if not source_directory.is_dir():
            raise FinGuardError(f"attestation directory does not exist: {source_directory}")
        target_directory = snapshot_root / "attestations"
        target_directory.mkdir()
        sources = []
        for source in source_directory.glob("*.json"):
            sources.append(source)
            if len(sources) > copier.max_files - copier.entries:
                raise FinGuardError("snapshot exceeds input entry limit")
        for index, source in enumerate(sorted(sources), start=1):
            copier.copy_file(
                source,
                target_directory / f"{index:03d}-{source.name}",
            )
        updates["attestations"] = target_directory
    else:
        updates["attestations"] = None
    return replace(args, **updates)


def _report_entries(
    directory: Path | None, specs: tuple[str, ...]
) -> list[tuple[str | None, Path]]:
    entries: list[tuple[str | None, Path]] = []
    if directory is not None:
        entries.extend((None, path) for path in discover_reports(directory))
    if len(entries) + len(specs) > MAX_INPUT_FILES:
        raise FinGuardError(f"report inputs exceed {MAX_INPUT_FILES} files")
    for spec in specs:
        report_type: str | None = None
        path_text = spec
        if "=" in spec:
            candidate_type, candidate_path = spec.split("=", 1)
            if candidate_type and candidate_path:
                report_type, path_text = candidate_type, candidate_path
        entries.append((report_type, Path(path_text)))

    unique: list[tuple[str | None, Path]] = []
    seen: set[Path] = set()
    for report_type, path in entries:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append((report_type, path))
    return unique


def _load_external_approval(args: GateRequest) -> ApprovalAttestation | None:
    path: Path | None = args.approval_attestation
    bundle: Path | None = args.approval_cosign_bundle
    hmac_key = args.approval_key
    has_cosign_options = bool(
        bundle
        or args.approval_cosign_verification_key
        or args.approval_cosign_certificate_identity
        or args.approval_cosign_certificate_oidc_issuer
        or args.approval_cosign_key_id
    )
    if path is None:
        if hmac_key is not None or has_cosign_options:
            raise FinGuardError("approval verification options require --approval-attestation")
        return None
    if hmac_key is not None and has_cosign_options:
        raise FinGuardError("choose exactly one HMAC or Cosign approval verification method")
    if has_cosign_options:
        if bundle is None or not args.approval_cosign_key_id:
            raise FinGuardError("Cosign approval verification requires a bundle and logical key ID")
        cosign_verify_blob(
            path,
            bundle,
            key=args.approval_cosign_verification_key,
            certificate_identity=args.approval_cosign_certificate_identity,
            certificate_oidc_issuer=args.approval_cosign_certificate_oidc_issuer,
        )
        return load_approval_attestation(
            path,
            external_signature_verified=True,
            external_key_id=args.approval_cosign_key_id,
        )
    return load_approval_attestation(path, signing_key=hmac_key)


def _load_external_vex(args: GateRequest) -> VexAttestation | None:
    path: Path | None = args.vex_attestation
    bundle: Path | None = args.vex_cosign_bundle
    hmac_key = args.vex_key
    has_cosign_options = bool(
        bundle
        or args.vex_cosign_verification_key
        or args.vex_cosign_certificate_identity
        or args.vex_cosign_certificate_oidc_issuer
        or args.vex_cosign_key_id
    )
    if path is None:
        if hmac_key is not None or has_cosign_options:
            raise FinGuardError("VEX verification options require --vex-attestation")
        return None
    if hmac_key is not None and has_cosign_options:
        raise FinGuardError("choose exactly one HMAC or Cosign VEX verification method")
    if has_cosign_options:
        if bundle is None or not args.vex_cosign_key_id:
            raise FinGuardError("Cosign VEX verification requires a bundle and logical key ID")
        cosign_verify_blob(
            path,
            bundle,
            key=args.vex_cosign_verification_key,
            certificate_identity=args.vex_cosign_certificate_identity,
            certificate_oidc_issuer=args.vex_cosign_certificate_oidc_issuer,
        )
        return load_vex_attestation(
            path,
            external_signature_verified=True,
            external_key_id=args.vex_cosign_key_id,
        )
    return load_vex_attestation(path, signing_key=hmac_key)
