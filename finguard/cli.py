"""Command-line interface for scan orchestration, gating, and evidence verification."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import fields
from pathlib import Path

from .approvals import (
    create_approval_attestation,
)
from .attestation import (
    create_scan_attestation,
    digest_text,
    sha256_path,
)
from .change import ChangeRequest
from .cli_parser import build_parser as create_parser
from .deployment import DeploymentRequest, deploy
from .deployment_signals import DeploymentInterrupted
from .errors import FinGuardError
from .evidence import verify_evidence_bundle
from .gate_service import GateRequest, execute_gate
from .jsonio import strict_json_loads
from .models import Decision, ScanResult, ScanStatus
from .release import ReleaseSubject, validate_image_reference
from .reporting import (
    compare_decisions,
    gitlab_code_quality,
    load_decision,
    prometheus_metrics,
    sarif_output,
    write_output,
)
from .safeio import atomic_write_text
from .scanners import scan_dependencies, scan_lint, scan_source, scan_web
from .signing import cosign_sign_blob
from .snapshots import snapshot_evidence_directory as _snapshot_evidence_directory
from .snapshots import snapshot_file as _snapshot_file  # noqa: F401 - compatibility
from .vex import (
    create_vex_attestation,
    load_vex_statements,
)

EXIT_OK = 0
EXIT_GATE_FAILED = 2
EXIT_INPUT_ERROR = 3
EXIT_SCANNER_ERROR = 4


def build_parser() -> argparse.ArgumentParser:
    return create_parser(
        {
            "scan": _handle_scan,
            "gate": _handle_gate,
            "verify": _handle_verify,
            "demo": _handle_demo,
            "deploy": _handle_deploy,
            "subject": _handle_subject,
            "attest_report": _handle_attest_report,
            "attest_approval": _handle_attest_approval,
            "attest_vex": _handle_attest_vex,
            "validate_images": _handle_validate_images,
            "export": _handle_export,
            "compare": _handle_compare,
        }
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except FinGuardError as exc:
        print(f"finguard: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except DeploymentInterrupted as exc:
        print(f"finguard: {exc}", file=sys.stderr)
        return 128 + exc.signum
    except KeyboardInterrupt:
        print("finguard: interrupted", file=sys.stderr)
        return 130


def _handle_scan(args: argparse.Namespace) -> int:
    output: Path = args.output
    output.mkdir(parents=True, exist_ok=True)
    results: list[ScanResult] = []
    if args.kind in {"source", "all"}:
        results.append(scan_source(args.workspace, args.exclude))
    if args.kind in {"lint", "all"}:
        results.append(scan_lint(args.workspace, args.exclude))
    if args.kind in {"dependencies", "all"}:
        results.append(scan_dependencies(args.workspace))
    if args.kind in {"web", "all"}:
        if not args.url:
            raise FinGuardError("--url is required for web and all scans")
        results.append(scan_web(args.url, args.timeout))

    paths: list[str] = []
    for result in results:
        name = f"{result.scanner}.json"
        path = output / name
        result.write_json(path)
        paths.append(str(path))
    payload = {
        "reports": paths,
        "statuses": {result.scanner: result.status.value for result in results},
        "finding_count": sum(len(result.findings) for result in results),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    has_error = any(result.status is ScanStatus.ERROR for result in results)
    return EXIT_SCANNER_ERROR if has_error else EXIT_OK


def _handle_gate(args: argparse.Namespace) -> int:
    values = vars(args)
    inputs = {item.name: values[item.name] for item in fields(GateRequest) if item.name in values}
    inputs["report"] = tuple(args.report)
    for key in ("signing_key", "attestation_key", "approval_key", "vex_key"):
        inputs[key] = _signing_key(values[f"{key}_env"])
    execution = execute_gate(GateRequest(**inputs), now=_utc_now())
    print(json.dumps(execution.to_dict(), ensure_ascii=False, indent=2))
    return EXIT_OK if execution.result.decision is Decision.PASS else EXIT_GATE_FAILED


def _handle_verify(args: argparse.Namespace) -> int:
    # Verification consumes the same private byte snapshot as deployment so a
    # concurrently replaced audit file cannot be reported as part of a verified
    # bundle after a different version of that file was hashed.
    with tempfile.TemporaryDirectory(prefix="finguard-verify-") as temporary:
        snapshot = Path(temporary).resolve() / "evidence"
        _snapshot_evidence_directory(args.evidence, snapshot)
        verification = verify_evidence_bundle(
            snapshot,
            signing_key=_signing_key(args.signing_key_env),
            cosign_verification_key=args.cosign_verification_key,
            cosign_certificate_identity=args.cosign_certificate_identity,
            cosign_certificate_oidc_issuer=args.cosign_certificate_oidc_issuer,
            require_signature=not args.allow_unsigned,
        )
    print(json.dumps(verification, ensure_ascii=False, indent=2))
    return EXIT_OK


def _handle_demo(args: argparse.Namespace) -> int:
    scenario = args.fixtures / args.scenario
    with tempfile.TemporaryDirectory(prefix="finguard-demo-") as temporary:
        change = _materialize_demo_change(
            scenario / "change.toml",
            Path(temporary).resolve() / "change.toml",
            now=_utc_now(),
        )
        gate_args = argparse.Namespace(
            policy=args.policy,
            shadow_policy=None,
            reports=scenario / "reports",
            report=[],
            change=change,
            subject=(scenario / "release-subject.json")
            if (scenario / "release-subject.json").is_file()
            else None,
            exceptions=(scenario / "exceptions.toml")
            if (scenario / "exceptions.toml").is_file()
            else None,
            expected_commit="",
            attestations=None,
            attestation_key_env="",
            approval_attestation=None,
            approval_key_env="",
            approval_cosign_bundle=None,
            approval_cosign_verification_key="",
            approval_cosign_certificate_identity="",
            approval_cosign_certificate_oidc_issuer="",
            approval_cosign_key_id="",
            vex_attestation=None,
            vex_key_env="",
            vex_cosign_bundle=None,
            vex_cosign_verification_key="",
            vex_cosign_certificate_identity="",
            vex_cosign_certificate_oidc_issuer="",
            vex_cosign_key_id="",
            output=args.output / args.scenario,
            signing_key_env=args.signing_key_env,
            signing_key_id=args.signing_key_id,
            cosign_signing_key="",
            force=args.force,
        )
        return _handle_gate(gate_args)


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _materialize_demo_change(source: Path, output: Path, *, now: dt.datetime) -> Path:
    """Give complete demo fixtures a short window around the current execution time."""

    text = source.read_text(encoding="utf-8")
    if "window_start =" not in text or "window_end =" not in text:
        return source

    start = now.astimezone(dt.UTC).replace(microsecond=0) - dt.timedelta(minutes=5)
    end = start + dt.timedelta(hours=1)
    replacements = {
        "window_start =": f"window_start = {start.isoformat()}",
        "window_end =": f"window_end = {end.isoformat()}",
    }
    rendered: list[str] = []
    for line in text.splitlines():
        rendered_line = line
        for prefix, replacement in replacements.items():
            if line.startswith(prefix):
                rendered_line = replacement
                break
        rendered.append(rendered_line)
    atomic_write_text(
        output,
        "\n".join(rendered) + "\n",
        context="demo change manifest",
    )
    return output


def _handle_deploy(args: argparse.Namespace) -> int:
    _validate_deploy_output_locations(args)
    with tempfile.TemporaryDirectory(prefix="finguard-deploy-") as temporary:
        snapshot = Path(temporary).resolve() / "evidence"
        _snapshot_evidence_directory(args.evidence, snapshot)
        snapshot_args = argparse.Namespace(**vars(args))
        snapshot_args.evidence = snapshot
        return _handle_deploy_snapshot(snapshot_args)


def _handle_deploy_snapshot(args: argparse.Namespace) -> int:
    record = deploy(
        DeploymentRequest(
            cluster=args.cluster,
            namespace=args.namespace,
            deployment=args.deployment,
            container=args.container,
            image=args.image,
            expected_policy_id=args.expected_policy_id,
            expected_policy_version=args.expected_policy_version,
            expected_policy_sha256=args.expected_policy_sha256,
            evidence_dir=args.evidence,
            output=args.output,
            timeout_seconds=args.timeout,
            require_signature=args.require_signature,
            smoke_test_attempts=args.smoke_test_attempts,
            smoke_test_timeout_seconds=args.smoke_test_timeout,
            smoke_test_interval_seconds=args.smoke_test_interval,
            allowed_health_hosts=tuple(args.allowed_health_host),
            force_output=args.force_result,
        ),
        signing_key=_signing_key(args.signing_key_env),
        cosign_verification_key=args.cosign_verification_key,
        cosign_certificate_identity=args.cosign_certificate_identity,
        cosign_certificate_oidc_issuer=args.cosign_certificate_oidc_issuer,
        result_cosign_signing_key=args.result_cosign_signing_key,
        result_cosign_bundle=args.result_cosign_bundle,
        dry_run=args.dry_run,
    )
    print(json.dumps(record, ensure_ascii=False, indent=2))
    return EXIT_OK


def _validate_deploy_output_locations(args: argparse.Namespace) -> None:
    evidence = args.evidence.expanduser().resolve()
    for label, candidate in (
        ("deployment result", args.output),
        ("deployment result signature", args.result_cosign_bundle),
    ):
        if candidate is None:
            continue
        resolved = candidate.expanduser().resolve()
        if resolved == evidence or evidence in resolved.parents:
            raise FinGuardError(f"{label} must be outside the evidence bundle")


def _handle_subject(args: argparse.Namespace) -> int:
    built_at = _parse_datetime(args.built_at) if args.built_at else dt.datetime.now(dt.UTC)
    subject = ReleaseSubject.from_mapping(
        {
            "service": args.service,
            "repository": args.repository,
            "commit_sha": args.commit,
            "image": args.image,
            "sbom_sha256": sha256_path(args.sbom),
            "environment": args.environment,
            "cluster": args.cluster,
            "namespace": args.namespace,
            "deployment": args.deployment,
            "container": args.container,
            "healthcheck_url": args.healthcheck_url,
            "builder_id": args.builder_id,
            "built_at": built_at,
        }
    )
    atomic_write_text(
        args.output,
        json.dumps(subject.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        context="release subject",
    )
    print(json.dumps({"subject": str(args.output), "sha256": subject.digest}, indent=2))
    return EXIT_OK


def _handle_attest_report(args: argparse.Namespace) -> int:
    finished_at = _parse_datetime(args.finished_at)
    started_at = _parse_datetime(args.started_at)
    path = create_scan_attestation(
        args.output,
        report_path=args.report,
        scanner=args.scanner,
        category=args.category,
        scanner_version=args.scanner_version,
        scanner_uri=args.scanner_uri,
        source_commit=args.source_commit,
        image_digest=args.image_digest,
        ruleset_sha256=sha256_path(args.ruleset),
        database_sha256=sha256_path(args.database) if args.database else "",
        database_updated_at=_database_updated_at(args.database),
        command_sha256=digest_text(args.command),
        ci_job_id=args.ci_job_id,
        runner_id=args.runner_id,
        exit_code=args.exit_code,
        complete=args.complete,
        target_uri=args.target_uri,
        started_at=started_at,
        finished_at=finished_at,
        signing_key=_signing_key(args.signing_key_env),
        key_id=args.key_id,
    )
    print(json.dumps({"attestation": str(path)}, indent=2))
    return EXIT_OK


def _handle_attest_approval(args: argparse.Namespace) -> int:
    signing_key = _signing_key(args.signing_key_env)
    if bool(signing_key) == bool(args.cosign_signing_key):
        raise FinGuardError("choose exactly one HMAC or Cosign approval signing method")
    issued_at = _parse_datetime(args.issued_at) if args.issued_at else dt.datetime.now(dt.UTC)
    path = create_approval_attestation(
        args.output,
        change=ChangeRequest.load(args.change),
        release_subject=ReleaseSubject.load(args.subject),
        issuer=args.issuer,
        source_uri=args.source_uri,
        event_id=args.event_id,
        issued_at=issued_at,
        signing_key=signing_key,
        key_id=args.key_id,
        force=args.force,
    )
    bundle: Path | None = None
    if args.cosign_signing_key:
        bundle = args.cosign_bundle or Path(f"{path}.sigstore.json")
        cosign_sign_blob(
            path,
            bundle,
            key=args.cosign_signing_key,
            force=args.force,
        )
    print(
        json.dumps(
            {
                "approval_attestation": str(path),
                "signature_bundle": str(bundle) if bundle else "",
            },
            indent=2,
        )
    )
    return EXIT_OK


def _handle_attest_vex(args: argparse.Namespace) -> int:
    signing_key = _signing_key(args.signing_key_env)
    if bool(signing_key) == bool(args.cosign_signing_key):
        raise FinGuardError("choose exactly one HMAC or Cosign VEX signing method")
    path = create_vex_attestation(
        args.output,
        release_subject=ReleaseSubject.load(args.subject),
        issuer=args.issuer,
        source_uri=args.source_uri,
        event_id=args.event_id,
        approver=args.approver,
        issued_at=_parse_datetime(args.issued_at),
        expires_at=_parse_datetime(args.expires_at),
        statements=load_vex_statements(args.statements),
        key_id=args.key_id,
        signing_key=signing_key,
        force=args.force,
    )
    bundle: Path | None = None
    if args.cosign_signing_key:
        bundle = args.cosign_bundle or Path(f"{path}.sigstore.json")
        cosign_sign_blob(
            path,
            bundle,
            key=args.cosign_signing_key,
            force=args.force,
        )
    print(
        json.dumps(
            {
                "vex_attestation": str(path),
                "signature_bundle": str(bundle) if bundle else "",
            },
            indent=2,
        )
    )
    return EXIT_OK


def _handle_validate_images(args: argparse.Namespace) -> int:
    for index, value in enumerate(args.images, start=1):
        validate_image_reference(value, context=f"images[{index}]")
    print(json.dumps({"validated": len(args.images)}, indent=2))
    return EXIT_OK


def _handle_export(args: argparse.Namespace) -> int:
    decision = load_decision(args.decision)
    if args.format == "gitlab-code-quality":
        write_output(args.output, gitlab_code_quality(decision))
    elif args.format == "sarif":
        write_output(args.output, sarif_output(decision))
    else:
        write_output(args.output, prometheus_metrics(decision), text_output=True)
    print(json.dumps({"format": args.format, "output": str(args.output)}, indent=2))
    return EXIT_OK


def _handle_compare(args: argparse.Namespace) -> int:
    comparison = compare_decisions(
        load_decision(args.baseline),
        load_decision(args.candidate),
    )
    if args.output:
        write_output(args.output, comparison)
    print(json.dumps(comparison, ensure_ascii=False, indent=2))
    return EXIT_OK


def _signing_key(environment_name: str) -> bytes | None:
    if not environment_name:
        return None
    value = os.environ.get(environment_name)
    if value is None or not value:
        raise FinGuardError(f"signing key environment variable is empty: {environment_name}")
    return value.encode("utf-8")


def _parse_datetime(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FinGuardError(f"invalid ISO-8601 datetime: {value}") from exc
    if parsed.tzinfo is None:
        raise FinGuardError(f"datetime must include a timezone: {value}")
    return parsed.astimezone(dt.UTC)


def _database_updated_at(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        value = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise FinGuardError(f"cannot read scanner database metadata {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise FinGuardError("scanner database metadata must be a JSON object")
    timestamp = next(
        (
            value[key]
            for key in ("UpdatedAt", "updated_at", "updatedAt", "DownloadedAt")
            if key in value
        ),
        None,
    )
    if not isinstance(timestamp, str):
        raise FinGuardError("scanner database metadata does not contain an update timestamp")
    return _parse_datetime(timestamp).isoformat()
