"""Command-line interface for scan orchestration, gating, and evidence verification."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .approvals import (
    ApprovalAttestation,
    create_approval_attestation,
    load_approval_attestation,
)
from .attestation import (
    create_scan_attestation,
    digest_text,
    load_attestation_directory,
    sha256_path,
)
from .change import ChangeRequest
from .config import Policy, load_exceptions
from .deployment import DeploymentRequest, deploy
from .errors import FinGuardError
from .evidence import create_evidence_bundle, verify_evidence_bundle
from .gate import PolicyEngine
from .jsonio import strict_json_loads
from .models import Decision, ScanResult, ScanStatus
from .parsers import discover_reports, parse_report
from .release import ReleaseSubject, validate_image_reference
from .reporting import (
    compare_decisions,
    gitlab_code_quality,
    load_decision,
    prometheus_metrics,
    sarif_output,
    write_output,
)
from .safeio import assert_no_symlink_components, atomic_write_text
from .scanners import scan_dependencies, scan_lint, scan_source, scan_web
from .signing import cosign_sign_blob, cosign_verify_blob
from .vex import (
    VexAttestation,
    create_vex_attestation,
    load_vex_attestation,
    load_vex_statements,
)

EXIT_OK = 0
EXIT_GATE_FAILED = 2
EXIT_INPUT_ERROR = 3
EXIT_SCANNER_ERROR = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="finguard",
        description="Policy-as-code DevSecOps quality gate for regulated delivery",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="run dependency-free local feedback scanners")
    scan.add_argument("kind", choices=["source", "lint", "dependencies", "web", "all"])
    scan.add_argument("--workspace", type=Path, default=Path("."))
    scan.add_argument("--output", type=Path, default=Path("build/reports/native"))
    scan.add_argument("--url", help="HTTP target for web/all scans")
    scan.add_argument("--timeout", type=float, default=5.0)
    scan.add_argument("--exclude", action="append", default=[])
    scan.set_defaults(handler=_handle_scan)

    gate = commands.add_parser("gate", help="evaluate reports and produce audit evidence")
    gate.add_argument("--policy", type=Path, default=Path("policies/financial-baseline.toml"))
    gate.add_argument("--shadow-policy", type=Path)
    gate.add_argument(
        "--reports", type=Path, help="directory recursively containing scanner reports"
    )
    gate.add_argument(
        "--report",
        action="append",
        default=[],
        metavar="[TYPE=]PATH",
        help="individual report; TYPE resolves ambiguous formats",
    )
    gate.add_argument("--change", type=Path)
    gate.add_argument("--subject", type=Path, help="immutable release subject JSON")
    gate.add_argument("--exceptions", type=Path)
    gate.add_argument("--attestations", type=Path, help="scan attestation directory")
    gate.add_argument("--attestation-key-env", default="")
    gate.add_argument(
        "--approval-attestation", type=Path, help="signed external change approval JSON"
    )
    gate.add_argument("--approval-key-env", default="")
    gate.add_argument("--approval-cosign-bundle", type=Path)
    gate.add_argument("--approval-cosign-verification-key", default="")
    gate.add_argument("--approval-cosign-certificate-identity", default="")
    gate.add_argument("--approval-cosign-certificate-oidc-issuer", default="")
    gate.add_argument("--approval-cosign-key-id", default="")
    gate.add_argument("--vex-attestation", type=Path)
    gate.add_argument("--vex-key-env", default="")
    gate.add_argument("--vex-cosign-bundle", type=Path)
    gate.add_argument("--vex-cosign-verification-key", default="")
    gate.add_argument("--vex-cosign-certificate-identity", default="")
    gate.add_argument("--vex-cosign-certificate-oidc-issuer", default="")
    gate.add_argument("--vex-cosign-key-id", default="")
    gate.add_argument("--expected-commit", default="")
    gate.add_argument("--output", type=Path, default=Path("build/evidence"))
    gate.add_argument("--signing-key-env", default="")
    gate.add_argument("--signing-key-id", default="local-hmac")
    gate.add_argument("--cosign-signing-key", default="")
    gate.add_argument("--force", action="store_true")
    gate.set_defaults(handler=_handle_gate)

    verify = commands.add_parser("verify", help="verify evidence file hashes and audit chain")
    verify.add_argument("--evidence", type=Path, required=True)
    verify.add_argument("--signing-key-env", default="")
    verify.add_argument("--cosign-verification-key", default="")
    verify.add_argument("--cosign-certificate-identity", default="")
    verify.add_argument("--cosign-certificate-oidc-issuer", default="")
    verify.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="verify hashes only; never use for release or deployment evidence",
    )
    verify.set_defaults(handler=_handle_verify)

    demo = commands.add_parser("demo", help="run a reproducible pass or fail portfolio scenario")
    demo.add_argument("--scenario", choices=["pass", "fail"], default="pass")
    demo.add_argument("--fixtures", type=Path, default=Path("examples/scenarios"))
    demo.add_argument("--policy", type=Path, default=Path("policies/financial-baseline.toml"))
    demo.add_argument("--output", type=Path, default=Path("build/demo-evidence"))
    demo.add_argument("--signing-key-env", default="")
    demo.add_argument("--signing-key-id", default="local-hmac")
    demo.add_argument("--force", action="store_true")
    demo.set_defaults(handler=_handle_demo)

    deployment = commands.add_parser(
        "deploy", help="deploy an immutable image after evidence verification"
    )
    deployment.add_argument("--cluster", required=True, help="approved kubectl context")
    deployment.add_argument("--namespace", required=True)
    deployment.add_argument("--deployment", required=True)
    deployment.add_argument("--container", required=True)
    deployment.add_argument("--image", required=True)
    deployment.add_argument("--expected-policy-id", required=True)
    deployment.add_argument("--expected-policy-version", required=True)
    deployment.add_argument("--expected-policy-sha256", required=True)
    deployment.add_argument("--evidence", type=Path, required=True)
    deployment.add_argument("--output", type=Path, default=Path("build/deployment-result.json"))
    deployment.add_argument("--timeout", type=int, default=300)
    deployment.add_argument("--smoke-test-attempts", type=int, default=3)
    deployment.add_argument("--smoke-test-timeout", type=float, default=5.0)
    deployment.add_argument("--smoke-test-interval", type=float, default=2.0)
    deployment.add_argument("--allowed-health-host", action="append", default=[])
    deployment.add_argument("--signing-key-env", default="")
    deployment.add_argument("--cosign-verification-key", default="")
    deployment.add_argument("--cosign-certificate-identity", default="")
    deployment.add_argument("--cosign-certificate-oidc-issuer", default="")
    deployment_signature = deployment.add_mutually_exclusive_group()
    deployment_signature.add_argument(
        "--require-signature",
        dest="require_signature",
        action="store_true",
        default=True,
        help="require a verified evidence signature (default)",
    )
    deployment_signature.add_argument(
        "--allow-unsigned",
        dest="require_signature",
        action="store_false",
        help="allow unsigned evidence for local dry-run demonstrations only",
    )
    deployment.add_argument("--result-cosign-signing-key", default="")
    deployment.add_argument("--result-cosign-bundle", type=Path)
    deployment.add_argument(
        "--force-result",
        action="store_true",
        help="explicitly replace an existing deployment result and signature",
    )
    deployment.add_argument("--dry-run", action="store_true")
    deployment.set_defaults(handler=_handle_deploy)

    subject = commands.add_parser(
        "subject", help="create an immutable source, artifact, and deployment subject"
    )
    subject.add_argument("--service", required=True)
    subject.add_argument("--repository", required=True)
    subject.add_argument("--commit", required=True)
    subject.add_argument("--image", required=True)
    subject.add_argument("--sbom", type=Path, required=True)
    subject.add_argument("--environment", required=True)
    subject.add_argument("--cluster", required=True)
    subject.add_argument("--namespace", required=True)
    subject.add_argument("--deployment", required=True)
    subject.add_argument("--container", required=True)
    subject.add_argument("--healthcheck-url", required=True)
    subject.add_argument("--builder-id", required=True)
    subject.add_argument("--built-at", default="")
    subject.add_argument("--output", type=Path, required=True)
    subject.set_defaults(handler=_handle_subject)

    attest = commands.add_parser(
        "attest-report", help="bind a scanner execution to an immutable report"
    )
    attest.add_argument("--report", type=Path, required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.add_argument("--scanner", required=True)
    attest.add_argument("--category", required=True)
    attest.add_argument("--scanner-version", required=True)
    attest.add_argument("--scanner-uri", required=True)
    attest.add_argument("--source-commit", required=True)
    attest.add_argument("--image-digest", default="")
    attest.add_argument("--ruleset", type=Path, required=True)
    attest.add_argument("--database", type=Path)
    attest.add_argument("--command", required=True)
    attest.add_argument("--ci-job-id", required=True)
    attest.add_argument("--runner-id", required=True)
    attest.add_argument("--exit-code", type=int, required=True)
    completion = attest.add_mutually_exclusive_group(required=True)
    completion.add_argument("--complete", dest="complete", action="store_true")
    completion.add_argument("--incomplete", dest="complete", action="store_false")
    attest.add_argument("--target-uri", default="")
    attest.add_argument("--started-at", required=True)
    attest.add_argument("--finished-at", required=True)
    attest.add_argument("--signing-key-env", default="")
    attest.add_argument("--key-id", default="")
    attest.set_defaults(handler=_handle_attest_report)

    approval = commands.add_parser(
        "attest-approval",
        help="create an ITSM adapter approval envelope for a release subject",
    )
    approval.add_argument("--change", type=Path, required=True)
    approval.add_argument("--subject", type=Path, required=True)
    approval.add_argument("--issuer", required=True)
    approval.add_argument("--source-uri", required=True)
    approval.add_argument("--event-id", required=True)
    approval.add_argument("--issued-at", default="")
    approval.add_argument("--output", type=Path, required=True)
    approval.add_argument("--signing-key-env", default="")
    approval.add_argument("--cosign-signing-key", default="")
    approval.add_argument("--cosign-bundle", type=Path)
    approval.add_argument("--key-id", required=True)
    approval.add_argument("--force", action="store_true")
    approval.set_defaults(handler=_handle_attest_approval)

    vex = commands.add_parser(
        "attest-vex",
        help="create signed security review evidence for VEX statements",
    )
    vex.add_argument("--subject", type=Path, required=True)
    vex.add_argument("--statements", type=Path, required=True)
    vex.add_argument("--issuer", required=True)
    vex.add_argument("--source-uri", required=True)
    vex.add_argument("--event-id", required=True)
    vex.add_argument("--approver", required=True)
    vex.add_argument("--issued-at", required=True)
    vex.add_argument("--expires-at", required=True)
    vex.add_argument("--output", type=Path, required=True)
    vex.add_argument("--signing-key-env", default="")
    vex.add_argument("--cosign-signing-key", default="")
    vex.add_argument("--cosign-bundle", type=Path)
    vex.add_argument("--key-id", required=True)
    vex.add_argument("--force", action="store_true")
    vex.set_defaults(handler=_handle_attest_vex)

    image_validation = commands.add_parser(
        "validate-images", help="fail unless every container image is digest-pinned"
    )
    image_validation.add_argument("images", nargs="+")
    image_validation.set_defaults(handler=_handle_validate_images)

    export = commands.add_parser(
        "export", help="render a decision for GitLab, SARIF, or Prometheus consumers"
    )
    export.add_argument("--decision", type=Path, required=True)
    export.add_argument(
        "--format",
        choices=["gitlab-code-quality", "sarif", "prometheus"],
        required=True,
    )
    export.add_argument("--output", type=Path, required=True)
    export.set_defaults(handler=_handle_export)

    comparison = commands.add_parser(
        "compare", help="compare baseline and candidate policy decisions"
    )
    comparison.add_argument("--baseline", type=Path, required=True)
    comparison.add_argument("--candidate", type=Path, required=True)
    comparison.add_argument("--output", type=Path)
    comparison.set_defaults(handler=_handle_compare)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except FinGuardError as exc:
        print(f"finguard: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
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
    # Scanner artifacts, policies, approvals, and change data may originate from
    # different CI jobs or mounted ITSM storage. Evaluate and archive one private
    # byte-for-byte snapshot so a concurrent replacement cannot create a signed
    # decision for inputs different from those captured in the evidence bundle.
    with tempfile.TemporaryDirectory(prefix="finguard-gate-") as temporary:
        snapshot_args = _snapshot_gate_arguments(args, Path(temporary).resolve())
        return _handle_gate_snapshot(snapshot_args)


def _handle_gate_snapshot(args: argparse.Namespace) -> int:
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
            signing_key=_signing_key(args.attestation_key_env),
        )
        for scan in scans:
            scan.provenance = attestations.get(scan.input_sha256)
    exceptions = load_exceptions(args.exceptions)
    approval_attestation = _load_external_approval(args)
    vex_attestation = _load_external_vex(args)
    evaluated_at = _utc_now()
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
    signing_key = _signing_key(args.signing_key_env)
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
    payload: dict[str, object] = {
        "decision": result.decision.value,
        "violation_count": len(result.violations),
        "violations": [
            {"code": violation.code, "message": violation.message}
            for violation in result.violations
        ],
        "active_finding_count": len(result.active_findings),
        "excepted_finding_count": len(result.excepted_findings),
        "manifest": str(manifest),
    }
    if shadow_result is not None:
        payload["shadow"] = compare_decisions(result.to_dict(), shadow_result.to_dict())
    print(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        )
    )
    return EXIT_OK if result.decision is Decision.PASS else EXIT_GATE_FAILED


def _snapshot_gate_arguments(args: argparse.Namespace, snapshot_root: Path) -> argparse.Namespace:
    """Copy every gate trust input into a private, immutable-for-this-run workspace."""

    snapshot = argparse.Namespace(**vars(args))
    snapshot.policy = _snapshot_file(args.policy, snapshot_root / "policy.toml")
    snapshot.shadow_policy = (
        _snapshot_file(args.shadow_policy, snapshot_root / "shadow-policy.toml")
        if args.shadow_policy
        else None
    )

    report_specs: list[str] = []
    for index, (report_type, source) in enumerate(
        _report_entries(args.reports, args.report), start=1
    ):
        target = _snapshot_file(
            source,
            snapshot_root / "reports" / f"{index:03d}-{source.name}",
        )
        report_specs.append(f"{report_type}={target}" if report_type else str(target))
    snapshot.reports = None
    snapshot.report = report_specs

    snapshot.change = _snapshot_optional_file(args.change, snapshot_root / "change.toml")
    snapshot.subject = _snapshot_optional_file(args.subject, snapshot_root / "release-subject.json")
    snapshot.exceptions = _snapshot_optional_file(
        args.exceptions, snapshot_root / "exceptions.toml"
    )
    snapshot.approval_attestation = _snapshot_optional_file(
        args.approval_attestation,
        snapshot_root / "approval-attestation.json",
    )
    snapshot.approval_cosign_bundle = _snapshot_optional_file(
        args.approval_cosign_bundle,
        snapshot_root / "approval-attestation.sigstore.json",
    )
    snapshot.vex_attestation = _snapshot_optional_file(
        args.vex_attestation,
        snapshot_root / "vex-attestation.json",
    )
    snapshot.vex_cosign_bundle = _snapshot_optional_file(
        args.vex_cosign_bundle,
        snapshot_root / "vex-attestation.sigstore.json",
    )

    if args.attestations:
        source_directory: Path = args.attestations
        assert_no_symlink_components(source_directory, context="gate attestation input")
        if not source_directory.is_dir():
            raise FinGuardError(f"attestation directory does not exist: {source_directory}")
        target_directory = snapshot_root / "attestations"
        for index, source in enumerate(sorted(source_directory.glob("*.json")), start=1):
            _snapshot_file(
                source,
                target_directory / f"{index:03d}-{source.name}",
            )
        snapshot.attestations = target_directory
    else:
        snapshot.attestations = None
    return snapshot


def _snapshot_optional_file(source: Path | None, target: Path) -> Path | None:
    return _snapshot_file(source, target) if source is not None else None


def _snapshot_file(source: Path, target: Path) -> Path:
    try:
        assert_no_symlink_components(source, context="gate input")
        if not source.is_file():
            raise FinGuardError(f"gate input does not exist: {source}")
        target.parent.mkdir(parents=True, exist_ok=True)
        # The private snapshot, rather than the mutable source, is used by every
        # subsequent parser, signature verifier, and evidence copy operation.
        with source.open("rb") as source_handle, target.open("xb") as target_handle:
            shutil.copyfileobj(source_handle, target_handle, length=1024 * 1024)
    except OSError as exc:
        raise FinGuardError(f"cannot snapshot gate input {source}: {exc}") from exc
    return target


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


def _snapshot_evidence_directory(source: Path, target: Path) -> Path:
    try:
        assert_no_symlink_components(source, context="deployment evidence input")
        if not source.is_dir():
            raise FinGuardError(f"evidence directory does not exist: {source}")
        # Preserve links instead of following them. The closed-world verifier then
        # rejects every link before consuming any artifact from this private copy.
        shutil.copytree(source, target, symlinks=True)
    except OSError as exc:
        raise FinGuardError(f"cannot snapshot deployment evidence {source}: {exc}") from exc
    return target


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


def _report_entries(directory: Path | None, specs: list[str]) -> list[tuple[str | None, Path]]:
    entries: list[tuple[str | None, Path]] = []
    if directory is not None:
        entries.extend((None, path) for path in discover_reports(directory))
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


def _signing_key(environment_name: str) -> bytes | None:
    if not environment_name:
        return None
    value = os.environ.get(environment_name)
    if value is None or not value:
        raise FinGuardError(f"signing key environment variable is empty: {environment_name}")
    return value.encode("utf-8")


def _load_external_approval(args: argparse.Namespace) -> ApprovalAttestation | None:
    path: Path | None = args.approval_attestation
    bundle: Path | None = args.approval_cosign_bundle
    hmac_key = _signing_key(args.approval_key_env)
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


def _load_external_vex(args: argparse.Namespace) -> VexAttestation | None:
    path: Path | None = args.vex_attestation
    bundle: Path | None = args.vex_cosign_bundle
    hmac_key = _signing_key(args.vex_key_env)
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
