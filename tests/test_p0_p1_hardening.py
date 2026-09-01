from __future__ import annotations

import datetime as dt
import json
from dataclasses import replace
from pathlib import Path

import pytest

from finguard.approvals import (
    ApprovalAttestation,
    create_approval_attestation,
    load_approval_attestation,
)
from finguard.attestation import (
    create_scan_attestation,
    digest_text,
    load_attestation_directory,
    load_scan_attestation,
)
from finguard.change import Approval, ChangeRequest
from finguard.cli import EXIT_OK, main
from finguard.config import Policy, PolicyException
from finguard.errors import (
    ConfigurationError,
    EvidenceVerificationError,
)
from finguard.evidence import create_evidence_bundle, verify_evidence_bundle
from finguard.gate import PolicyEngine
from finguard.licenses import LicenseDisposition, evaluate_spdx_expression
from finguard.models import Decision, Finding, GateResult, ScanResult, ScanStatus, Severity
from finguard.parsers import discover_reports, parse_report
from finguard.release import ReleaseSubject, commit_matches


def _minimal_result() -> GateResult:
    return GateResult(
        decision=Decision.PASS,
        policy_id="TEST",
        policy_version="1",
        violations=[],
        active_findings=[],
        excepted_findings=[],
        scan_results=[],
        metrics={},
        evaluated_at="2026-09-01T00:00:00+00:00",
    )


def test_force_never_replaces_an_unowned_directory(tmp_path: Path) -> None:
    target = tmp_path / "important-project"
    target.mkdir()
    sentinel = target / "do-not-delete.txt"
    sentinel.write_text("preserve me", encoding="utf-8")
    policy = tmp_path / "policy.toml"
    policy.write_text("policy", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="not owned by FinGuard"):
        create_evidence_bundle(
            target,
            result=_minimal_result(),
            policy_path=policy,
            report_paths=[],
            force=True,
        )

    assert sentinel.read_text(encoding="utf-8") == "preserve me"


def test_force_atomically_replaces_only_an_owned_bundle(tmp_path: Path) -> None:
    target = tmp_path / "evidence"
    policy = tmp_path / "policy.toml"
    policy.write_text("first", encoding="utf-8")
    create_evidence_bundle(
        target,
        result=_minimal_result(),
        policy_path=policy,
        report_paths=[],
    )
    stale = target / "stale.txt"
    stale.write_text("old", encoding="utf-8")
    policy.write_text("second", encoding="utf-8")

    create_evidence_bundle(
        target,
        result=_minimal_result(),
        policy_path=policy,
        report_paths=[],
        force=True,
    )

    assert not stale.exists()
    assert (target / ".finguard-evidence").is_file()
    assert verify_evidence_bundle(target)["verified"] is True


def test_evidence_without_ownership_marker_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "evidence"
    policy = tmp_path / "policy.toml"
    policy.write_text("policy", encoding="utf-8")
    create_evidence_bundle(
        target,
        result=_minimal_result(),
        policy_path=policy,
        report_paths=[],
    )
    (target / ".finguard-evidence").unlink()
    with pytest.raises(EvidenceVerificationError, match="ownership marker"):
        verify_evidence_bundle(target)


def test_evidence_refuses_symlink_inputs(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text("policy", encoding="utf-8")
    linked_policy = tmp_path / "linked-policy.toml"
    linked_policy.symlink_to(policy)

    with pytest.raises(ConfigurationError, match="symlink evidence input"):
        create_evidence_bundle(
            tmp_path / "evidence",
            result=_minimal_result(),
            policy_path=linked_policy,
            report_paths=[],
        )


def _strict_release(
    project_root: Path,
    tmp_path: Path,
    *,
    finished: dt.datetime | None = None,
) -> tuple[
    Policy,
    list[ScanResult],
    ChangeRequest,
    ReleaseSubject,
    list[Path],
    ApprovalAttestation,
    Path,
]:
    scenario = project_root / "examples/scenarios/pass"
    policy = Policy.load(project_root / "policies/financial-release.toml")
    policy = replace(
        policy,
        change=replace(
            policy.change,
            allowed_approval_key_ids=("onprem-itsm-cosign-v1",),
            allowed_approval_signature_methods=("hmac-sha256",),
        ),
    )
    subject = ReleaseSubject.load(scenario / "release-subject.json")
    change = ChangeRequest.load(scenario / "change.toml")
    reports = discover_reports(scenario / "reports")
    scans = [parse_report(path) for path in reports]
    key = b"scan-attestation-test-key"
    rulesets = {
        "ruff": project_root / "pyproject.toml",
        "junit": project_root / "pyproject.toml",
        "coverage.py": project_root / "pyproject.toml",
        "semgrep": project_root / ".semgrep/secure-coding.yml",
        "trivy": project_root / "config/trivy.yaml",
        "cyclonedx": project_root / "config/trivy.yaml",
        "owasp-zap": project_root / "config/zap-rules.conf",
    }
    commands = {
        "ruff": "ruff check . --exit-zero --output-format=json",
        "junit": "pytest --junitxml",
        "coverage.py": "pytest --cov=finguard --cov-report=xml",
        "semgrep": "semgrep scan --config .semgrep/secure-coding.yml",
        "trivy": "trivy image security",
        "cyclonedx": "trivy image cyclonedx",
        "owasp-zap": "zap-baseline.py -c zap-rules.conf",
    }
    finished = finished or dt.datetime(2026, 9, 1, 0, 5, tzinfo=dt.UTC)
    started = finished - dt.timedelta(minutes=5)
    attestation_paths: list[Path] = []
    for index, (report, scan) in enumerate(zip(reports, scans, strict=True), start=1):
        output = tmp_path / "attestations" / f"{index:02d}-{scan.scanner}.json"
        create_scan_attestation(
            output,
            report_path=report,
            scanner=scan.scanner,
            category=scan.category,
            scanner_version="1.0.0",
            scanner_uri=f"tool://{scan.scanner}@1.0.0",
            source_commit=subject.commit_sha,
            image_digest=(
                subject.image_digest
                if scan.category in policy.provenance.artifact_bound_categories
                else ""
            ),
            ruleset_sha256=_sha256(rulesets[scan.scanner]),
            database_sha256=(
                "d" * 64 if scan.scanner in policy.provenance.require_database_for_scanners else ""
            ),
            database_updated_at=(
                finished.isoformat()
                if scan.scanner in policy.provenance.require_database_for_scanners
                else ""
            ),
            command_sha256=digest_text(commands[scan.scanner]),
            ci_job_id=f"job-{index}",
            runner_id="gitlab:onprem-protected",
            exit_code=0,
            complete=True,
            target_uri=(str(scan.metrics["targets"][0]) if scan.category == "dast" else ""),
            started_at=started,
            finished_at=finished,
            signing_key=key,
            key_id="onprem-scan-attestor-v1",
        )
        scan.provenance = load_scan_attestation(output, report_path=report, signing_key=key)
        attestation_paths.append(output)
    approval_path = tmp_path / "approval-attestation.json"
    approval_key = b"approval-attestation-test-key"
    create_approval_attestation(
        approval_path,
        change=change,
        release_subject=subject,
        issuer="itsm://change-management",
        source_uri="https://itsm.example/changes/CB-2026-0107",
        event_id="itsm-event-1",
        issued_at=finished,
        signing_key=approval_key,
        key_id="onprem-itsm-cosign-v1",
    )
    approval = load_approval_attestation(approval_path, signing_key=approval_key)
    return policy, scans, change, subject, attestation_paths, approval, approval_path


def test_strict_release_accepts_fresh_signed_report_attestations(
    project_root: Path, tmp_path: Path
) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        approval_attestation=approval,
        expected_commit=subject.commit_sha,
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC),
    )
    assert result.decision is Decision.PASS
    assert result.metrics["active_finding_count"] == 0
    assert result.metrics["inventory_count"] == 1
    assert result.inventory[0].metadata["observed_by"] == ["cyclonedx", "trivy"]


def test_strict_release_requires_verified_external_approval(
    project_root: Path, tmp_path: Path
) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    now = dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC)

    missing = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        now=now,
    )
    unverified = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        approval_attestation=replace(approval, signature_verified=False),
        now=now,
    )

    assert "APPROVAL_ATTESTATION_MISSING" in {item.code for item in missing.violations}
    assert "APPROVAL_ATTESTATION_UNTRUSTED" in {item.code for item in unverified.violations}


def test_external_approval_is_bound_to_issuer_signer_subject_and_time(
    project_root: Path, tmp_path: Path
) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    invalid = replace(
        approval,
        issuer="itsm://rogue",
        key_id="unknown-key",
        change_id="CB-OTHER",
        release_subject_sha256="b" * 64,
        issued_at=dt.datetime(2026, 8, 29, tzinfo=dt.UTC),
    )
    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        approval_attestation=invalid,
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC),
    )
    codes = {item.code for item in result.violations}
    assert {
        "APPROVAL_ISSUER_UNTRUSTED",
        "APPROVAL_SIGNER_UNTRUSTED",
        "APPROVAL_ATTESTATION_SUBJECT_MISMATCH",
        "APPROVAL_ATTESTATION_TIME_INVALID",
    } <= codes


def test_external_approval_is_bound_to_complete_change_request(
    project_root: Path, tmp_path: Path
) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    altered_change = replace(
        change,
        deployer="unapproved-operator@company.example",
        rollback_plan="승인 이후 바뀐 별도 복구 절차이며 원래 승인 내용과 일치하지 않는다.",
    )

    result = PolicyEngine(policy).evaluate(
        scans,
        change=altered_change,
        release_subject=subject,
        approval_attestation=approval,
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC),
    )

    violation = next(
        item for item in result.violations if item.code == "APPROVAL_ATTESTATION_SUBJECT_MISMATCH"
    )
    assert "change_request_sha256" in violation.details["fields"]


def test_approval_attestation_tampering_breaks_signature(
    project_root: Path, tmp_path: Path
) -> None:
    *_, approval_path = _strict_release(project_root, tmp_path)
    envelope = json.loads(approval_path.read_text(encoding="utf-8"))
    envelope["payload"]["event_id"] = "tampered-event"
    approval_path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="signature mismatch"):
        load_approval_attestation(
            approval_path,
            signing_key=b"approval-attestation-test-key",
        )


def test_cli_creates_external_approval_adapter_envelope(
    project_root: Path, tmp_path: Path, monkeypatch, capsys
) -> None:
    scenario = project_root / "examples/scenarios/pass"
    output = tmp_path / "approval.json"
    monkeypatch.setenv("TEST_APPROVAL_KEY", "approval-attestation-test-key")

    code = main(
        [
            "attest-approval",
            "--change",
            str(scenario / "change.toml"),
            "--subject",
            str(scenario / "release-subject.json"),
            "--issuer",
            "itsm://change-management",
            "--source-uri",
            "https://itsm.example/changes/CB-2026-0107",
            "--event-id",
            "itsm-event-1",
            "--issued-at",
            "2026-09-01T00:05:00Z",
            "--output",
            str(output),
            "--signing-key-env",
            "TEST_APPROVAL_KEY",
            "--key-id",
            "onprem-itsm-v1",
        ]
    )

    assert code == EXIT_OK
    assert json.loads(capsys.readouterr().out)["approval_attestation"] == str(output)
    approval = load_approval_attestation(
        output,
        signing_key=b"approval-attestation-test-key",
    )
    assert approval.change_id == "CB-2026-0107"
    assert approval.signature_verified is True


def test_cli_loads_and_captures_strict_attestations(
    project_root: Path, tmp_path: Path, monkeypatch, capsys
) -> None:
    _, _, _, _, attestation_paths, _, approval_path = _strict_release(
        project_root, tmp_path, finished=dt.datetime.now(dt.UTC)
    )
    monkeypatch.setenv("TEST_SCAN_KEY", "scan-attestation-test-key")
    monkeypatch.setenv("TEST_EVIDENCE_KEY", "evidence-test-key")
    monkeypatch.setattr("finguard.cli.cosign_verify_blob", lambda *args, **kwargs: None)
    approval_bundle = tmp_path / "approval-attestation.sigstore.json"
    approval_bundle.write_text("{}\n", encoding="utf-8")
    scenario = project_root / "examples/scenarios/pass"
    code = main(
        [
            "gate",
            "--policy",
            str(project_root / "policies/financial-release.toml"),
            "--reports",
            str(scenario / "reports"),
            "--attestations",
            str(attestation_paths[0].parent),
            "--attestation-key-env",
            "TEST_SCAN_KEY",
            "--change",
            str(scenario / "change.toml"),
            "--approval-attestation",
            str(approval_path),
            "--approval-cosign-bundle",
            str(approval_bundle),
            "--approval-cosign-verification-key",
            "keys/itsm-cosign.pub",
            "--approval-cosign-key-id",
            "onprem-itsm-cosign-v1",
            "--subject",
            str(scenario / "release-subject.json"),
            "--expected-commit",
            "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
            "--output",
            str(tmp_path / "evidence"),
            "--signing-key-env",
            "TEST_EVIDENCE_KEY",
            "--signing-key-id",
            "evidence-key-v1",
        ]
    )
    assert code == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "pass"
    decision = json.loads((tmp_path / "evidence/decision.json").read_text(encoding="utf-8"))
    assert all(scan["provenance"]["signature_verified"] for scan in decision["scans"])
    assert decision["metrics"]["approval_attestation_verified"] is True
    assert (tmp_path / "evidence/inputs/approval-attestation.json").is_file()


def test_strict_release_rejects_stale_and_artifact_mismatched_scan(
    project_root: Path, tmp_path: Path
) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    artifact_scan = next(scan for scan in scans if scan.category == "dast")
    assert artifact_scan.provenance is not None
    artifact_scan.provenance = replace(
        artifact_scan.provenance,
        image_digest="sha256:" + "b" * 64,
        started_at="2026-08-29T00:00:00+00:00",
        finished_at="2026-08-29T00:05:00+00:00",
    )
    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        approval_attestation=approval,
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC),
    )
    codes = {item.code for item in result.violations}
    assert "SCAN_ATTESTATION_SUBJECT_MISMATCH" in codes
    assert "SCAN_ATTESTATION_STALE" in codes


def test_strict_release_rejects_unapproved_scanner_exit_code(
    project_root: Path, tmp_path: Path
) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    scan = next(item for item in scans if item.scanner == "ruff")
    assert scan.provenance is not None
    scan.provenance = replace(scan.provenance, exit_code=7)

    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        approval_attestation=approval,
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC),
    )

    assert "SCAN_EXIT_CODE_UNACCEPTABLE" in {item.code for item in result.violations}


def test_strict_release_rejects_unapproved_scanner_command(
    project_root: Path, tmp_path: Path
) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    scan = next(item for item in scans if item.scanner == "semgrep")
    assert scan.provenance is not None
    scan.provenance = replace(scan.provenance, command_sha256="f" * 64)

    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        approval_attestation=approval,
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC),
    )

    assert "SCAN_COMMAND_UNTRUSTED" in {item.code for item in result.violations}


def test_strict_release_rejects_stale_vulnerability_database(
    project_root: Path, tmp_path: Path
) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    scan = next(item for item in scans if item.scanner == "trivy")
    assert scan.provenance is not None
    scan.provenance = replace(
        scan.provenance,
        database_updated_at="2026-08-01T00:00:00+00:00",
    )

    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        approval_attestation=approval,
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC),
    )

    assert "SCAN_DATABASE_STALE" in {item.code for item in result.violations}


def test_dast_attestation_target_must_match_report_target(
    project_root: Path, tmp_path: Path
) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    scan = next(item for item in scans if item.category == "dast")
    assert scan.provenance is not None
    scan.provenance = replace(scan.provenance, target_uri="https://other.example/")

    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        approval_attestation=approval,
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC),
    )

    violation = next(
        item for item in result.violations if item.code == "SCAN_ATTESTATION_SUBJECT_MISMATCH"
    )
    assert "target_uri" in violation.details["fields"]


def test_dast_attestation_rejects_multi_target_report(project_root: Path, tmp_path: Path) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    scan = next(item for item in scans if item.category == "dast")
    scan.metrics["targets"] = [
        *scan.metrics["targets"],
        "https://unapproved-target.example/",
    ]

    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        approval_attestation=approval,
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC),
    )

    violation = next(
        item for item in result.violations if item.code == "SCAN_ATTESTATION_SUBJECT_MISMATCH"
    )
    assert "target_uri" in violation.details["fields"]


def test_required_approval_roles_must_have_distinct_people(project_root: Path) -> None:
    scenario = project_root / "examples/scenarios/pass"
    policy = Policy.load(project_root / "policies/financial-baseline.toml")
    policy = replace(
        policy,
        gate=replace(
            policy.gate,
            required_categories=(),
            required_scanners=(),
            min_coverage_percent=0,
        ),
        provenance=replace(policy.provenance, require_release_subject=False),
    )
    change = ChangeRequest.load(scenario / "change.toml")
    shared_person = "same-reviewer@example.com"
    change = replace(
        change,
        approvals=(
            Approval(shared_person, "security", dt.datetime(2026, 8, 31, tzinfo=dt.UTC)),
            Approval(
                shared_person,
                "release_manager",
                dt.datetime(2026, 8, 31, 1, tzinfo=dt.UTC),
            ),
        ),
    )

    result = PolicyEngine(policy).evaluate(
        [], change=change, now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC)
    )

    assert "APPROVAL_ROLE_SEPARATION_VIOLATION" in {item.code for item in result.violations}


def test_report_tampering_breaks_attestation_binding(project_root: Path, tmp_path: Path) -> None:
    report = tmp_path / "ruff.json"
    report.write_bytes((project_root / "examples/scenarios/pass/reports/ruff.json").read_bytes())
    attestation = tmp_path / "ruff.attestation.json"
    now = dt.datetime(2026, 9, 1, tzinfo=dt.UTC)
    create_scan_attestation(
        attestation,
        report_path=report,
        scanner="ruff",
        category="lint",
        scanner_version="1.0",
        scanner_uri="tool://ruff@1.0",
        source_commit="a" * 40,
        image_digest="",
        ruleset_sha256="b" * 64,
        command_sha256="c" * 64,
        ci_job_id="job-1",
        runner_id="gitlab:onprem-protected",
        exit_code=0,
        complete=True,
        target_uri="",
        started_at=now,
        finished_at=now,
        signing_key=b"key",
        key_id="onprem-scan-attestor-v1",
    )
    report.write_bytes(report.read_bytes() + b" ")
    with pytest.raises(EvidenceVerificationError, match="does not match report"):
        load_scan_attestation(attestation, report_path=report, signing_key=b"key")


def test_release_subject_mismatch_blocks_gate(project_root: Path, tmp_path: Path) -> None:
    policy, scans, change, subject, _, approval, _ = _strict_release(project_root, tmp_path)
    different = replace(
        subject,
        image="registry.example/credit/api@sha256:" + "b" * 64,
    )
    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=different,
        approval_attestation=approval,
        expected_commit=subject.commit_sha,
        now=dt.datetime(2026, 9, 1, 1, 0, tzinfo=dt.UTC),
    )
    codes = {item.code for item in result.violations}
    assert "RELEASE_SUBJECT_MISMATCH" in codes
    assert "SCAN_ATTESTATION_SUBJECT_MISMATCH" in codes


def test_commit_binding_requires_complete_object_ids() -> None:
    full = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
    assert commit_matches(full, full.upper()) is True
    assert commit_matches(full, full[:12]) is False
    assert commit_matches(full, "a") is False
    assert commit_matches(full, "not-a-sha") is False


def test_multiple_coverage_reports_fail_instead_of_using_best_value(
    project_root: Path,
) -> None:
    policy = Policy.load(project_root / "policies/merge-request.toml")
    policy = replace(
        policy,
        gate=replace(
            policy.gate,
            required_categories=(),
            required_scanners=(),
            min_coverage_percent=0,
        ),
    )
    scans = [
        ScanResult(
            scanner="coverage.py",
            category="test",
            status=ScanStatus.PASSED,
            metrics={"coverage_percent": value},
        )
        for value in (40.0, 100.0)
    ]
    result = PolicyEngine(policy).evaluate(scans)
    assert result.decision is Decision.FAIL
    assert result.metrics["coverage_percent"] == 0
    assert "COVERAGE_REPORT_AMBIGUOUS" in {item.code for item in result.violations}


def test_zap_preserves_each_unique_instance(tmp_path: Path) -> None:
    report = tmp_path / "zap.json"
    report.write_text(
        json.dumps(
            {
                "site": [
                    {
                        "@name": "https://service.example",
                        "alerts": [
                            {
                                "pluginid": "10020",
                                "alert": "Missing security header",
                                "riskcode": "2",
                                "instances": [
                                    {"uri": "https://service.example/a", "method": "GET"},
                                    {"uri": "https://service.example/b", "method": "POST"},
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = parse_report(report)
    assert {(item.location, item.metadata["method"]) for item in result.findings} == {
        ("/a", "GET"),
        ("/b", "POST"),
    }


def test_spdx_and_or_expressions_apply_correct_obligations() -> None:
    arguments = {
        "allowed": {"MIT", "Apache-2.0"},
        "denied": {"GPL-3.0-only"},
        "review_required": {"MPL-2.0"},
        "allow_unknown": False,
    }
    optional = evaluate_spdx_expression("MIT OR GPL-3.0-only", **arguments)
    combined = evaluate_spdx_expression("MIT AND GPL-3.0-only", **arguments)
    assert optional.disposition is LicenseDisposition.ALLOWED
    assert combined.disposition is LicenseDisposition.DENIED


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("MPL-2.0", LicenseDisposition.REVIEW),
        ("Unknown-License", LicenseDisposition.NOT_ALLOWED),
        ("MIT WITH Classpath-exception-2.0", LicenseDisposition.REVIEW),
        ("(MIT AND Apache-2.0) OR GPL-3.0-only", LicenseDisposition.ALLOWED),
        ("MIT $$$ Apache-2.0", LicenseDisposition.UNKNOWN),
        ("(MIT AND Apache-2.0", LicenseDisposition.UNKNOWN),
    ],
)
def test_spdx_expression_edge_cases(expression: str, expected: LicenseDisposition) -> None:
    result = evaluate_spdx_expression(
        expression,
        allowed={"MIT", "Apache-2.0"},
        denied={"GPL-3.0-only"},
        review_required={"MPL-2.0"},
        allow_unknown=False,
    )
    assert result.disposition is expected


def test_attestation_signature_and_directory_errors(project_root: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text("[]\n", encoding="utf-8")
    now = dt.datetime(2026, 9, 1, tzinfo=dt.UTC)
    output = tmp_path / "attestations/report.json"
    arguments = {
        "report_path": report,
        "scanner": "ruff",
        "category": "lint",
        "scanner_version": "1.0",
        "scanner_uri": "tool://ruff@1.0",
        "source_commit": "a" * 40,
        "image_digest": "",
        "ruleset_sha256": "b" * 64,
        "command_sha256": "c" * 64,
        "ci_job_id": "job-1",
        "runner_id": "gitlab:onprem-protected",
        "exit_code": 0,
        "complete": True,
        "target_uri": "",
        "started_at": now,
        "finished_at": now,
    }
    with pytest.raises(EvidenceVerificationError, match="key_id"):
        create_scan_attestation(output, **arguments, signing_key=b"key")

    create_scan_attestation(output, **arguments, signing_key=b"key", key_id="key-v1")
    with pytest.raises(EvidenceVerificationError, match="signature mismatch"):
        load_scan_attestation(output, report_path=report, signing_key=b"wrong")

    envelope = json.loads(output.read_text(encoding="utf-8"))
    envelope["signature"]["algorithm"] = "unsupported"
    output.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(EvidenceVerificationError, match="unsupported"):
        load_scan_attestation(output)

    with pytest.raises(EvidenceVerificationError, match="does not exist"):
        load_attestation_directory(tmp_path / "missing", [report])


def test_change_approval_must_follow_final_build(project_root: Path) -> None:
    scenario = project_root / "examples/scenarios/pass"
    policy = Policy.load(project_root / "policies/financial-baseline.toml")
    subject = ReleaseSubject.load(scenario / "release-subject.json")
    change = ChangeRequest.load(scenario / "change.toml")
    too_late_build = replace(
        subject,
        built_at=dt.datetime(2026, 9, 1, 12, 0, tzinfo=dt.UTC),
    )
    change = replace(change, release_subject=too_late_build)
    policy = replace(
        policy,
        provenance=replace(policy.provenance, require_release_subject=False),
        gate=replace(
            policy.gate,
            required_categories=(),
            required_scanners=(),
            min_coverage_percent=0,
        ),
    )
    result = PolicyEngine(policy).evaluate([], change=change)
    assert "APPROVAL_PRECEDES_BUILD" in {item.code for item in result.violations}


def test_exception_scope_and_validity_are_enforced(project_root: Path) -> None:
    policy = Policy.load(project_root / "policies/merge-request.toml")
    policy = replace(
        policy,
        gate=replace(
            policy.gate,
            required_categories=(),
            required_scanners=(),
            min_coverage_percent=0,
        ),
    )
    finding = Finding(
        scanner="semgrep",
        category="sast",
        rule_id="python.sql-injection",
        severity=Severity.HIGH,
        message="SQL injection",
        location="app.py:10",
    )
    scan = ScanResult(
        scanner="semgrep",
        category="sast",
        status=ScanStatus.FINDINGS,
        findings=[finding],
    )
    exception = PolicyException(
        exception_id="EXC-1",
        fingerprint=finding.fingerprint,
        reason="Temporary compatibility issue with tracked remediation",
        owner="owner@example.com",
        approver="security@example.com",
        created_at=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
        expires_at=dt.datetime(2026, 9, 15, tzinfo=dt.UTC),
        ticket="RISK-1",
        category="sast",
        severity="high",
        policy_id=policy.policy_id,
        policy_version=policy.version,
        compensating_controls="Ingress allowlist and WAF rule are monitored daily.",
    )
    result = PolicyEngine(policy).evaluate(
        [scan],
        exceptions=[exception],
        now=dt.datetime(2026, 9, 2, tzinfo=dt.UTC),
    )
    assert result.decision is Decision.PASS
    assert len(result.excepted_findings) == 1

    overlong = replace(exception, expires_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC))
    result = PolicyEngine(policy).evaluate(
        [scan],
        exceptions=[overlong],
        now=dt.datetime(2026, 9, 2, tzinfo=dt.UTC),
    )
    assert "EXCEPTION_VALIDITY_EXCEEDED" in {item.code for item in result.violations}

    future = replace(
        exception,
        created_at=dt.datetime(2026, 9, 10, tzinfo=dt.UTC),
        expires_at=dt.datetime(2026, 9, 15, tzinfo=dt.UTC),
    )
    result = PolicyEngine(policy).evaluate(
        [scan],
        exceptions=[future],
        now=dt.datetime(2026, 9, 2, tzinfo=dt.UTC),
    )
    assert "EXCEPTION_TIME_INVALID" in {item.code for item in result.violations}
    assert [item.fingerprint for item in result.active_findings] == [finding.fingerprint]


def test_deployment_window_duration_and_expiry_are_policy_controlled(
    project_root: Path,
) -> None:
    scenario = project_root / "examples/scenarios/pass"
    policy = Policy.load(project_root / "policies/financial-baseline.toml")
    policy = replace(
        policy,
        gate=replace(
            policy.gate,
            required_categories=(),
            required_scanners=(),
            min_coverage_percent=0,
        ),
        provenance=replace(policy.provenance, require_release_subject=False),
    )
    change = ChangeRequest.load(scenario / "change.toml")
    wide = replace(
        change,
        window_start=dt.datetime(2026, 9, 2, tzinfo=dt.UTC),
        window_end=dt.datetime(2026, 9, 4, tzinfo=dt.UTC),
    )
    wide_result = PolicyEngine(policy).evaluate(
        [], change=wide, now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC)
    )
    assert "DEPLOYMENT_WINDOW_TOO_LONG" in {item.code for item in wide_result.violations}

    expired = replace(
        change,
        window_start=dt.datetime(2026, 8, 30, tzinfo=dt.UTC),
        window_end=dt.datetime(2026, 8, 31, tzinfo=dt.UTC),
    )
    expired_result = PolicyEngine(policy).evaluate(
        [], change=expired, now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC)
    )
    assert "DEPLOYMENT_WINDOW_EXPIRED" in {item.code for item in expired_result.violations}


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()
