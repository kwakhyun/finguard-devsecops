from __future__ import annotations

import datetime as dt
import json
from dataclasses import replace
from pathlib import Path

import pytest

from finguard.config import Policy
from finguard.errors import EvidenceVerificationError
from finguard.gate import PolicyEngine
from finguard.models import Decision
from finguard.parsers import parse_report
from finguard.release import ReleaseSubject
from finguard.vex import VexStatement, create_vex_attestation, load_vex_attestation

NOW = dt.datetime(2026, 9, 1, tzinfo=dt.UTC)
VEX_KEY = b"trusted-vex-review-key"


def _policy(project_root: Path) -> Policy:
    policy = Policy.load(project_root / "policies/merge-request.toml")
    return replace(
        policy,
        gate=replace(
            policy.gate,
            required_categories=(),
            required_scanners=(),
            min_coverage_percent=0,
        ),
        vex=replace(
            policy.vex,
            allowed_issuers=("vex://security-review",),
            allowed_key_ids=("test-vex-hmac-v1",),
            allowed_signature_methods=("hmac-sha256",),
        ),
    )


def _report(
    tmp_path: Path,
    *,
    severity: str = "high",
    state: str = "not_affected",
    justification: str = "code_not_reachable",
    detail: str = "The vulnerable parser is excluded from every production execution path.",
) -> Path:
    path = tmp_path / f"{severity}-{state}.cdx.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "pkg:pypi/example@1.0",
                        "name": "example",
                        "version": "1.0",
                        "licenses": [{"license": {"id": "MIT"}}],
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2099-1000",
                        "ratings": [{"severity": severity}],
                        "affects": [{"ref": "pkg:pypi/example@1.0"}],
                        "analysis": {
                            "state": state,
                            "justification": justification,
                            "detail": detail,
                            "response": ["will_not_fix"],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _subject(project_root: Path, sbom_sha256: str) -> ReleaseSubject:
    subject = ReleaseSubject.load(project_root / "examples/scenarios/pass/release-subject.json")
    return replace(subject, sbom_sha256=sbom_sha256)


def _signed_vex(
    tmp_path: Path,
    *,
    subject: ReleaseSubject,
    fingerprint: str,
    state: str = "not_affected",
    justification: str = "code_not_reachable",
    detail: str = "The vulnerable parser is excluded from every production execution path.",
):
    path = tmp_path / "vex-attestation.json"
    create_vex_attestation(
        path,
        release_subject=subject,
        issuer="vex://security-review",
        source_uri="https://security.example/reviews/VEX-1000",
        event_id="vex-review-event-1000",
        approver="security-reviewer@example.com",
        issued_at=NOW - dt.timedelta(hours=1),
        expires_at=NOW + dt.timedelta(days=1),
        statements=(
            VexStatement(
                fingerprint=fingerprint,
                state=state,
                justification=justification,
                detail=detail,
            ),
        ),
        key_id="test-vex-hmac-v1",
        signing_key=VEX_KEY,
        force=True,
    )
    return load_vex_attestation(path, signing_key=VEX_KEY)


def test_vex_rejects_non_object_signature(project_root: Path, tmp_path: Path) -> None:
    report = parse_report(_report(tmp_path))
    subject = _subject(project_root, report.input_sha256)
    finding = next(item for item in report.findings if item.rule_id.startswith("CVE-"))
    _signed_vex(tmp_path, subject=subject, fingerprint=finding.fingerprint)
    path = tmp_path / "vex-attestation.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["signature"] = "not-an-object"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="signature must be an object"):
        load_vex_attestation(path)


def test_scanner_reported_vex_cannot_suppress_without_trusted_attestation(
    project_root: Path, tmp_path: Path
) -> None:
    scan = parse_report(_report(tmp_path))
    result = PolicyEngine(_policy(project_root)).evaluate([scan], now=NOW)

    assert result.decision is Decision.FAIL
    assert not result.vexed_findings
    assert "VEX_ATTESTATION_MISSING" in {item.code for item in result.violations}
    assert "BLOCKING_FINDINGS" in {item.code for item in result.violations}


def test_signed_subject_bound_vex_suppresses_high_finding(
    project_root: Path, tmp_path: Path
) -> None:
    scan = parse_report(_report(tmp_path))
    subject = _subject(project_root, scan.input_sha256)
    vulnerability = next(item for item in scan.findings if item.rule_id.startswith("CVE-"))
    attestation = _signed_vex(
        tmp_path,
        subject=subject,
        fingerprint=vulnerability.fingerprint,
    )

    result = PolicyEngine(_policy(project_root)).evaluate(
        [scan], release_subject=subject, vex_attestation=attestation, now=NOW
    )

    assert result.decision is Decision.PASS
    assert len(result.vexed_findings) == 1
    assert result.metrics["vexed_finding_count"] == 1
    assert result.metrics["vex_attestation_verified"] is True


def test_signed_vex_fails_closed_for_short_detail_and_critical_severity(
    project_root: Path, tmp_path: Path
) -> None:
    high_scan = parse_report(_report(tmp_path, detail="too short"))
    subject = _subject(project_root, high_scan.input_sha256)
    high_finding = next(item for item in high_scan.findings if item.rule_id.startswith("CVE-"))
    insufficient = _signed_vex(
        tmp_path,
        subject=subject,
        fingerprint=high_finding.fingerprint,
        detail="too short",
    )
    high_result = PolicyEngine(_policy(project_root)).evaluate(
        [high_scan], release_subject=subject, vex_attestation=insufficient, now=NOW
    )
    assert "VEX_JUSTIFICATION_INSUFFICIENT" in {item.code for item in high_result.violations}
    assert "BLOCKING_FINDINGS" in {item.code for item in high_result.violations}

    critical_scan = parse_report(_report(tmp_path, severity="critical"))
    subject = _subject(project_root, critical_scan.input_sha256)
    critical_finding = next(
        item for item in critical_scan.findings if item.rule_id.startswith("CVE-")
    )
    critical_vex = _signed_vex(
        tmp_path,
        subject=subject,
        fingerprint=critical_finding.fingerprint,
    )
    critical_result = PolicyEngine(_policy(project_root)).evaluate(
        [critical_scan], release_subject=subject, vex_attestation=critical_vex, now=NOW
    )
    assert "VEX_SEVERITY_NOT_SUPPRESSIBLE" in {item.code for item in critical_result.violations}
    assert "BLOCKING_FINDINGS" in {item.code for item in critical_result.violations}


def test_unknown_scanner_reported_vex_state_is_a_policy_violation(
    project_root: Path, tmp_path: Path
) -> None:
    scan = parse_report(_report(tmp_path, state="invented_state"))
    result = PolicyEngine(_policy(project_root)).evaluate([scan], now=NOW)

    assert "VEX_STATE_INVALID" in {item.code for item in result.violations}


def test_vex_partition_preserves_order_and_rejections(project_root, tmp_path):
    from finguard.checks.suppression import SuppressionChecks
    from finguard.models import Finding, Severity

    findings = [
        Finding("test", "sca", f"CVE-2099-{i}", Severity.HIGH, "issue", component=f"package-{i}")
        for i in range(30)
    ]
    findings[5] = replace(findings[5], severity=Severity.CRITICAL)
    subject = _subject(project_root, "a" * 64)
    attestation = _signed_vex(tmp_path, subject=subject, fingerprint=findings[0].fingerprint)
    statements = tuple(
        VexStatement(
            item.fingerprint,
            "not_affected",
            "code_not_reachable",
            "Reviewed execution paths cannot reach vulnerable code.",
        )
        for item in reversed(findings[::2] + [findings[5]])
    )
    attestation = replace(attestation, statements=statements)
    violations = []
    active, vexed = SuppressionChecks(_policy(project_root)).apply_vex(
        findings, attestation, subject, NOW, violations
    )
    assert active == findings[1::2]
    assert vexed == list(reversed(findings[::2]))
    assert [item.code for item in violations] == ["VEX_SEVERITY_NOT_SUPPRESSIBLE"]
