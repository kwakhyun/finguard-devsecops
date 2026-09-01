from __future__ import annotations

import datetime as dt
from dataclasses import replace
from pathlib import Path

from finguard.change import ChangeRequest
from finguard.config import Policy, PolicyException
from finguard.gate import PolicyEngine
from finguard.models import Decision, Finding, ScanResult, ScanStatus, Severity
from finguard.parsers import discover_reports, parse_report
from finguard.release import ReleaseSubject


def _scenario(project_root: Path, name: str):
    directory = project_root / "examples/scenarios" / name
    scans = [parse_report(path) for path in discover_reports(directory / "reports")]
    return (
        scans,
        ChangeRequest.load(directory / "change.toml"),
        ReleaseSubject.load(directory / "release-subject.json"),
    )


def test_financial_policy_passes_complete_clean_evidence(project_root: Path) -> None:
    policy = Policy.load(project_root / "policies/financial-baseline.toml")
    scans, change, subject = _scenario(project_root, "pass")
    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    )
    assert result.decision is Decision.PASS
    assert result.violations == []
    assert result.metrics["coverage_percent"] == 93.0


def test_financial_policy_blocks_risky_release(project_root: Path) -> None:
    policy = Policy.load(project_root / "policies/financial-baseline.toml")
    scans, change, subject = _scenario(project_root, "fail")
    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    )
    codes = {violation.code for violation in result.violations}
    assert result.decision is Decision.FAIL
    assert {
        "BLOCKING_FINDINGS",
        "LICENSE_DENIED",
        "COVERAGE_BELOW_THRESHOLD",
        "SEPARATION_OF_DUTIES_VIOLATION",
        "APPROVAL_ROLE_MISSING",
    }.issubset(codes)


def test_valid_exception_suppresses_exact_fingerprint(project_root: Path) -> None:
    policy = Policy.load(project_root / "policies/financial-baseline.toml")
    policy = replace(
        policy,
        gate=replace(
            policy.gate,
            required_categories=(),
            required_scanners=(),
            min_coverage_percent=0,
            max_findings={next(iter(policy.gate.max_findings)): 0},
        ),
        change=replace(policy.change, required=False),
        provenance=replace(policy.provenance, require_release_subject=False),
        exceptions=replace(
            policy.exceptions,
            require_scope=False,
            require_compensating_controls=False,
        ),
    )
    finding_scan = parse_report(project_root / "examples/scenarios/fail/reports/ruff.json")
    finding = finding_scan.findings[0]
    exception = PolicyException(
        exception_id="EXC-1",
        fingerprint=finding.fingerprint,
        reason="Approved temporary mitigation",
        owner="owner@example.com",
        approver="reviewer@example.com",
        expires_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC),
        ticket="RISK-1",
    )
    result = PolicyEngine(policy).evaluate(
        [finding_scan],
        exceptions=[exception],
        now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    )
    assert result.decision is Decision.PASS
    assert [item.fingerprint for item in result.excepted_findings] == [finding.fingerprint]


def test_expired_exception_is_rejected(project_root: Path) -> None:
    policy = Policy.load(project_root / "policies/financial-baseline.toml")
    policy = replace(
        policy,
        gate=replace(
            policy.gate,
            required_categories=(),
            required_scanners=(),
            min_coverage_percent=0,
        ),
        change=replace(policy.change, required=False),
        provenance=replace(policy.provenance, require_release_subject=False),
    )
    scan = parse_report(project_root / "examples/scenarios/fail/reports/semgrep.json")
    exception = PolicyException(
        exception_id="EXPIRED-1",
        fingerprint=scan.findings[0].fingerprint,
        reason="Expired temporary mitigation",
        owner="owner@example.com",
        approver="reviewer@example.com",
        expires_at=dt.datetime(2026, 8, 1, tzinfo=dt.UTC),
        ticket="RISK-2",
    )
    result = PolicyEngine(policy).evaluate(
        [scan],
        exceptions=[exception],
        now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    )
    assert result.decision is Decision.FAIL
    assert "EXCEPTION_EXPIRED" in {item.code for item in result.violations}


def test_pipeline_commit_must_match_change_manifest(project_root: Path) -> None:
    policy = Policy.load(project_root / "policies/financial-baseline.toml")
    scans, change, subject = _scenario(project_root, "pass")
    result = PolicyEngine(policy).evaluate(
        scans,
        change=change,
        release_subject=subject,
        expected_commit="0123456789abcdef",
        now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    )
    assert "COMMIT_MISMATCH" in {item.code for item in result.violations}


def test_unknown_duplicate_cannot_replace_a_known_blocking_severity(
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
            fail_on_unknown_severity=False,
            max_findings={},
        ),
    )
    common = {
        "category": "sast",
        "rule_id": "security.rule",
        "message": "same issue",
        "location": "src/app.py:7",
    }
    scans = [
        ScanResult(
            scanner="known-scanner",
            category="sast",
            status=ScanStatus.FINDINGS,
            findings=[Finding(scanner="known-scanner", severity=Severity.CRITICAL, **common)],
        ),
        ScanResult(
            scanner="unknown-scanner",
            category="sast",
            status=ScanStatus.FINDINGS,
            findings=[Finding(scanner="unknown-scanner", severity=Severity.UNKNOWN, **common)],
        ),
    ]

    result = PolicyEngine(policy).evaluate(scans, now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC))

    assert result.decision is Decision.FAIL
    assert result.active_findings[0].severity is Severity.CRITICAL
    assert "BLOCKING_FINDINGS" in {item.code for item in result.violations}
