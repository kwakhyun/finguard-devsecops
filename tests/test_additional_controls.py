from __future__ import annotations

import datetime as dt
import json
from dataclasses import replace
from pathlib import Path

import pytest

from finguard.change import ChangeRequest
from finguard.config import Policy, PolicyException, load_exceptions
from finguard.errors import ConfigurationError, EvidenceVerificationError, ReportParseError
from finguard.evidence import create_evidence_bundle, verify_evidence_bundle
from finguard.gate import PolicyEngine
from finguard.models import Finding, ScanResult, ScanStatus, Severity
from finguard.parsers import parse_report
from finguard.scanners import scan_source, scan_web


def test_cyclonedx_vulnerability_and_license_are_parsed(tmp_path: Path) -> None:
    report = tmp_path / "sbom.cdx.json"
    report.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "pkg:pypi/demo@1.0",
                        "name": "demo",
                        "version": "1.0",
                        "licenses": [{"license": {"id": "MIT"}}],
                    },
                    {"bom-ref": "unknown", "name": "unknown-lib", "version": "2.0"},
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2099-2",
                        "description": "example",
                        "ratings": [{"severity": "high", "score": 8.1}],
                        "affects": [{"ref": "pkg:pypi/demo@1.0"}],
                        "recommendation": "upgrade to 1.1",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = parse_report(report)
    assert result.metrics["component_count"] == 2
    assert {item.license_id for item in result.findings if item.license_id} == {"MIT", "UNKNOWN"}
    vulnerability = next(item for item in result.findings if item.category == "sca")
    assert vulnerability.severity is Severity.HIGH
    assert vulnerability.fixed_version == ""
    assert vulnerability.metadata["recommendation"] == "upgrade to 1.1"


def test_pip_audit_and_extended_trivy_findings_are_parsed(tmp_path: Path) -> None:
    audit = tmp_path / "pip-audit.json"
    audit.write_text(
        json.dumps(
            {
                "dependencies": [
                    {
                        "name": "demo",
                        "version": "1.0",
                        "vulns": [
                            {
                                "id": "PYSEC-2099-1",
                                "description": "example vulnerability",
                                "fix_versions": ["1.1"],
                                "aliases": ["CVE-2099-3"],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert parse_report(audit).findings[0].fixed_version == "1.1"

    trivy = tmp_path / "trivy-extra.json"
    trivy.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "Dockerfile",
                        "Misconfigurations": [
                            {"ID": "DS001", "Severity": "MEDIUM", "Title": "Example config"}
                        ],
                        "Secrets": [
                            {
                                "RuleID": "secret-key",
                                "Severity": "HIGH",
                                "Title": "Secret",
                                "StartLine": 7,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    categories = {item.category for item in parse_report(trivy).findings}
    assert categories == {"iac", "secret"}


def test_normalized_report_and_explicit_xml_type(tmp_path: Path) -> None:
    normalized = ScanResult(
        scanner="custom",
        category="sast",
        status=ScanStatus.PASSED,
        generated_at="2026-09-01T00:00:00+00:00",
    )
    normalized_path = tmp_path / "custom.json"
    normalized.write_json(normalized_path)
    assert parse_report(normalized_path).scanner == "custom"

    coverage_path = tmp_path / "metrics.xml"
    coverage_path.write_text(
        '<coverage line-rate="0.875" lines-valid="40" lines-covered="35" />',
        encoding="utf-8",
    )
    assert parse_report(coverage_path, "coverage").metrics["coverage_percent"] == 87.5
    with pytest.raises(ReportParseError, match="explicit type"):
        parse_report(coverage_path)


def test_exception_file_validation(tmp_path: Path) -> None:
    exceptions = tmp_path / "exceptions.toml"
    exceptions.write_text(
        """
[[exceptions]]
id = "EXC-1"
fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
reason = "temporary"
owner = "owner@example.com"
approver = "reviewer@example.com"
expires_at = 2099-01-01T00:00:00Z
ticket = "RISK-1"
""".strip(),
        encoding="utf-8",
    )
    loaded = load_exceptions(exceptions)
    assert loaded[0].exception_id == "EXC-1"
    assert loaded[0].is_expired is False
    entry = exceptions.read_text(encoding="utf-8")
    exceptions.write_text(f"{entry}\n{entry}\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="duplicate exception"):
        load_exceptions(exceptions)


def test_policy_rejects_conflicting_license_lists(project_root: Path, tmp_path: Path) -> None:
    source = (project_root / "policies/financial-baseline.toml").read_text(encoding="utf-8")
    invalid = source.replace(
        'denied = ["AGPL-3.0-only"',
        'denied = ["MIT", "AGPL-3.0-only"',
    )
    path = tmp_path / "invalid-policy.toml"
    path.write_text(invalid, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="multiple dispositions"):
        Policy.load(path)


def test_change_rejects_non_hex_commit(project_root: Path, tmp_path: Path) -> None:
    source = (project_root / "examples/scenarios/pass/change.toml").read_text(encoding="utf-8")
    path = tmp_path / "change.toml"
    path.write_text(
        source.replace("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", "not-a-sha"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="Git object ID"):
        ChangeRequest.load(path)


def test_missing_scans_errors_and_unknown_severity_fail_closed(project_root: Path) -> None:
    policy = Policy.load(project_root / "policies/financial-baseline.toml")
    policy = replace(
        policy,
        gate=replace(policy.gate, min_coverage_percent=0),
        change=replace(policy.change, required=False),
        provenance=replace(policy.provenance, require_release_subject=False),
    )
    error_scan = ScanResult(
        scanner="broken-semgrep",
        category="sast",
        status=ScanStatus.ERROR,
        errors=["scanner crashed"],
        findings=[
            Finding(
                scanner="broken-semgrep",
                category="sast",
                rule_id="unknown-rule",
                severity=Severity.UNKNOWN,
                message="unranked",
            )
        ],
    )
    result = PolicyEngine(policy).evaluate([error_scan])
    codes = {item.code for item in result.violations}
    assert {
        "REQUIRED_SCAN_MISSING",
        "REQUIRED_SCANNER_MISSING",
        "SCANNER_ERROR",
        "UNKNOWN_SEVERITY",
    }.issubset(codes)


def test_self_approved_exception_is_not_applied(project_root: Path) -> None:
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
        exceptions=replace(
            policy.exceptions,
            require_scope=False,
            require_compensating_controls=False,
        ),
    )
    scan = parse_report(project_root / "examples/scenarios/fail/reports/semgrep.json")
    exception = PolicyException(
        exception_id="SELF-1",
        fingerprint=scan.findings[0].fingerprint,
        reason="invalid self approval",
        owner="same@example.com",
        approver="same@example.com",
        expires_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC),
        ticket="RISK-3",
    )
    result = PolicyEngine(policy).evaluate(
        [scan],
        exceptions=[exception],
        now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    )
    assert "EXCEPTION_SELF_APPROVED" in {item.code for item in result.violations}


def test_native_sast_and_dast_error_paths(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "invalid.py").write_text("def broken(:\n", encoding="utf-8")
    assert scan_source(tmp_path).status is ScanStatus.ERROR

    def unavailable(*args, **kwargs):
        raise TimeoutError("unavailable")

    class UnavailableOpener:
        open = staticmethod(unavailable)

    monkeypatch.setattr("urllib.request.build_opener", lambda *handlers: UnavailableOpener())
    web = scan_web("https://service.example/health")
    assert web.status is ScanStatus.ERROR
    assert "target request failed" in web.errors[0]


def test_unsigned_or_corrupt_evidence_is_rejected(project_root: Path, tmp_path: Path) -> None:
    policy_path = project_root / "policies/financial-baseline.toml"
    policy = Policy.load(policy_path)
    scan = ScanResult(scanner="custom", category="test", status=ScanStatus.PASSED)
    relaxed = replace(
        policy,
        gate=replace(
            policy.gate,
            required_categories=("test",),
            required_scanners=(),
            min_coverage_percent=0,
        ),
        change=replace(policy.change, required=False),
        provenance=replace(policy.provenance, require_release_subject=False),
    )
    result = PolicyEngine(relaxed).evaluate([scan])
    report = tmp_path / "report.json"
    scan.write_json(report)
    output = tmp_path / "evidence"
    create_evidence_bundle(
        output,
        result=result,
        policy_path=policy_path,
        report_paths=[report],
    )
    with pytest.raises(EvidenceVerificationError, match="manifest.sig is missing"):
        verify_evidence_bundle(output, signing_key=b"unexpected-key")
    (output / "audit.jsonl").write_text("not-json\n", encoding="utf-8")
    with pytest.raises(EvidenceVerificationError, match="hash mismatch"):
        verify_evidence_bundle(output)
