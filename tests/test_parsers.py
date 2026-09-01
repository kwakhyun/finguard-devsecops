from __future__ import annotations

import json
from pathlib import Path

import pytest

from finguard.errors import ReportParseError
from finguard.models import Severity
from finguard.parsers import discover_reports, parse_report


def test_pass_scenario_formats_are_auto_detected(project_root: Path) -> None:
    report_dir = project_root / "examples/scenarios/pass/reports"
    scans = [parse_report(path) for path in discover_reports(report_dir)]
    categories = {scan.category for scan in scans}
    assert categories == {"lint", "test", "sast", "sca", "dast"}
    assert sum(len(scan.findings) for scan in scans) == 2


def test_semgrep_and_trivy_details_are_normalized(project_root: Path) -> None:
    report_dir = project_root / "examples/scenarios/fail/reports"
    semgrep = parse_report(report_dir / "semgrep.json")
    trivy = parse_report(report_dir / "trivy.json")
    assert semgrep.findings[0].severity is Severity.HIGH
    vulnerability = next(item for item in trivy.findings if item.category == "sca")
    assert vulnerability.rule_id == "CVE-2099-0001"
    assert vulnerability.fixed_version == ""


def test_junit_failure_creates_finding(project_root: Path) -> None:
    report = project_root / "examples/scenarios/fail/reports/junit.xml"
    result = parse_report(report)
    assert result.metrics["test_failures"] == 1
    assert result.findings[0].location.endswith("test_rejects_duplicate_request")


def test_unknown_json_fails_closed(tmp_path: Path) -> None:
    report = tmp_path / "unknown.json"
    report.write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(ReportParseError, match="cannot detect"):
        parse_report(report)


def test_xml_reports_reject_dtd_and_entity_declarations(tmp_path: Path) -> None:
    report = tmp_path / "coverage.xml"
    report.write_text(
        '<!DOCTYPE coverage [<!ENTITY value "1">]><coverage line-rate="&value;" />',
        encoding="utf-8",
    )

    with pytest.raises(ReportParseError, match="DTD and entity"):
        parse_report(report)


def test_cyclonedx_includes_nested_components_and_uses_stricter_cvss_score(
    tmp_path: Path,
) -> None:
    report = tmp_path / "sbom.cdx.json"
    report.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "application",
                        "bom-ref": "app@1",
                        "name": "app",
                        "version": "1",
                        "licenses": [{"license": {"id": "MIT"}}],
                        "components": [
                            {
                                "type": "library",
                                "bom-ref": "nested@2",
                                "name": "nested",
                                "version": "2",
                                "licenses": [{"license": {"id": "AGPL-3.0-only"}}],
                            }
                        ],
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2099-9999",
                        "ratings": [{"severity": "low", "score": 9.8}],
                        "affects": [{"ref": "nested@2"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = parse_report(report, "cyclonedx")

    assert result.metrics["component_count"] == 2
    assert {item.license_id for item in result.findings if item.category == "license"} == {
        "MIT",
        "AGPL-3.0-only",
    }
    vulnerability = next(item for item in result.findings if item.category == "sca")
    assert vulnerability.severity is Severity.CRITICAL
    assert vulnerability.component == "nested"


def test_null_fixed_version_is_not_treated_as_an_available_fix(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "image",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2099-0001",
                                "PkgName": "library",
                                "InstalledVersion": "1.0.0",
                                "FixedVersion": None,
                                "Severity": "HIGH",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = parse_report(report, "trivy")

    assert result.findings[0].fixed_version == ""


def test_cyclonedx_rejects_null_component_name_and_oversized_score(tmp_path: Path) -> None:
    invalid_payloads = [
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": None, "licenses": [{"license": {"id": "MIT"}}]}],
        },
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [],
            "vulnerabilities": [
                {
                    "id": "CVE-2099-0002",
                    "ratings": [{"score": 10**400}],
                }
            ],
        },
    ]
    for index, payload in enumerate(invalid_payloads):
        report = tmp_path / f"invalid-{index}.cdx.json"
        report.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ReportParseError):
            parse_report(report, "cyclonedx")
