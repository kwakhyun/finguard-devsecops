from __future__ import annotations

import json
from pathlib import Path

from finguard.cli import EXIT_OK, main
from finguard.models import Decision, Finding, GateResult, Severity
from finguard.parsers import parse_report
from finguard.reporting import (
    compare_decisions,
    gitlab_code_quality,
    prometheus_metrics,
    sarif_output,
)


def _decision(severity: Severity = Severity.HIGH) -> GateResult:
    finding = Finding(
        scanner="semgrep",
        category="sast",
        rule_id="python.sql-injection",
        severity=severity,
        message="Possible SQL injection",
        location="service/app.py:42:7",
    )
    return GateResult(
        decision=Decision.FAIL,
        policy_id="POLICY",
        policy_version="1.0",
        violations=[],
        active_findings=[finding],
        excepted_findings=[],
        scan_results=[],
        metrics={
            "active_finding_count": 1,
            "excepted_finding_count": 0,
            "vexed_finding_count": 2,
            "inventory_count": 7,
            "approval_attestation_verified": True,
            "coverage_percent": 88.5,
            "severity_counts": {severity.label: 1},
        },
        evaluated_at="2026-09-01T00:00:00+00:00",
    )


def test_sarif_adapter_handles_security_score_and_location(tmp_path: Path) -> None:
    report = tmp_path / "coverity.sarif"
    report.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "Coverity",
                                "rules": [
                                    {
                                        "id": "SQLI",
                                        "helpUri": "https://example.test/SQLI",
                                        "properties": {
                                            "security-severity": "9.8",
                                            "tags": ["security", "CWE-89"],
                                        },
                                    }
                                ],
                            }
                        },
                        "invocations": [{"executionSuccessful": True}],
                        "results": [
                            {
                                "ruleId": "SQLI",
                                "message": {"text": "SQL injection"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/app.py"},
                                            "region": {"startLine": 9, "startColumn": 3},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = parse_report(report)
    assert result.scanner == "coverity"
    assert result.findings[0].severity is Severity.CRITICAL
    assert result.findings[0].location == "src/app.py:9:3"
    assert result.findings[0].cwe == ("CWE-89",)


def test_reporting_formats_are_machine_consumable() -> None:
    decision = _decision().to_dict()
    quality = gitlab_code_quality(decision)
    assert quality[0]["severity"] == "critical"
    assert quality[0]["location"]["lines"]["begin"] == 42
    sarif = sarif_output(decision)
    assert sarif["runs"][0]["results"][0]["level"] == "error"
    metrics = prometheus_metrics(decision)
    assert 'finguard_gate_pass{policy_id="POLICY",policy_version="1.0"} 0' in metrics
    assert "finguard_test_coverage_percent" in metrics
    assert "finguard_gate_vexed_findings" in metrics
    assert "finguard_gate_inventory_components" in metrics
    assert "finguard_gate_policy_violations" in metrics
    assert "finguard_approval_attestation_verified" in metrics


def test_cli_exports_and_compares_decisions(tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    candidate = tmp_path / "candidate.json"
    baseline.write_text(json.dumps(_decision().to_dict()), encoding="utf-8")
    candidate_value = _decision(Severity.MEDIUM).to_dict()
    candidate_value["decision"] = "pass"
    candidate.write_text(json.dumps(candidate_value), encoding="utf-8")

    quality = tmp_path / "code-quality.json"
    assert (
        main(
            [
                "export",
                "--decision",
                str(baseline),
                "--format",
                "gitlab-code-quality",
                "--output",
                str(quality),
            ]
        )
        == EXIT_OK
    )
    assert json.loads(quality.read_text(encoding="utf-8"))[0]["check_name"]
    capsys.readouterr()

    comparison = tmp_path / "comparison.json"
    assert (
        main(
            [
                "compare",
                "--baseline",
                str(baseline),
                "--candidate",
                str(candidate),
                "--output",
                str(comparison),
            ]
        )
        == EXIT_OK
    )
    assert json.loads(comparison.read_text(encoding="utf-8"))["decision_changed"] is True


def test_shadow_policy_is_recorded_without_changing_primary_decision(
    project_root: Path, tmp_path: Path, current_pass_change: Path, capsys
) -> None:
    baseline = project_root / "policies/financial-baseline.toml"
    candidate = tmp_path / "candidate.toml"
    candidate.write_text(
        baseline.read_text(encoding="utf-8")
        .replace('id = "FIN-SW-DEVSECOPS-BASELINE"', 'id = "FIN-SW-DEVSECOPS-SHADOW"')
        .replace("min_coverage_percent = 85.0", "min_coverage_percent = 95.0"),
        encoding="utf-8",
    )
    scenario = project_root / "examples/scenarios/pass"
    output = tmp_path / "evidence"
    code = main(
        [
            "gate",
            "--policy",
            str(baseline),
            "--shadow-policy",
            str(candidate),
            "--reports",
            str(scenario / "reports"),
            "--change",
            str(current_pass_change),
            "--subject",
            str(scenario / "release-subject.json"),
            "--output",
            str(output),
        ]
    )
    assert code == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "pass"
    assert payload["shadow"]["candidate_decision"] == "fail"
    comparison = json.loads((output / "policy-comparison.json").read_text(encoding="utf-8"))
    assert comparison["added_violations"] == ["COVERAGE_BELOW_THRESHOLD"]


def test_compare_decisions_reports_added_and_removed_items() -> None:
    baseline = _decision().to_dict()
    candidate = _decision(Severity.MEDIUM).to_dict()
    candidate["violations"] = [{"code": "NEW_POLICY_RULE"}]
    candidate["findings"]["active"][0]["fingerprint"] = "f" * 64
    comparison = compare_decisions(baseline, candidate)
    assert comparison["added_violations"] == ["NEW_POLICY_RULE"]
    assert comparison["newly_active_findings"]
    assert comparison["no_longer_active_findings"]
