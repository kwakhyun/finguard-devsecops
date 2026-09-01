"""Developer feedback, policy comparison, and operational metric renderers."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .jsonio import strict_json_loads
from .models import GateResult
from .safeio import atomic_write_text


def load_decision(path: Path) -> dict[str, Any]:
    try:
        value = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ConfigurationError(f"cannot load gate decision {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("decision") not in {"pass", "fail"}:
        raise ConfigurationError(f"not a FinGuard gate decision: {path}")
    return value


def gitlab_code_quality(decision: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for finding in _active_findings(decision):
        path, line = _source_location(str(finding.get("location", "")), finding)
        result.append(
            {
                "description": str(finding.get("message", "FinGuard finding")),
                "check_name": str(finding.get("rule_id", "finguard")),
                "fingerprint": str(finding.get("fingerprint", "")),
                "severity": _gitlab_severity(str(finding.get("severity", "unknown"))),
                "location": {"path": path, "lines": {"begin": line}},
            }
        )
    return result


def sarif_output(decision: Mapping[str, Any]) -> dict[str, Any]:
    findings = _active_findings(decision)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = str(finding.get("rule_id", "finguard"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": str(finding.get("message", rule_id))[:200]},
            },
        )
        path, line = _source_location(str(finding.get("location", "")), finding)
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(str(finding.get("severity", "unknown"))),
                "message": {"text": str(finding.get("message", "FinGuard finding"))},
                "partialFingerprints": {
                    "finguardFingerprint/v1": str(finding.get("fingerprint", ""))
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": path},
                            "region": {"startLine": line},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FinGuard",
                        "informationUri": "https://finguard.dev",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def prometheus_metrics(decision: Mapping[str, Any]) -> str:
    policy = decision.get("policy", {})
    if not isinstance(policy, Mapping):
        policy = {}
    labels = (
        f'policy_id="{_escape_label(str(policy.get("id", "unknown")))}",'
        f'policy_version="{_escape_label(str(policy.get("version", "unknown")))}"'
    )
    metrics = decision.get("metrics", {})
    if not isinstance(metrics, Mapping):
        metrics = {}
    violations = decision.get("violations", [])
    violation_count = len(violations) if isinstance(violations, list) else 0
    passed = 1 if decision.get("decision") == "pass" else 0
    lines = [
        "# HELP finguard_gate_pass Whether the policy gate passed.",
        "# TYPE finguard_gate_pass gauge",
        f"finguard_gate_pass{{{labels}}} {passed}",
        "# HELP finguard_gate_findings Active security and quality findings.",
        "# TYPE finguard_gate_findings gauge",
        f"finguard_gate_findings{{{labels}}} {int(metrics.get('active_finding_count', 0))}",
        "# HELP finguard_gate_exceptions Findings covered by an approved exception.",
        "# TYPE finguard_gate_exceptions gauge",
        f"finguard_gate_exceptions{{{labels}}} {int(metrics.get('excepted_finding_count', 0))}",
        "# HELP finguard_gate_vexed_findings Findings suppressed by accepted VEX analysis.",
        "# TYPE finguard_gate_vexed_findings gauge",
        f"finguard_gate_vexed_findings{{{labels}}} {int(metrics.get('vexed_finding_count', 0))}",
        "# HELP finguard_gate_inventory_components OSS inventory records evaluated.",
        "# TYPE finguard_gate_inventory_components gauge",
        f"finguard_gate_inventory_components{{{labels}}} {int(metrics.get('inventory_count', 0))}",
        "# HELP finguard_gate_policy_violations Policy violations emitted by the gate.",
        "# TYPE finguard_gate_policy_violations gauge",
        f"finguard_gate_policy_violations{{{labels}}} {violation_count}",
        "# HELP finguard_approval_attestation_verified Whether external approval was verified.",
        "# TYPE finguard_approval_attestation_verified gauge",
        (
            f"finguard_approval_attestation_verified{{{labels}}} "
            f"{int(bool(metrics.get('approval_attestation_verified', False)))}"
        ),
        "# HELP finguard_test_coverage_percent Canonical line coverage percentage.",
        "# TYPE finguard_test_coverage_percent gauge",
        (
            f"finguard_test_coverage_percent{{{labels}}} "
            f"{float(metrics.get('coverage_percent', 0)):.2f}"
        ),
    ]
    severity_counts = metrics.get("severity_counts", {})
    if isinstance(severity_counts, Mapping):
        for severity in ("critical", "high", "medium", "low", "info", "unknown"):
            count = int(severity_counts.get(severity, 0))
            lines.append(
                f'finguard_gate_findings_by_severity{{{labels},severity="{severity}"}} {count}'
            )
    return "\n".join(lines) + "\n"


def compare_gate_results(baseline: GateResult, candidate: GateResult) -> dict[str, Any]:
    return compare_decisions(baseline.to_dict(), candidate.to_dict())


def compare_decisions(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    baseline_violations = _violation_codes(baseline)
    candidate_violations = _violation_codes(candidate)
    baseline_findings = _finding_fingerprints(baseline)
    candidate_findings = _finding_fingerprints(candidate)
    baseline_policy = baseline.get("policy", {})
    candidate_policy = candidate.get("policy", {})
    return {
        "schema_version": "1.0",
        "baseline_policy": baseline_policy,
        "candidate_policy": candidate_policy,
        "baseline_decision": baseline.get("decision", "unknown"),
        "candidate_decision": candidate.get("decision", "unknown"),
        "decision_changed": baseline.get("decision") != candidate.get("decision"),
        "added_violations": sorted(candidate_violations - baseline_violations),
        "removed_violations": sorted(baseline_violations - candidate_violations),
        "newly_active_findings": sorted(candidate_findings - baseline_findings),
        "no_longer_active_findings": sorted(baseline_findings - candidate_findings),
    }


def write_output(path: Path, value: object, *, text_output: bool = False) -> None:
    content = (
        str(value)
        if text_output
        else json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    )
    atomic_write_text(path, content, context="report export")


def _active_findings(decision: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    findings = decision.get("findings", {})
    active = findings.get("active", []) if isinstance(findings, Mapping) else []
    return [item for item in active if isinstance(item, Mapping)]


def _violation_codes(decision: Mapping[str, Any]) -> set[str]:
    violations = decision.get("violations", [])
    if not isinstance(violations, list):
        return set()
    return {
        str(item.get("code", ""))
        for item in violations
        if isinstance(item, Mapping) and item.get("code")
    }


def _finding_fingerprints(decision: Mapping[str, Any]) -> set[str]:
    return {
        str(item.get("fingerprint", ""))
        for item in _active_findings(decision)
        if item.get("fingerprint")
    }


def _source_location(value: str, finding: Mapping[str, Any]) -> tuple[str, int]:
    match = re.match(r"^(.*?):(\d+)(?::\d+)?$", value)
    if match:
        return match.group(1), max(1, int(match.group(2)))
    if value and not value.startswith(("http://", "https://")):
        return value, 1
    component = str(finding.get("component", "dependency") or "dependency")
    return f"dependencies/{component}", 1


def _gitlab_severity(value: str) -> str:
    return {
        "critical": "blocker",
        "high": "critical",
        "medium": "major",
        "low": "minor",
        "info": "info",
    }.get(value.casefold(), "major")


def _sarif_level(value: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(value.casefold(), "warning")


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
