"""SARIF 2.1 adapter for Semgrep, Coverity, Sonar, and compatible analyzers."""

from __future__ import annotations

import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from finguard.errors import ReportParseError
from finguard.models import Finding, ScanResult, ScanStatus, Severity

from .common import generated_at, location


def parse_sarif(data: object, path: Path) -> ScanResult:
    if not isinstance(data, dict):
        raise ReportParseError(f"invalid SARIF report: {path}")
    runs = _objects(data.get("runs"), "runs", path, required=True)
    findings: list[Finding] = []
    errors: list[str] = []
    scanners: set[str] = set()
    for run_index, run in enumerate(runs):
        tool = _mapping(run.get("tool"), f"runs[{run_index}].tool", path, required=True)
        driver = _mapping(tool.get("driver"), f"runs[{run_index}].tool.driver", path, required=True)
        scanner_raw = driver.get("name")
        if not isinstance(scanner_raw, str) or not scanner_raw.strip():
            raise ReportParseError(f"runs[{run_index}].tool.driver.name is required in {path}")
        scanner = scanner_raw.strip().casefold()
        scanners.add(scanner)
        rules = _rules(driver.get("rules", []), path, run_index)
        invocations = _objects(run.get("invocations", []), f"runs[{run_index}].invocations", path)
        for invocation_index, invocation in enumerate(invocations):
            successful = invocation.get("executionSuccessful")
            if successful is not None and not isinstance(successful, bool):
                raise ReportParseError(
                    f"runs[{run_index}].invocations[{invocation_index}]."
                    f"executionSuccessful must be a boolean in {path}"
                )
            if successful is False:
                errors.append(f"{scanner} execution was not successful")
        results = _objects(run.get("results", []), f"runs[{run_index}].results", path)
        for result_index, item in enumerate(results):
            context = f"runs[{run_index}].results[{result_index}]"
            rule_id_raw = item.get("ruleId")
            if not isinstance(rule_id_raw, str) or not rule_id_raw.strip():
                raise ReportParseError(f"{context}.ruleId is required in {path}")
            rule_id = rule_id_raw.strip()
            rule = rules.get(rule_id, {})
            message_data = _mapping(item.get("message"), f"{context}.message", path, required=True)
            message_raw = message_data.get("text") or message_data.get("markdown")
            if not isinstance(message_raw, str) or not message_raw.strip():
                raise ReportParseError(f"{context}.message text is required in {path}")
            path_text, line, column = _physical_location(item, context, path)
            properties = _mapping(item.get("properties", {}), f"{context}.properties", path)
            severity = _severity(item, rule, properties, context, path)
            tags = rule.get("tags", [])
            if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
                raise ReportParseError(f"rule tags must be an array of strings in {path}")
            suppressions = _objects(item.get("suppressions", []), f"{context}.suppressions", path)
            findings.append(
                Finding(
                    scanner=scanner,
                    category="sast",
                    rule_id=rule_id,
                    severity=severity,
                    message=message_raw.strip(),
                    location=location(path_text, line, column),
                    cwe=tuple(tag for tag in tags if tag.upper().startswith("CWE-")),
                    metadata={
                        "help_uri": rule.get("help_uri", ""),
                        "sarif_level": item.get("level", ""),
                        # SARIF suppressions are audit data only. FinGuard exceptions
                        # remain the only policy-controlled suppression path.
                        "reported_suppressions": suppressions,
                    },
                )
            )
    scanner_name = next(iter(scanners)) if len(scanners) == 1 else "sarif"
    status = (
        ScanStatus.ERROR if errors else (ScanStatus.FINDINGS if findings else ScanStatus.PASSED)
    )
    return ScanResult(
        scanner=scanner_name,
        category="sast",
        status=status,
        findings=findings,
        errors=errors,
        metrics={"run_count": len(runs), "tool_count": len(scanners)},
        source=str(path),
        generated_at=generated_at(path),
    )


def _objects(
    value: object,
    field: str,
    path: Path,
    *,
    required: bool = False,
) -> list[dict[str, object]]:
    if value is None:
        if required:
            raise ReportParseError(f"{field} is required in {path}")
        return []
    if not isinstance(value, list):
        raise ReportParseError(f"{field} must be an array in {path}")
    result: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ReportParseError(f"{field}[{index}] must be an object in {path}")
        result.append(item)
    return result


def _mapping(
    value: object,
    field: str,
    path: Path,
    *,
    required: bool = False,
) -> dict[str, object]:
    if value is None:
        if required:
            raise ReportParseError(f"{field} is required in {path}")
        return {}
    if not isinstance(value, dict):
        raise ReportParseError(f"{field} must be an object in {path}")
    return value


def _rules(value: object, path: Path, run_index: int) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for rule_index, item in enumerate(
        _objects(value, f"runs[{run_index}].tool.driver.rules", path)
    ):
        context = f"runs[{run_index}].tool.driver.rules[{rule_index}]"
        rule_id_raw = item.get("id")
        if not isinstance(rule_id_raw, str) or not rule_id_raw.strip():
            raise ReportParseError(f"{context}.id is required in {path}")
        rule_id = rule_id_raw.strip()
        if rule_id in result:
            raise ReportParseError(f"duplicate SARIF rule id {rule_id} in {path}")
        properties = _mapping(item.get("properties", {}), f"{context}.properties", path)
        configuration = _mapping(
            item.get("defaultConfiguration", {}),
            f"{context}.defaultConfiguration",
            path,
        )
        tags = properties.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise ReportParseError(f"{context}.properties.tags must be strings in {path}")
        help_uri = item.get("helpUri", "")
        if not isinstance(help_uri, str):
            raise ReportParseError(f"{context}.helpUri must be a string in {path}")
        result[rule_id] = {
            "level": configuration.get("level", ""),
            "security_severity": properties.get("security-severity", ""),
            "tags": tags,
            "help_uri": help_uri,
        }
    return result


def _severity(
    item: Mapping[str, object],
    rule: Mapping[str, Any],
    properties: Mapping[str, object],
    context: str,
    path: Path,
) -> Severity:
    score = properties.get("security-severity") or rule.get("security_severity")
    if score not in (None, ""):
        if isinstance(score, bool) or not isinstance(score, (str, int, float)):
            raise ReportParseError(f"{context} security severity is invalid in {path}")
        try:
            numeric = float(score)
        except (ValueError, OverflowError) as exc:
            raise ReportParseError(
                f"{context} security severity must be numeric in {path}"
            ) from exc
        if not math.isfinite(numeric) or not 0 <= numeric <= 10:
            raise ReportParseError(
                f"{context} security severity must be between 0 and 10 in {path}"
            )
        if numeric >= 9:
            return Severity.CRITICAL
        if numeric >= 7:
            return Severity.HIGH
        if numeric >= 4:
            return Severity.MEDIUM
        return Severity.LOW
    level = item.get("level") or rule.get("level") or "warning"
    if not isinstance(level, str):
        raise ReportParseError(f"{context}.level must be a string in {path}")
    return {
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "note": Severity.LOW,
        "none": Severity.INFO,
    }.get(level.casefold(), Severity.UNKNOWN)


def _physical_location(
    item: Mapping[str, object], context: str, path: Path
) -> tuple[str, int | None, int | None]:
    locations = _objects(item.get("locations", []), f"{context}.locations", path)
    if not locations:
        return "", None, None
    physical = _mapping(
        locations[0].get("physicalLocation"),
        f"{context}.locations[0].physicalLocation",
        path,
        required=True,
    )
    artifact = _mapping(
        physical.get("artifactLocation", {}),
        f"{context}.locations[0].physicalLocation.artifactLocation",
        path,
    )
    region = _mapping(
        physical.get("region", {}),
        f"{context}.locations[0].physicalLocation.region",
        path,
    )
    uri = artifact.get("uri", "")
    if not isinstance(uri, str):
        raise ReportParseError(f"{context} artifact URI must be a string in {path}")
    line = _positive_integer(region.get("startLine"), f"{context} startLine", path)
    column = _positive_integer(region.get("startColumn"), f"{context} startColumn", path)
    return uri, line, column


def _positive_integer(value: object, field: str, path: Path) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ReportParseError(f"{field} must be a positive integer in {path}")
    return value
