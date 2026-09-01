"""Adapters for coverage.py and JUnit XML reports."""

from __future__ import annotations

import math
import xml.etree.ElementTree as ET
from pathlib import Path

from finguard.errors import ReportParseError
from finguard.models import Finding, ScanResult, ScanStatus, Severity

from .common import MAX_REPORT_BYTES, generated_at


def _root(path: Path) -> ET.Element:
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            raise ReportParseError(f"XML report exceeds 50 MiB limit: {path}")
        payload = path.read_bytes()
        upper_payload = payload.upper()
        if b"<!DOCTYPE" in upper_payload or b"<!ENTITY" in upper_payload:
            raise ReportParseError(f"XML DTD and entity declarations are not allowed: {path}")
        return ET.fromstring(payload)  # noqa: S314 - DTD and entities are rejected above
    except ReportParseError:
        raise
    except (OSError, ET.ParseError) as exc:
        raise ReportParseError(f"cannot parse XML report {path}: {exc}") from exc


def parse_coverage(path: Path) -> ScanResult:
    root = _root(path)
    if root.tag != "coverage":
        raise ReportParseError(f"not a coverage XML report: {path}")
    try:
        line_rate = float(root.attrib["line-rate"])
    except ValueError as exc:
        raise ReportParseError(f"invalid coverage line-rate in {path}") from exc
    except KeyError as exc:
        raise ReportParseError(f"coverage line-rate is missing in {path}") from exc
    if not math.isfinite(line_rate) or not 0 <= line_rate <= 1:
        raise ReportParseError(f"coverage line-rate must be finite and between 0 and 1 in {path}")
    metrics: dict[str, float | int | str | bool] = {}
    branch_rate: float | None = None
    if "branch-rate" in root.attrib:
        try:
            branch_rate = float(root.attrib["branch-rate"])
        except ValueError as exc:
            raise ReportParseError(f"invalid coverage branch-rate in {path}") from exc
        if not math.isfinite(branch_rate) or not 0 <= branch_rate <= 1:
            raise ReportParseError(
                f"coverage branch-rate must be finite and between 0 and 1 in {path}"
            )
    required_counts = {"lines-valid", "lines-covered"}
    if not required_counts.issubset(root.attrib):
        raise ReportParseError(f"coverage line counts are required in {path}")
    if branch_rate is not None:
        required_branch_counts = {"branches-valid", "branches-covered"}
        if not required_branch_counts.issubset(root.attrib):
            raise ReportParseError(f"coverage branch counts are required in {path}")
    elif "branches-valid" in root.attrib or "branches-covered" in root.attrib:
        raise ReportParseError(f"coverage branch counts require branch-rate in {path}")
    for source_name, target_name in (
        ("lines-valid", "lines_valid"),
        ("lines-covered", "lines_covered"),
        ("branches-valid", "branches_valid"),
        ("branches-covered", "branches_covered"),
    ):
        if source_name in root.attrib:
            try:
                value = int(root.attrib[source_name])
            except ValueError as exc:
                raise ReportParseError(f"invalid {source_name} in {path}") from exc
            if value < 0:
                raise ReportParseError(f"{source_name} cannot be negative in {path}")
            metrics[target_name] = value
    _validate_coverage_counts(metrics, line_rate, branch_rate, path)
    lines_valid = int(metrics["lines_valid"])
    lines_covered = int(metrics["lines_covered"])
    metrics["coverage_percent"] = lines_covered / lines_valid * 100 if lines_valid else 0.0
    if branch_rate is not None:
        branches_valid = int(metrics["branches_valid"])
        branches_covered = int(metrics["branches_covered"])
        metrics["branch_coverage_percent"] = (
            branches_covered / branches_valid * 100 if branches_valid else 0.0
        )
    return ScanResult(
        scanner="coverage.py",
        category="test",
        status=ScanStatus.PASSED,
        metrics=metrics,
        source=str(path),
        generated_at=generated_at(path),
    )


def parse_junit(path: Path) -> ScanResult:
    root = _root(path)
    if root.tag not in {"testsuite", "testsuites"}:
        raise ReportParseError(f"not a JUnit XML report: {path}")
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    if not suites:
        raise ReportParseError(f"JUnit report contains no test suites: {path}")
    counts = {
        name: sum(_nonnegative_int(suite.attrib.get(name, "0"), name, path) for suite in suites)
        for name in ("tests", "failures", "errors", "skipped")
    }
    tests = counts["tests"]
    failures = counts["failures"]
    errors = counts["errors"]
    skipped = counts["skipped"]
    if failures + errors + skipped > tests:
        raise ReportParseError(f"JUnit result counts exceed total tests in {path}")
    findings: list[Finding] = []
    observed_failures = 0
    observed_errors = 0
    observed_skipped = 0
    observed_cases = 0
    for suite in suites:
        for case in suite.findall("testcase"):
            observed_cases += 1
            outcomes = [child for child in case if child.tag in {"failure", "error", "skipped"}]
            if len(outcomes) > 1:
                raise ReportParseError(f"JUnit testcase has multiple outcomes in {path}")
            issue = outcomes[0] if outcomes else None
            if issue is None:
                continue
            if issue.tag == "skipped":
                observed_skipped += 1
                continue
            if issue.tag == "failure":
                observed_failures += 1
            else:
                observed_errors += 1
            class_name = case.attrib.get("classname", "")
            test_name = case.attrib.get("name", "unknown")
            findings.append(
                Finding(
                    scanner="junit",
                    category="test",
                    rule_id="test.failure",
                    severity=Severity.HIGH,
                    message=(issue.attrib.get("message") or issue.text or "Test failed").strip(),
                    location=f"{class_name}::{test_name}".strip(":"),
                )
            )
    if observed_cases != tests:
        raise ReportParseError(f"JUnit testcase count does not match declared tests in {path}")
    if (observed_failures, observed_errors, observed_skipped) != (failures, errors, skipped):
        raise ReportParseError(f"JUnit outcome elements do not match declared counts in {path}")
    return ScanResult(
        scanner="junit",
        category="test",
        status=ScanStatus.FINDINGS if failures + errors else ScanStatus.PASSED,
        findings=findings,
        metrics={"tests": tests, "test_failures": failures + errors, "skipped": skipped},
        source=str(path),
        generated_at=generated_at(path),
    )


def _nonnegative_int(value: object, field: str, path: Path) -> int:
    try:
        result = int(str(value))
    except ValueError as exc:
        raise ReportParseError(f"invalid JUnit {field} in {path}") from exc
    if result < 0:
        raise ReportParseError(f"JUnit {field} cannot be negative in {path}")
    return result


def _validate_coverage_counts(
    metrics: dict[str, float | int | str | bool],
    line_rate: float,
    branch_rate: float | None,
    path: Path,
) -> None:
    for valid_key, covered_key in (
        ("lines_valid", "lines_covered"),
        ("branches_valid", "branches_covered"),
    ):
        if valid_key not in metrics or covered_key not in metrics:
            continue
        valid = int(metrics[valid_key])
        covered = int(metrics[covered_key])
        if covered > valid:
            raise ReportParseError(f"{covered_key} exceeds {valid_key} in {path}")
        expected = covered / valid if valid else 0.0
        reported = line_rate if valid_key == "lines_valid" else branch_rate
        if reported is not None:
            if not math.isclose(reported, expected, abs_tol=0.0001):
                raise ReportParseError(
                    f"coverage rate is inconsistent with {valid_key} counts in {path}"
                )
