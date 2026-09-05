"""Required scans, quality metrics, severity thresholds, and license controls."""

from __future__ import annotations

import math
from collections import Counter

from ..licenses import LicenseDisposition, evaluate_spdx_expression
from ..models import (
    Finding,
    GateViolation,
    ScanResult,
    ScanStatus,
    Severity,
)
from ..policy_types import Policy


class QualityChecks:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def check_required_scans(
        self, scans: list[ScanResult], violations: list[GateViolation]
    ) -> None:
        for category in self.policy.gate.required_categories:
            candidates = [scan for scan in scans if scan.category == category]
            usable = [
                scan
                for scan in candidates
                if scan.status not in {ScanStatus.ERROR, ScanStatus.SKIPPED}
            ]
            if not usable:
                violations.append(
                    GateViolation(
                        code="REQUIRED_SCAN_MISSING",
                        message=f"Required scan category has no usable report: {category}",
                        details={"category": category},
                    )
                )
        for scanner in self.policy.gate.required_scanners:
            candidates = [scan for scan in scans if scan.scanner == scanner]
            usable = [
                scan
                for scan in candidates
                if scan.status not in {ScanStatus.ERROR, ScanStatus.SKIPPED}
            ]
            if not usable:
                violations.append(
                    GateViolation(
                        code="REQUIRED_SCANNER_MISSING",
                        message=f"Required scanner has no usable report: {scanner}",
                        details={"scanner": scanner},
                    )
                )
        if self.policy.gate.fail_on_scanner_error:
            for scan in scans:
                if scan.status is ScanStatus.ERROR or scan.errors:
                    violations.append(
                        GateViolation(
                            code="SCANNER_ERROR",
                            message=f"Scanner did not complete cleanly: {scan.scanner}",
                            details={"scanner": scan.scanner, "errors": scan.errors},
                        )
                    )

    def check_sbom_completeness(
        self, scans: list[ScanResult], violations: list[GateViolation]
    ) -> None:
        for scan in scans:
            if scan.scanner != "cyclonedx":
                continue
            count = scan.metrics.get("component_count")
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or count < self.policy.gate.minimum_sbom_components
            ):
                violations.append(
                    GateViolation(
                        code="SBOM_INCOMPLETE",
                        message="SBOM component inventory does not meet policy",
                        details={
                            "actual": count,
                            "minimum": self.policy.gate.minimum_sbom_components,
                        },
                    )
                )

    def check_severities(
        self,
        findings: list[Finding],
        severity_counts: Counter[Severity],
        violations: list[GateViolation],
    ) -> None:
        blocking = [
            finding for finding in findings if finding.severity in self.policy.gate.block_severities
        ]
        if blocking:
            violations.append(
                GateViolation(
                    code="BLOCKING_FINDINGS",
                    message=f"Found {len(blocking)} finding(s) at a blocking severity",
                    details={
                        "fingerprints": [item.fingerprint for item in blocking],
                        "severities": sorted({item.severity.label for item in blocking}),
                    },
                )
            )
        if self.policy.gate.fail_on_unknown_severity and severity_counts[Severity.UNKNOWN]:
            violations.append(
                GateViolation(
                    code="UNKNOWN_SEVERITY",
                    message="One or more findings have an unknown severity",
                    details={"count": severity_counts[Severity.UNKNOWN]},
                )
            )
        for severity, maximum in self.policy.gate.max_findings.items():
            actual = severity_counts[severity]
            if actual > maximum:
                violations.append(
                    GateViolation(
                        code="FINDING_LIMIT_EXCEEDED",
                        message=(
                            f"{severity.label} finding count {actual} exceeds allowed "
                            f"maximum {maximum}"
                        ),
                        details={
                            "severity": severity.label,
                            "actual": actual,
                            "maximum": maximum,
                        },
                    )
                )
        if self.policy.gate.require_fixes_for_blocking_vulnerabilities:
            without_fix = [
                finding
                for finding in findings
                if finding.category == "sca"
                and finding.severity in self.policy.gate.block_severities
                and not finding.fixed_version
            ]
            if without_fix:
                violations.append(
                    GateViolation(
                        code="VULNERABILITY_WITHOUT_FIX",
                        message="Blocking dependency vulnerabilities have no known fixed version",
                        details={"fingerprints": [item.fingerprint for item in without_fix]},
                    )
                )

    def check_licenses(self, findings: list[Finding], violations: list[GateViolation]) -> None:
        for finding in findings:
            expression = (finding.license_id or "UNKNOWN").strip()
            evaluation = evaluate_spdx_expression(
                expression,
                allowed=set(self.policy.licenses.allowed),
                denied=set(self.policy.licenses.denied),
                review_required=set(self.policy.licenses.review_required),
                allow_unknown=self.policy.licenses.allow_unknown,
            )
            code = ""
            message = ""
            if evaluation.disposition is LicenseDisposition.DENIED:
                code = "LICENSE_DENIED"
                message = f"Denied open-source license detected: {expression}"
            elif evaluation.disposition is LicenseDisposition.REVIEW:
                code = "LICENSE_REVIEW_REQUIRED"
                message = f"Open-source license requires legal review: {expression}"
            elif evaluation.disposition is LicenseDisposition.UNKNOWN:
                code = "LICENSE_EXPRESSION_INVALID"
                message = f"Dependency license expression is unknown or invalid: {expression}"
            elif evaluation.disposition is LicenseDisposition.NOT_ALLOWED:
                code = "LICENSE_NOT_ALLOWLISTED"
                message = f"Open-source license is not allowlisted: {expression}"
            if code:
                violations.append(
                    GateViolation(
                        code=code,
                        message=message,
                        details={
                            "component": finding.component,
                            "fingerprint": finding.fingerprint,
                            "identifiers": list(evaluation.identifiers),
                        },
                    )
                )

    def check_test_metrics(
        self, scans: list[ScanResult], violations: list[GateViolation]
    ) -> tuple[float, int]:
        coverage_reports = [scan for scan in scans if scan.scanner == "coverage.py"]
        if len(coverage_reports) > 1:
            violations.append(
                GateViolation(
                    code="COVERAGE_REPORT_AMBIGUOUS",
                    message="Exactly one canonical coverage.py report is allowed",
                    details={"count": len(coverage_reports)},
                )
            )
        coverage = 0.0
        if len(coverage_reports) == 1:
            try:
                candidate = float(coverage_reports[0].metrics.get("coverage_percent", 0))
            except (TypeError, ValueError):
                candidate = math.nan
            if math.isfinite(candidate) and 0 <= candidate <= 100:
                coverage = candidate
            else:
                violations.append(
                    GateViolation(
                        code="COVERAGE_METRIC_INVALID",
                        message="Coverage metric must be finite and between 0 and 100",
                    )
                )
        test_failures = 0
        test_count = 0
        for scan in scans:
            if scan.category != "test":
                continue
            value = scan.metrics.get("test_failures", 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                violations.append(
                    GateViolation(
                        code="TEST_METRIC_INVALID",
                        message="Test failure count must be a non-negative integer",
                        details={"scanner": scan.scanner},
                    )
                )
                continue
            test_failures += value
            if scan.scanner == "junit":
                tests = scan.metrics.get("tests")
                if isinstance(tests, bool) or not isinstance(tests, int) or tests < 0:
                    violations.append(
                        GateViolation(
                            code="TEST_METRIC_INVALID",
                            message="Test count must be a non-negative integer",
                            details={"scanner": scan.scanner},
                        )
                    )
                else:
                    test_count += tests
        if coverage < self.policy.gate.min_coverage_percent:
            violations.append(
                GateViolation(
                    code="COVERAGE_BELOW_THRESHOLD",
                    message=(
                        f"Coverage {coverage:.2f}% is below required "
                        f"{self.policy.gate.min_coverage_percent:.2f}%"
                    ),
                    details={
                        "actual": coverage,
                        "minimum": self.policy.gate.min_coverage_percent,
                    },
                )
            )
        if test_failures > self.policy.gate.max_test_failures:
            violations.append(
                GateViolation(
                    code="TEST_FAILURE_LIMIT_EXCEEDED",
                    message=(
                        f"Test failures {test_failures} exceed allowed maximum "
                        f"{self.policy.gate.max_test_failures}"
                    ),
                    details={
                        "actual": test_failures,
                        "maximum": self.policy.gate.max_test_failures,
                    },
                )
            )
        test_required = (
            "test" in self.policy.gate.required_categories
            or "junit" in self.policy.gate.required_scanners
        )
        if test_required and test_count < self.policy.gate.minimum_test_count:
            violations.append(
                GateViolation(
                    code="TEST_COUNT_BELOW_MINIMUM",
                    message=(
                        f"Executed test count {test_count} is below required minimum "
                        f"{self.policy.gate.minimum_test_count}"
                    ),
                    details={
                        "actual": test_count,
                        "minimum": self.policy.gate.minimum_test_count,
                    },
                )
            )
        return coverage, test_failures
