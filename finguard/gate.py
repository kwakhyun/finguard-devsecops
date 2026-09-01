"""Deterministic policy-as-code quality gate."""

from __future__ import annotations

import datetime as dt
import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import replace

from .approvals import ApprovalAttestation
from .change import Approval, ChangeRequest
from .config import Policy, PolicyException
from .licenses import LicenseDisposition, evaluate_spdx_expression
from .models import (
    Decision,
    Finding,
    GateResult,
    GateViolation,
    ScanResult,
    ScanStatus,
    Severity,
)
from .release import ReleaseSubject, commit_matches
from .vex import KNOWN_STATES, VexAttestation


class PolicyEngine:
    """Evaluate normalized scan evidence and change controls without side effects."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate(
        self,
        scans: Iterable[ScanResult],
        *,
        exceptions: Iterable[PolicyException] = (),
        change: ChangeRequest | None = None,
        release_subject: ReleaseSubject | None = None,
        approval_attestation: ApprovalAttestation | None = None,
        vex_attestation: VexAttestation | None = None,
        expected_commit: str = "",
        now: dt.datetime | None = None,
    ) -> GateResult:
        evaluated_at = now or dt.datetime.now(dt.UTC)
        if evaluated_at.tzinfo is None:
            evaluated_at = evaluated_at.replace(tzinfo=dt.UTC)
        else:
            evaluated_at = evaluated_at.astimezone(dt.UTC)
        scan_results = list(scans)
        violations: list[GateViolation] = []

        self._check_required_scans(scan_results, violations)
        self._check_sbom_completeness(scan_results, violations)
        self._check_release_subject(change, release_subject, expected_commit, violations)
        self._check_scan_provenance(
            scan_results,
            release_subject,
            expected_commit,
            evaluated_at,
            violations,
        )
        findings = self._deduplicate(scan_results)
        inventory = [finding for finding in findings if _is_inventory(finding)]
        issues = [finding for finding in findings if not _is_inventory(finding)]
        issues, vexed = self._apply_vex(
            issues,
            vex_attestation,
            release_subject,
            evaluated_at,
            violations,
        )
        active, excepted = self._apply_exceptions(
            issues,
            list(exceptions),
            release_subject,
            evaluated_at,
            violations,
        )
        severity_counts = Counter(finding.severity for finding in active)
        self._check_severities(active, severity_counts, violations)
        self._check_licenses(inventory, violations)
        coverage, test_failures = self._check_test_metrics(scan_results, violations)
        self._check_change(change, expected_commit, evaluated_at, violations)
        self._check_approval_attestation(
            change,
            release_subject,
            approval_attestation,
            evaluated_at,
            violations,
        )

        category_status: dict[str, list[str]] = {}
        for scan in scan_results:
            category_status.setdefault(scan.category, []).append(scan.status.value)
        metrics = {
            "scan_count": len(scan_results),
            "finding_count": len(findings),
            "issue_count": len(issues),
            "inventory_count": len(inventory),
            "vexed_finding_count": len(vexed),
            "active_finding_count": len(active),
            "excepted_finding_count": len(excepted),
            "severity_counts": {
                severity.label: severity_counts.get(severity, 0) for severity in Severity
            },
            "coverage_percent": coverage,
            "test_failures": test_failures,
            "approval_attestation_verified": bool(
                approval_attestation and approval_attestation.signature_verified
            ),
            "vex_attestation_verified": bool(
                vex_attestation and vex_attestation.signature_verified
            ),
            "category_status": category_status,
        }
        has_error = any(item.severity == "error" for item in violations)
        decision = Decision.FAIL if has_error else Decision.PASS
        return GateResult(
            decision=decision,
            policy_id=self.policy.policy_id,
            policy_version=self.policy.version,
            violations=violations,
            active_findings=active,
            excepted_findings=excepted,
            scan_results=scan_results,
            metrics=metrics,
            evaluated_at=evaluated_at.isoformat(),
            change_id=change.change_id if change else "",
            release_subject=release_subject,
            inventory=inventory,
            vexed_findings=vexed,
        )

    def _check_required_scans(
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

    def _check_sbom_completeness(
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

    @staticmethod
    def _deduplicate(scans: list[ScanResult]) -> list[Finding]:
        observations: dict[str, list[Finding]] = {}
        for scan in scans:
            for finding in scan.findings:
                observations.setdefault(finding.fingerprint, []).append(finding)
        unique: list[Finding] = []
        for items in observations.values():
            # UNKNOWN sorts after CRITICAL for fail-safe presentation, but it
            # must never replace a scanner's known severity during merging.
            # Otherwise a policy that explicitly tolerates unknown severities
            # could accidentally hide a known blocking observation.
            known = [item for item in items if item.severity is not Severity.UNKNOWN]
            winner = max(known or items, key=lambda item: int(item.severity))
            metadata = dict(winner.metadata)
            metadata["observed_by"] = sorted({item.scanner for item in items})
            metadata["observation_count"] = len(items)
            unique.append(replace(winner, metadata=metadata))
        return sorted(
            unique,
            key=lambda item: (-int(item.severity), item.category, item.rule_id, item.location),
        )

    def _apply_exceptions(
        self,
        findings: list[Finding],
        exceptions: list[PolicyException],
        release_subject: ReleaseSubject | None,
        now: dt.datetime,
        violations: list[GateViolation],
    ) -> tuple[list[Finding], list[Finding]]:
        by_fingerprint: dict[str, list[PolicyException]] = {}
        for exception in exceptions:
            by_fingerprint.setdefault(exception.fingerprint, []).append(exception)

        active: list[Finding] = []
        excepted: list[Finding] = []
        reported_exception_issues: set[str] = set()
        for finding in findings:
            candidates = by_fingerprint.get(finding.fingerprint, [])
            accepted = False
            for exception in candidates:
                rejection = self._exception_rejection(exception, finding, release_subject, now)
                if rejection is not None:
                    code, message, details = rejection
                    key = f"{code}:{exception.exception_id}"
                    if key not in reported_exception_issues:
                        violations.append(
                            GateViolation(code=code, message=message, details=details)
                        )
                        reported_exception_issues.add(key)
                    continue
                accepted = True
                break
            (excepted if accepted else active).append(finding)
        return active, excepted

    def _apply_vex(
        self,
        findings: list[Finding],
        attestation: VexAttestation | None,
        release_subject: ReleaseSubject | None,
        now: dt.datetime,
        violations: list[GateViolation],
    ) -> tuple[list[Finding], list[Finding]]:
        by_fingerprint = {finding.fingerprint: finding for finding in findings}
        for finding in findings:
            reported_state = str(finding.metadata.get("reported_vex_state", "")).casefold()
            if reported_state and reported_state not in KNOWN_STATES:
                violations.append(
                    GateViolation(
                        code="VEX_STATE_INVALID",
                        message=f"Scanner reported an unknown VEX state: {reported_state}",
                        details={"fingerprint": finding.fingerprint},
                    )
                )
            elif reported_state in self.policy.vex.accepted_states and attestation is None:
                violations.append(
                    GateViolation(
                        code="VEX_ATTESTATION_MISSING",
                        message=(
                            "Scanner-reported VEX cannot suppress a finding without signed review"
                        ),
                        details={"fingerprint": finding.fingerprint},
                    )
                )

        if attestation is None:
            return findings, []
        if not self._check_vex_attestation(attestation, release_subject, now, violations):
            return findings, []

        active = list(findings)
        vexed: list[Finding] = []
        for statement in attestation.statements:
            matched_finding = by_fingerprint.get(statement.fingerprint)
            if matched_finding is None:
                violations.append(
                    GateViolation(
                        code="VEX_FINDING_NOT_FOUND",
                        message="Signed VEX statement does not match an observed finding",
                        details={"fingerprint": statement.fingerprint},
                    )
                )
                continue
            if statement.state not in self.policy.vex.accepted_states:
                continue
            if matched_finding.severity in self.policy.vex.non_suppressible_severities:
                violations.append(
                    GateViolation(
                        code="VEX_SEVERITY_NOT_SUPPRESSIBLE",
                        message="Policy does not allow VEX to suppress this severity",
                        details={
                            "fingerprint": matched_finding.fingerprint,
                            "severity": matched_finding.severity.label,
                        },
                    )
                )
                continue
            if self.policy.vex.require_justification and (
                not statement.justification
                or len(statement.detail) < self.policy.vex.minimum_detail_length
            ):
                violations.append(
                    GateViolation(
                        code="VEX_JUSTIFICATION_INSUFFICIENT",
                        message="Accepted VEX state requires justification and review detail",
                        details={
                            "fingerprint": matched_finding.fingerprint,
                            "state": statement.state,
                        },
                    )
                )
                continue
            active.remove(matched_finding)
            vexed.append(matched_finding)
        return active, vexed

    def _check_vex_attestation(
        self,
        attestation: VexAttestation,
        release_subject: ReleaseSubject | None,
        now: dt.datetime,
        violations: list[GateViolation],
    ) -> bool:
        valid = True

        def reject(code: str, message: str, details: dict[str, object] | None = None) -> None:
            nonlocal valid
            valid = False
            violations.append(GateViolation(code=code, message=message, details=details or {}))

        if self.policy.vex.require_signed_attestation and not attestation.signature_verified:
            reject("VEX_ATTESTATION_UNTRUSTED", "VEX review signature was not verified")
        if (
            self.policy.vex.allowed_signature_methods
            and attestation.signature_method not in self.policy.vex.allowed_signature_methods
        ):
            reject("VEX_SIGNATURE_METHOD_NOT_ALLOWED", "VEX signature method is not allowed")
        if (
            self.policy.vex.allowed_issuers
            and attestation.issuer not in self.policy.vex.allowed_issuers
        ):
            reject("VEX_ISSUER_UNTRUSTED", "VEX review issuer is not allowed")
        if (
            self.policy.vex.allowed_key_ids
            and attestation.key_id not in self.policy.vex.allowed_key_ids
        ):
            reject("VEX_SIGNER_UNTRUSTED", "VEX review signing key is not allowed")
        if release_subject is None or attestation.release_subject_sha256 != release_subject.digest:
            reject("VEX_SUBJECT_MISMATCH", "VEX review does not match the release subject")
        issued = _as_utc(attestation.issued_at)
        expires = _as_utc(attestation.expires_at)
        skew = dt.timedelta(minutes=self.policy.provenance.clock_skew_minutes)
        if issued > now + skew or expires <= now or expires <= issued:
            reject("VEX_TIME_INVALID", "VEX review is expired or has an invalid time range")
        if expires - issued > dt.timedelta(days=self.policy.vex.max_validity_days):
            reject("VEX_VALIDITY_EXCEEDED", "VEX review validity exceeds policy")
        return valid

    def _exception_rejection(
        self,
        exception: PolicyException,
        finding: Finding,
        release_subject: ReleaseSubject | None,
        now: dt.datetime,
    ) -> tuple[str, str, dict[str, object]] | None:
        common: dict[str, object] = {
            "exception_id": exception.exception_id,
            "ticket": exception.ticket,
        }
        expiry = _as_utc(exception.expires_at)
        if exception.revoked:
            return (
                "EXCEPTION_REVOKED",
                f"Policy exception has been revoked: {exception.exception_id}",
                common,
            )
        if expiry <= now:
            return (
                "EXCEPTION_EXPIRED",
                f"Policy exception has expired: {exception.exception_id}",
                {**common, "expires_at": expiry.isoformat()},
            )
        if exception.owner.casefold() == exception.approver.casefold():
            return (
                "EXCEPTION_SELF_APPROVED",
                f"Policy exception violates separation of duties: {exception.exception_id}",
                common,
            )
        if (
            finding.category not in self.policy.exceptions.allowed_categories
            or finding.severity in self.policy.exceptions.non_exceptionable_severities
        ):
            return (
                "EXCEPTION_NOT_ALLOWED",
                f"Finding cannot be excepted by policy: {exception.exception_id}",
                {
                    **common,
                    "category": finding.category,
                    "severity": finding.severity.label,
                },
            )
        if len(exception.reason.strip()) < self.policy.exceptions.min_reason_length:
            return (
                "EXCEPTION_REASON_INSUFFICIENT",
                f"Policy exception reason is too short: {exception.exception_id}",
                common,
            )
        if (
            self.policy.exceptions.require_compensating_controls
            and len(exception.compensating_controls.strip()) < 20
        ):
            return (
                "EXCEPTION_CONTROL_MISSING",
                f"Policy exception lacks compensating controls: {exception.exception_id}",
                common,
            )
        if exception.renewal_count > self.policy.exceptions.max_renewals:
            return (
                "EXCEPTION_RENEWAL_LIMIT",
                f"Policy exception exceeds its renewal limit: {exception.exception_id}",
                {**common, "renewal_count": exception.renewal_count},
            )
        if exception.created_at is None:
            if self.policy.exceptions.require_scope:
                return (
                    "EXCEPTION_SCOPE_INCOMPLETE",
                    f"Policy exception is missing created_at: {exception.exception_id}",
                    common,
                )
        else:
            created = _as_utc(exception.created_at)
            skew = dt.timedelta(minutes=self.policy.provenance.clock_skew_minutes)
            if created > now + skew:
                return (
                    "EXCEPTION_TIME_INVALID",
                    f"Policy exception is not active yet: {exception.exception_id}",
                    {**common, "created_at": created.isoformat()},
                )
            if expiry - created > dt.timedelta(days=self.policy.exceptions.max_validity_days):
                return (
                    "EXCEPTION_VALIDITY_EXCEEDED",
                    f"Policy exception exceeds maximum validity: {exception.exception_id}",
                    {
                        **common,
                        "max_validity_days": self.policy.exceptions.max_validity_days,
                    },
                )
        if self.policy.exceptions.require_scope:
            expected_scope = {
                "category": finding.category,
                "severity": finding.severity.label,
                "policy_id": self.policy.policy_id,
                "policy_version": self.policy.version,
            }
            actual_scope = {
                "category": exception.category,
                "severity": exception.severity.casefold(),
                "policy_id": exception.policy_id,
                "policy_version": exception.policy_version,
                "service": exception.service,
                "environment": exception.environment,
            }
            if release_subject is not None:
                expected_scope.update(
                    {
                        "service": release_subject.service,
                        "environment": release_subject.environment,
                    }
                )
            mismatches = [
                name
                for name, expected in expected_scope.items()
                if not actual_scope[name] or actual_scope[name] != expected
            ]
            if mismatches:
                return (
                    "EXCEPTION_SCOPE_MISMATCH",
                    f"Policy exception scope does not match: {exception.exception_id}",
                    {**common, "fields": mismatches},
                )
        return None

    def _check_severities(
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

    def _check_licenses(self, findings: list[Finding], violations: list[GateViolation]) -> None:
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

    def _check_test_metrics(
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

    def _check_release_subject(
        self,
        change: ChangeRequest | None,
        release_subject: ReleaseSubject | None,
        expected_commit: str,
        violations: list[GateViolation],
    ) -> None:
        if release_subject is None:
            if self.policy.provenance.require_release_subject:
                violations.append(
                    GateViolation(
                        code="RELEASE_SUBJECT_MISSING",
                        message="An immutable release subject is required",
                    )
                )
            return
        if expected_commit and not commit_matches(release_subject.commit_sha, expected_commit):
            violations.append(
                GateViolation(
                    code="RELEASE_COMMIT_MISMATCH",
                    message="Release subject commit does not match the pipeline commit",
                    details={
                        "subject": release_subject.commit_sha,
                        "pipeline": expected_commit,
                    },
                )
            )
        if change is None:
            if self.policy.change.required:
                violations.append(
                    GateViolation(
                        code="RELEASE_APPROVAL_SUBJECT_MISSING",
                        message="Release subject cannot be verified without a change request",
                    )
                )
            return
        approved = change.release_subject
        if approved is None:
            violations.append(
                GateViolation(
                    code="RELEASE_APPROVAL_SUBJECT_MISSING",
                    message="Change request does not bind an approved release subject",
                )
            )
        elif approved.digest != release_subject.digest:
            violations.append(
                GateViolation(
                    code="RELEASE_SUBJECT_MISMATCH",
                    message="Runtime release subject differs from the approved change subject",
                    details={
                        "approved_sha256": approved.digest,
                        "runtime_sha256": release_subject.digest,
                    },
                )
            )

    def _check_scan_provenance(
        self,
        scans: list[ScanResult],
        release_subject: ReleaseSubject | None,
        expected_commit: str,
        now: dt.datetime,
        violations: list[GateViolation],
    ) -> None:
        expected_source = release_subject.commit_sha if release_subject else expected_commit
        for scan in scans:
            if release_subject and scan.scanner == "cyclonedx":
                if scan.input_sha256 != release_subject.sbom_sha256:
                    violations.append(
                        GateViolation(
                            code="SBOM_SUBJECT_MISMATCH",
                            message="CycloneDX report does not match the approved SBOM digest",
                            details={
                                "report": scan.input_sha256,
                                "approved": release_subject.sbom_sha256,
                            },
                        )
                    )
            provenance = scan.provenance
            if provenance is None:
                if self.policy.provenance.require_scan_attestations:
                    violations.append(
                        GateViolation(
                            code="SCAN_ATTESTATION_MISSING",
                            message=f"Scan report has no attestation: {scan.scanner}",
                            details={"scanner": scan.scanner, "source": scan.source},
                        )
                    )
                continue
            mismatches: list[str] = []
            if provenance.report_sha256 != scan.input_sha256:
                mismatches.append("report_sha256")
            if provenance.scanner != scan.scanner:
                mismatches.append("scanner")
            if provenance.category != scan.category:
                mismatches.append("category")
            if expected_source and not commit_matches(provenance.source_commit, expected_source):
                mismatches.append("source_commit")
            if (
                release_subject
                and scan.category in self.policy.provenance.artifact_bound_categories
                and provenance.image_digest != release_subject.image_digest
            ):
                mismatches.append("image_digest")
            if scan.category == "dast":
                targets = scan.metrics.get("targets", [])
                if (
                    not provenance.target_uri
                    or not isinstance(targets, list)
                    or targets != [provenance.target_uri]
                ):
                    mismatches.append("target_uri")
            if mismatches:
                violations.append(
                    GateViolation(
                        code="SCAN_ATTESTATION_SUBJECT_MISMATCH",
                        message=(
                            f"Scan attestation does not match its report subject: {scan.scanner}"
                        ),
                        details={"scanner": scan.scanner, "fields": mismatches},
                    )
                )
            if not provenance.complete:
                violations.append(
                    GateViolation(
                        code="SCAN_ATTESTATION_INCOMPLETE",
                        message=f"Scanner execution is marked incomplete: {scan.scanner}",
                    )
                )
            allowed_exit_codes = self.policy.provenance.allowed_exit_codes.get(scan.scanner)
            if allowed_exit_codes is not None and provenance.exit_code not in allowed_exit_codes:
                violations.append(
                    GateViolation(
                        code="SCAN_EXIT_CODE_UNACCEPTABLE",
                        message=f"Scanner exit code is not accepted by policy: {scan.scanner}",
                        details={
                            "scanner": scan.scanner,
                            "actual": provenance.exit_code,
                            "allowed": list(allowed_exit_codes),
                        },
                    )
                )
            allowed_commands = self.policy.provenance.allowed_command_sha256.get(scan.scanner)
            if allowed_commands is not None and provenance.command_sha256 not in allowed_commands:
                violations.append(
                    GateViolation(
                        code="SCAN_COMMAND_UNTRUSTED",
                        message=f"Scanner command is not approved by policy: {scan.scanner}",
                        details={"scanner": scan.scanner},
                    )
                )
            if (
                self.policy.provenance.require_signed_attestations
                and not provenance.signature_verified
            ):
                violations.append(
                    GateViolation(
                        code="SCAN_ATTESTATION_UNTRUSTED",
                        message=f"Scan attestation signature is not verified: {scan.scanner}",
                        details={"key_id": provenance.key_id},
                    )
                )
            if (
                self.policy.provenance.allowed_runner_ids
                and provenance.runner_id not in self.policy.provenance.allowed_runner_ids
            ):
                violations.append(
                    GateViolation(
                        code="SCAN_RUNNER_UNTRUSTED",
                        message=f"Scan was produced by an untrusted runner: {scan.scanner}",
                        details={"runner_id": provenance.runner_id},
                    )
                )
            if (
                self.policy.provenance.allowed_key_ids
                and provenance.key_id not in self.policy.provenance.allowed_key_ids
            ):
                violations.append(
                    GateViolation(
                        code="SCAN_SIGNER_UNTRUSTED",
                        message=f"Scan was signed by an untrusted key: {scan.scanner}",
                        details={"key_id": provenance.key_id},
                    )
                )
            expected_ruleset = self.policy.provenance.ruleset_sha256.get(scan.scanner)
            if expected_ruleset and provenance.ruleset_sha256 != expected_ruleset.casefold():
                violations.append(
                    GateViolation(
                        code="SCAN_RULESET_UNTRUSTED",
                        message=f"Scanner ruleset hash is not approved: {scan.scanner}",
                        details={"scanner": scan.scanner},
                    )
                )
            if (
                scan.scanner in self.policy.provenance.require_database_for_scanners
                and not provenance.database_sha256
            ):
                violations.append(
                    GateViolation(
                        code="SCAN_DATABASE_PROVENANCE_MISSING",
                        message=f"Scanner database metadata is missing: {scan.scanner}",
                        details={"scanner": scan.scanner},
                    )
                )
            if scan.scanner in self.policy.provenance.require_database_for_scanners:
                try:
                    database_updated = _parse_timestamp(provenance.database_updated_at)
                except ValueError:
                    violations.append(
                        GateViolation(
                            code="SCAN_DATABASE_TIME_INVALID",
                            message=(
                                "Scanner database update time is missing or invalid: "
                                f"{scan.scanner}"
                            ),
                            details={"scanner": scan.scanner},
                        )
                    )
                else:
                    database_skew = dt.timedelta(minutes=self.policy.provenance.clock_skew_minutes)
                    if database_updated > now + database_skew:
                        violations.append(
                            GateViolation(
                                code="SCAN_DATABASE_TIME_INVALID",
                                message=(
                                    f"Scanner database update time is in the future: {scan.scanner}"
                                ),
                                details={"scanner": scan.scanner},
                            )
                        )
                    elif now - database_updated > dt.timedelta(
                        hours=self.policy.provenance.max_database_age_hours
                    ):
                        violations.append(
                            GateViolation(
                                code="SCAN_DATABASE_STALE",
                                message=f"Scanner vulnerability database is stale: {scan.scanner}",
                                details={
                                    "scanner": scan.scanner,
                                    "updated_at": database_updated.isoformat(),
                                },
                            )
                        )
            try:
                started = _parse_timestamp(provenance.started_at)
                finished = _parse_timestamp(provenance.finished_at)
            except ValueError:
                violations.append(
                    GateViolation(
                        code="SCAN_ATTESTATION_TIME_INVALID",
                        message=f"Scan attestation has an invalid timestamp: {scan.scanner}",
                    )
                )
                continue
            skew = dt.timedelta(minutes=self.policy.provenance.clock_skew_minutes)
            if started > finished or finished > now + skew:
                violations.append(
                    GateViolation(
                        code="SCAN_ATTESTATION_TIME_INVALID",
                        message=f"Scan attestation time ordering is invalid: {scan.scanner}",
                    )
                )
            elif now - finished > dt.timedelta(hours=self.policy.provenance.max_report_age_hours):
                violations.append(
                    GateViolation(
                        code="SCAN_ATTESTATION_STALE",
                        message=f"Scan report is older than the allowed window: {scan.scanner}",
                        details={"finished_at": finished.isoformat()},
                    )
                )

    def _check_change(
        self,
        change: ChangeRequest | None,
        expected_commit: str,
        now: dt.datetime,
        violations: list[GateViolation],
    ) -> None:
        if change is None:
            if self.policy.change.required:
                violations.append(
                    GateViolation(
                        code="CHANGE_REQUEST_MISSING",
                        message="A CB or SR change-control manifest is required",
                    )
                )
            return
        if change.request_type not in self.policy.change.allowed_types:
            violations.append(
                GateViolation(
                    code="CHANGE_TYPE_NOT_ALLOWED",
                    message=f"Change type is not allowed: {change.request_type}",
                )
            )
        if expected_commit and not commit_matches(change.commit_sha, expected_commit):
            violations.append(
                GateViolation(
                    code="COMMIT_MISMATCH",
                    message="Change request commit does not match the pipeline commit",
                    details={"manifest": change.commit_sha, "pipeline": expected_commit},
                )
            )
        if self.policy.change.require_rollback_plan and len(change.rollback_plan) < 20:
            violations.append(
                GateViolation(
                    code="ROLLBACK_PLAN_INSUFFICIENT",
                    message="Rollback plan is missing or too short to be actionable",
                )
            )
        if self.policy.change.require_deployment_window and (
            change.window_start is None or change.window_end is None
        ):
            violations.append(
                GateViolation(
                    code="DEPLOYMENT_WINDOW_MISSING",
                    message="An approved deployment window is required",
                )
            )
        if change.window_start is not None and change.window_end is not None:
            window_start = _as_utc(change.window_start)
            window_end = _as_utc(change.window_end)
            maximum_window = dt.timedelta(hours=self.policy.change.maximum_deployment_window_hours)
            if window_end - window_start > maximum_window:
                violations.append(
                    GateViolation(
                        code="DEPLOYMENT_WINDOW_TOO_LONG",
                        message="Approved deployment window exceeds the policy maximum",
                        details={
                            "actual_hours": (window_end - window_start).total_seconds() / 3600,
                            "maximum_hours": self.policy.change.maximum_deployment_window_hours,
                        },
                    )
                )
            if now > window_end:
                violations.append(
                    GateViolation(
                        code="DEPLOYMENT_WINDOW_EXPIRED",
                        message="Approved deployment window has already expired",
                        details={"window_end": window_end.isoformat()},
                    )
                )

        unique_approvers = {approval.approver.casefold() for approval in change.approvals}
        if len(unique_approvers) < self.policy.change.minimum_approvals:
            violations.append(
                GateViolation(
                    code="APPROVALS_INSUFFICIENT",
                    message=(
                        f"Change has {len(unique_approvers)} distinct approval(s); "
                        f"{self.policy.change.minimum_approvals} required"
                    ),
                )
            )
        actual_roles = {approval.role.casefold() for approval in change.approvals}
        missing_roles = [
            role
            for role in self.policy.change.approval_roles
            if role.casefold() not in actual_roles
        ]
        if missing_roles:
            violations.append(
                GateViolation(
                    code="APPROVAL_ROLE_MISSING",
                    message=f"Required approval roles are missing: {', '.join(missing_roles)}",
                    details={"missing_roles": missing_roles},
                )
            )
        elif self.policy.change.approval_roles and not _roles_have_distinct_approvers(
            change.approvals, self.policy.change.approval_roles
        ):
            violations.append(
                GateViolation(
                    code="APPROVAL_ROLE_SEPARATION_VIOLATION",
                    message="Each required approval role must be held by a different approver",
                    details={"required_roles": list(self.policy.change.approval_roles)},
                )
            )
        future_approvals = [
            approval.approver
            for approval in change.approvals
            if _as_utc(approval.approved_at) > now
        ]
        if future_approvals:
            violations.append(
                GateViolation(
                    code="APPROVAL_TIME_INVALID",
                    message="One or more approvals are dated in the future",
                    details={"approvers": future_approvals},
                )
            )
        if self.policy.change.require_approval_after_build and change.release_subject is not None:
            built_at = change.release_subject.built_at
            prebuild_approvals = [
                approval.approver
                for approval in change.approvals
                if _as_utc(approval.approved_at) < built_at
            ]
            if prebuild_approvals:
                violations.append(
                    GateViolation(
                        code="APPROVAL_PRECEDES_BUILD",
                        message="Release approvals must refer to the final built artifact",
                        details={"approvers": prebuild_approvals},
                    )
                )
        if self.policy.change.require_separation_of_duties:
            requester = change.requester.casefold()
            deployer = change.deployer.casefold()
            conflicts: list[str] = []
            if requester == deployer:
                conflicts.append("requester equals deployer")
            for approval in change.approvals:
                identity = approval.approver.casefold()
                if identity in {requester, deployer}:
                    conflicts.append(f"approver {approval.approver} has an execution role")
            if conflicts:
                violations.append(
                    GateViolation(
                        code="SEPARATION_OF_DUTIES_VIOLATION",
                        message="Change roles are not sufficiently separated",
                        details={"conflicts": conflicts},
                    )
                )

    def _check_approval_attestation(
        self,
        change: ChangeRequest | None,
        release_subject: ReleaseSubject | None,
        attestation: ApprovalAttestation | None,
        now: dt.datetime,
        violations: list[GateViolation],
    ) -> None:
        if attestation is None:
            if self.policy.change.require_approval_attestation:
                violations.append(
                    GateViolation(
                        code="APPROVAL_ATTESTATION_MISSING",
                        message="Signed external change approval evidence is required",
                    )
                )
            return

        if not attestation.signature_verified:
            violations.append(
                GateViolation(
                    code="APPROVAL_ATTESTATION_UNTRUSTED",
                    message="External change approval signature was not verified",
                    details={"key_id": attestation.key_id},
                )
            )
        if (
            self.policy.change.allowed_approval_signature_methods
            and attestation.signature_method
            not in self.policy.change.allowed_approval_signature_methods
        ):
            violations.append(
                GateViolation(
                    code="APPROVAL_SIGNATURE_METHOD_NOT_ALLOWED",
                    message="External approval used a signature method not allowed by policy",
                    details={"signature_method": attestation.signature_method},
                )
            )
        if (
            self.policy.change.allowed_approval_issuers
            and attestation.issuer not in self.policy.change.allowed_approval_issuers
        ):
            violations.append(
                GateViolation(
                    code="APPROVAL_ISSUER_UNTRUSTED",
                    message="External change approval was issued by an untrusted authority",
                    details={"issuer": attestation.issuer},
                )
            )
        if (
            self.policy.change.allowed_approval_key_ids
            and attestation.key_id not in self.policy.change.allowed_approval_key_ids
        ):
            violations.append(
                GateViolation(
                    code="APPROVAL_SIGNER_UNTRUSTED",
                    message="External change approval used an untrusted signing key",
                    details={"key_id": attestation.key_id},
                )
            )

        mismatches: list[str] = []
        if change is None:
            mismatches.append("change")
        else:
            if attestation.change_id != change.change_id:
                mismatches.append("change_id")
            if attestation.change_request_sha256 != change.digest:
                mismatches.append("change_request_sha256")
            expected_approvals = sorted(_approval_tuple(item) for item in change.approvals)
            actual_approvals = sorted(_approval_tuple(item) for item in attestation.approvals)
            if actual_approvals != expected_approvals:
                mismatches.append("approvals")
            approved_subject = change.release_subject
            if (
                approved_subject is None
                or attestation.release_subject_sha256 != approved_subject.digest
            ):
                mismatches.append("change_release_subject")
        if release_subject is None or attestation.release_subject_sha256 != release_subject.digest:
            mismatches.append("runtime_release_subject")
        if mismatches:
            violations.append(
                GateViolation(
                    code="APPROVAL_ATTESTATION_SUBJECT_MISMATCH",
                    message="External approval evidence does not match the requested release",
                    details={"fields": sorted(set(mismatches))},
                )
            )

        earliest_issue_time: dt.datetime | None = None
        if change is not None and change.approvals:
            earliest_issue_time = max(_as_utc(item.approved_at) for item in change.approvals)
        if release_subject is not None:
            built_at = _as_utc(release_subject.built_at)
            earliest_issue_time = (
                max(earliest_issue_time, built_at) if earliest_issue_time else built_at
            )
        skew = dt.timedelta(minutes=self.policy.provenance.clock_skew_minutes)
        if (
            earliest_issue_time is not None and attestation.issued_at < earliest_issue_time
        ) or attestation.issued_at > now + skew:
            violations.append(
                GateViolation(
                    code="APPROVAL_ATTESTATION_TIME_INVALID",
                    message="External approval evidence has an invalid issuance time",
                    details={
                        "issued_at": attestation.issued_at.isoformat(),
                        "not_before": (
                            earliest_issue_time.isoformat() if earliest_issue_time else ""
                        ),
                    },
                )
            )


def _is_inventory(finding: Finding) -> bool:
    return finding.category == "license" or finding.metadata.get("kind") == "dependency_license"


def _parse_timestamp(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(dt.UTC)


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC)


def _roles_have_distinct_approvers(
    approvals: Iterable[Approval], required_roles: Iterable[str]
) -> bool:
    candidates: dict[str, set[str]] = {
        role.casefold(): {
            approval.approver.casefold()
            for approval in approvals
            if approval.role.casefold() == role.casefold()
        }
        for role in required_roles
    }
    identity_to_role: dict[str, str] = {}

    def assign(role: str, visited: set[str]) -> bool:
        for identity in sorted(candidates[role]):
            if identity in visited:
                continue
            visited.add(identity)
            previous = identity_to_role.get(identity)
            if previous is None or assign(previous, visited):
                identity_to_role[identity] = role
                return True
        return False

    return all(assign(role, set()) for role in candidates)


def _approval_tuple(approval: Approval) -> tuple[str, str, str]:
    return (
        approval.approver.casefold(),
        approval.role.casefold(),
        _as_utc(approval.approved_at).isoformat(),
    )
