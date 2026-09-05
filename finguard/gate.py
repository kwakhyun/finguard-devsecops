"""Deterministic policy-as-code quality gate."""

from __future__ import annotations

import datetime as dt
from collections import Counter
from collections.abc import Iterable
from dataclasses import replace

from .approvals import ApprovalAttestation
from .change import ChangeRequest
from .checks.change import ChangeChecks
from .checks.common import _is_inventory
from .checks.provenance import ProvenanceChecks
from .checks.quality import QualityChecks
from .checks.suppression import SuppressionChecks
from .models import (
    Decision,
    Finding,
    GateResult,
    GateViolation,
    ScanResult,
    Severity,
)
from .policy_exceptions import PolicyException
from .policy_types import Policy
from .release import ReleaseSubject
from .vex import VexAttestation


class PolicyEngine:
    """Orchestrate checks and assemble one deterministic policy decision."""

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
        quality_checks = QualityChecks(self.policy)
        provenance_checks = ProvenanceChecks(self.policy)
        change_checks = ChangeChecks(self.policy)
        suppression_checks = SuppressionChecks(self.policy)
        scan_results = list(scans)
        violations: list[GateViolation] = []

        quality_checks.check_required_scans(scan_results, violations)
        quality_checks.check_sbom_completeness(scan_results, violations)
        provenance_checks.check_release_subject(
            change, release_subject, expected_commit, violations
        )
        provenance_checks.check_scan_provenance(
            scan_results,
            release_subject,
            expected_commit,
            evaluated_at,
            violations,
        )
        findings = self._deduplicate(scan_results)
        inventory = [finding for finding in findings if _is_inventory(finding)]
        issues = [finding for finding in findings if not _is_inventory(finding)]
        issues, vexed = suppression_checks.apply_vex(
            issues,
            vex_attestation,
            release_subject,
            evaluated_at,
            violations,
        )
        active, excepted = suppression_checks.apply_exceptions(
            issues,
            list(exceptions),
            release_subject,
            evaluated_at,
            violations,
        )
        severity_counts = Counter(finding.severity for finding in active)
        quality_checks.check_severities(active, severity_counts, violations)
        quality_checks.check_licenses(inventory, violations)
        coverage, test_failures = quality_checks.check_test_metrics(scan_results, violations)
        change_checks.check_change(change, expected_commit, evaluated_at, violations)
        change_checks.check_approval_attestation(
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
