"""Change approvals, separation of duties, and signed approval checks."""

from __future__ import annotations

import datetime as dt

from ..approvals import ApprovalAttestation
from ..change import ChangeRequest
from ..models import (
    GateViolation,
)
from ..policy_types import Policy
from ..release import ReleaseSubject, commit_matches
from .common import (
    _approval_tuple,
    _as_utc,
    _roles_have_distinct_approvers,
)


class ChangeChecks:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def check_change(
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

    def check_approval_attestation(
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
