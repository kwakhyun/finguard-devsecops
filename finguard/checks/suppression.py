"""Scoped exception and VEX evaluation."""

from __future__ import annotations

import datetime as dt

from ..models import (
    Finding,
    GateViolation,
)
from ..policy_exceptions import PolicyException
from ..policy_types import Policy
from ..release import ReleaseSubject
from ..vex import KNOWN_STATES, VexAttestation
from .common import (
    _as_utc,
)


class SuppressionChecks:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def apply_exceptions(
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
                rejection = self.exception_rejection(exception, finding, release_subject, now)
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

    def apply_vex(
        self,
        findings: list[Finding],
        attestation: VexAttestation | None,
        release_subject: ReleaseSubject | None,
        now: dt.datetime,
        violations: list[GateViolation],
    ) -> tuple[list[Finding], list[Finding]]:
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
        if not self.check_vex_attestation(attestation, release_subject, now, violations):
            return findings, []

        by_fingerprint = {finding.fingerprint: finding for finding in findings}
        suppressed: set[str] = set()
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
            if statement.fingerprint not in suppressed:
                suppressed.add(statement.fingerprint)
                vexed.append(matched_finding)
        return [item for item in findings if item.fingerprint not in suppressed], vexed

    def check_vex_attestation(
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

    def exception_rejection(
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
