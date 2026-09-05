"""Release subject and scanner provenance checks."""

from __future__ import annotations

import datetime as dt

from ..change import ChangeRequest
from ..models import (
    GateViolation,
    ScanResult,
)
from ..policy_types import Policy
from ..release import ReleaseSubject, commit_matches
from .common import (
    _parse_timestamp,
)


class ProvenanceChecks:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def check_release_subject(
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

    def check_scan_provenance(
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
