"""Policy value ranges and cross-control consistency checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .config_fields import (
    _representable_days,
    _representable_hours,
)
from .errors import ConfigurationError

if TYPE_CHECKING:
    from .policy_types import Policy


def validate_policy(policy: Policy) -> None:
    if not policy.policy_id.strip() or not policy.version.strip():
        raise ConfigurationError("metadata.id and metadata.version cannot be empty")
    if not 0 <= policy.gate.min_coverage_percent <= 100:
        raise ConfigurationError("gates.min_coverage_percent must be between 0 and 100")
    if policy.gate.max_test_failures < 0:
        raise ConfigurationError("gates.max_test_failures cannot be negative")
    if policy.gate.minimum_test_count < 0:
        raise ConfigurationError("gates.minimum_test_count cannot be negative")
    if policy.gate.minimum_sbom_components < 0:
        raise ConfigurationError("gates.minimum_sbom_components cannot be negative")
    if policy.change.minimum_approvals < 0:
        raise ConfigurationError("change.minimum_approvals cannot be negative")
    if len({role.casefold() for role in policy.change.approval_roles}) != len(
        policy.change.approval_roles
    ):
        raise ConfigurationError("change.approval_roles contains duplicate normalized roles")
    if policy.change.maximum_deployment_window_hours <= 0:
        raise ConfigurationError("change.maximum_deployment_window_hours must be positive")
    _representable_hours(
        policy.change.maximum_deployment_window_hours,
        "change.maximum_deployment_window_hours",
    )
    if policy.change.maximum_evidence_age_hours <= 0:
        raise ConfigurationError("change.maximum_evidence_age_hours must be positive")
    _representable_hours(
        policy.change.maximum_evidence_age_hours,
        "change.maximum_evidence_age_hours",
    )
    if policy.change.require_approval_attestation:
        if not policy.change.required:
            raise ConfigurationError(
                "change approval attestations cannot be required when change control is optional"
            )
        if not policy.change.allowed_approval_issuers:
            raise ConfigurationError(
                "change.allowed_approval_issuers cannot be empty when "
                "approval attestations are required"
            )
        if not policy.change.allowed_approval_key_ids:
            raise ConfigurationError(
                "change.allowed_approval_key_ids cannot be empty when "
                "approval attestations are required"
            )
        if not policy.change.allowed_approval_signature_methods:
            raise ConfigurationError(
                "change.allowed_approval_signature_methods cannot be empty when "
                "approval attestations are required"
            )
    unknown_approval_methods = set(policy.change.allowed_approval_signature_methods) - {
        "hmac-sha256",
        "cosign",
    }
    if unknown_approval_methods:
        raise ConfigurationError(
            f"unsupported change approval signature methods: {sorted(unknown_approval_methods)}"
        )
    if policy.provenance.max_report_age_hours <= 0:
        raise ConfigurationError("provenance.max_report_age_hours must be positive")
    _representable_hours(
        policy.provenance.max_report_age_hours,
        "provenance.max_report_age_hours",
    )
    if policy.provenance.max_database_age_hours <= 0:
        raise ConfigurationError("provenance.max_database_age_hours must be positive")
    _representable_hours(
        policy.provenance.max_database_age_hours,
        "provenance.max_database_age_hours",
    )
    if not 0 <= policy.provenance.clock_skew_minutes <= 60:
        raise ConfigurationError("provenance.clock_skew_minutes must be between 0 and 60")
    if (
        policy.provenance.require_signed_attestations
        and not policy.provenance.require_scan_attestations
    ):
        raise ConfigurationError(
            "signed scan attestations cannot be required when scan attestations are optional"
        )
    if policy.provenance.require_signed_attestations:
        if not policy.provenance.allowed_runner_ids:
            raise ConfigurationError(
                "provenance.allowed_runner_ids cannot be empty for signed attestations"
            )
        if not policy.provenance.allowed_key_ids:
            raise ConfigurationError(
                "provenance.allowed_key_ids cannot be empty for signed attestations"
            )
    if policy.provenance.require_scan_attestations:
        missing_rulesets = sorted(
            set(policy.gate.required_scanners) - set(policy.provenance.ruleset_sha256)
        )
        if missing_rulesets:
            raise ConfigurationError(
                "provenance.ruleset_sha256 is missing required scanners: "
                + ", ".join(missing_rulesets)
            )
        missing_exit_codes = sorted(
            set(policy.gate.required_scanners) - set(policy.provenance.allowed_exit_codes)
        )
        if missing_exit_codes:
            raise ConfigurationError(
                "provenance.allowed_exit_codes is missing required scanners: "
                + ", ".join(missing_exit_codes)
            )
        missing_commands = sorted(
            set(policy.gate.required_scanners) - set(policy.provenance.allowed_command_sha256)
        )
        if missing_commands:
            raise ConfigurationError(
                "provenance.allowed_command_sha256 is missing required scanners: "
                + ", ".join(missing_commands)
            )
    for scanner, digest in policy.provenance.ruleset_sha256.items():
        if (
            not scanner.strip()
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest.casefold())
        ):
            raise ConfigurationError(
                "provenance.ruleset_sha256 must map scanner names to SHA-256 digests"
            )
    if policy.exceptions.max_validity_days <= 0:
        raise ConfigurationError("exception_controls.max_validity_days must be positive")
    _representable_days(
        policy.exceptions.max_validity_days,
        "exception_controls.max_validity_days",
    )
    if policy.exceptions.max_renewals < 0:
        raise ConfigurationError("exception_controls.max_renewals cannot be negative")
    if policy.exceptions.min_reason_length < 1:
        raise ConfigurationError("exception_controls.min_reason_length must be positive")
    if policy.vex.minimum_detail_length < 0:
        raise ConfigurationError("vex.minimum_detail_length cannot be negative")
    if policy.vex.max_validity_days <= 0:
        raise ConfigurationError("vex.max_validity_days must be positive")
    _representable_days(policy.vex.max_validity_days, "vex.max_validity_days")
    known_vex_states = {
        "resolved",
        "resolved_with_pedigree",
        "exploitable",
        "in_triage",
        "false_positive",
        "not_affected",
    }
    unknown_vex_states = set(policy.vex.accepted_states) - known_vex_states
    if unknown_vex_states:
        raise ConfigurationError(f"unsupported accepted VEX states: {sorted(unknown_vex_states)}")
    if policy.vex.require_signed_attestation:
        if not policy.vex.allowed_issuers:
            raise ConfigurationError(
                "vex.allowed_issuers cannot be empty for signed VEX attestations"
            )
        if not policy.vex.allowed_key_ids:
            raise ConfigurationError(
                "vex.allowed_key_ids cannot be empty for signed VEX attestations"
            )
        if not policy.vex.allowed_signature_methods:
            raise ConfigurationError(
                "vex.allowed_signature_methods cannot be empty for signed VEX attestations"
            )
    unknown_vex_methods = set(policy.vex.allowed_signature_methods) - {
        "hmac-sha256",
        "cosign",
    }
    if unknown_vex_methods:
        raise ConfigurationError(
            f"unsupported VEX signature methods: {sorted(unknown_vex_methods)}"
        )
    license_groups = {
        "allowed": {item.casefold() for item in policy.licenses.allowed},
        "denied": {item.casefold() for item in policy.licenses.denied},
        "review_required": {item.casefold() for item in policy.licenses.review_required},
    }
    for name, values in license_groups.items():
        source = getattr(policy.licenses, name)
        if len(values) != len(source):
            raise ConfigurationError(f"licenses.{name} contains duplicate normalized identifiers")
    overlap = (
        (license_groups["allowed"] & license_groups["denied"])
        | (license_groups["allowed"] & license_groups["review_required"])
        | (license_groups["denied"] & license_groups["review_required"])
    )
    if overlap:
        raise ConfigurationError(
            f"licenses cannot appear in multiple dispositions: {sorted(overlap)}"
        )
