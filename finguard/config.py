"""Strict TOML policy and exception loading."""

from __future__ import annotations

import tomllib
from pathlib import Path

from .config_fields import (
    _boolean,
    _digest_tuple_mapping,
    _exit_code_mapping,
    _integer,
    _known_keys,
    _number,
    _required,
    _string_mapping,
    _string_tuple,
    _text,
)
from .errors import ConfigurationError
from .models import Severity
from .policy_exceptions import PolicyException as PolicyException
from .policy_exceptions import load_exceptions as load_exceptions
from .policy_types import ChangePolicy as ChangePolicy
from .policy_types import ExceptionPolicy as ExceptionPolicy
from .policy_types import GatePolicy as GatePolicy
from .policy_types import LicensePolicy as LicensePolicy
from .policy_types import Policy as Policy
from .policy_types import ProvenancePolicy as ProvenancePolicy
from .policy_types import VexPolicy as VexPolicy


def load_policy(path: Path, *, policy_type: type[Policy] = Policy) -> Policy:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"cannot load policy {path}: {exc}") from exc

    metadata = raw.get("metadata", {})
    gates = raw.get("gates", {})
    licenses = raw.get("licenses", {})
    change = raw.get("change", {})
    provenance = raw.get("provenance", {})
    exception_controls = raw.get("exception_controls", {})
    vex = raw.get("vex", {})
    if not all(
        isinstance(item, dict)
        for item in (
            metadata,
            gates,
            licenses,
            change,
            provenance,
            exception_controls,
            vex,
        )
    ):
        raise ConfigurationError("policy sections must be TOML tables")

    _known_keys(
        raw,
        {
            "metadata",
            "gates",
            "licenses",
            "change",
            "provenance",
            "exception_controls",
            "vex",
        },
        "policy",
    )
    _known_keys(metadata, {"id", "version", "name", "owner"}, "metadata")
    _known_keys(
        gates,
        {
            "required_categories",
            "required_scanners",
            "block_severities",
            "min_coverage_percent",
            "max_test_failures",
            "minimum_test_count",
            "fail_on_scanner_error",
            "fail_on_unknown_severity",
            "require_fixes_for_blocking_vulnerabilities",
            "minimum_sbom_components",
            "max_findings",
        },
        "gates",
    )
    _known_keys(licenses, {"allowed", "denied", "review_required", "allow_unknown"}, "licenses")
    _known_keys(
        change,
        {
            "required",
            "allowed_types",
            "minimum_approvals",
            "require_rollback_plan",
            "require_separation_of_duties",
            "require_deployment_window",
            "maximum_deployment_window_hours",
            "maximum_evidence_age_hours",
            "approval_roles",
            "require_approval_after_build",
            "require_approval_attestation",
            "allowed_approval_issuers",
            "allowed_approval_key_ids",
            "allowed_approval_signature_methods",
        },
        "change",
    )
    _known_keys(
        provenance,
        {
            "require_release_subject",
            "require_scan_attestations",
            "require_signed_attestations",
            "max_report_age_hours",
            "clock_skew_minutes",
            "artifact_bound_categories",
            "allowed_runner_ids",
            "allowed_key_ids",
            "ruleset_sha256",
            "require_database_for_scanners",
            "allowed_exit_codes",
            "allowed_command_sha256",
            "max_database_age_hours",
        },
        "provenance",
    )
    _known_keys(
        exception_controls,
        {
            "allowed_categories",
            "non_exceptionable_severities",
            "max_validity_days",
            "max_renewals",
            "min_reason_length",
            "require_compensating_controls",
            "require_scope",
        },
        "exception_controls",
    )
    _known_keys(
        vex,
        {
            "accepted_states",
            "require_justification",
            "minimum_detail_length",
            "require_signed_attestation",
            "allowed_issuers",
            "allowed_key_ids",
            "allowed_signature_methods",
            "max_validity_days",
            "non_suppressible_severities",
        },
        "vex",
    )

    block_names = _string_tuple(
        _required(gates, "block_severities", "gates"), "gates.block_severities"
    )
    block_severities = tuple(Severity.parse(name) for name in block_names)
    if Severity.UNKNOWN in block_severities and "unknown" not in {
        name.lower() for name in block_names
    }:
        raise ConfigurationError("gates.block_severities contains an invalid severity")
    if len(set(block_severities)) != len(block_severities):
        raise ConfigurationError("gates.block_severities contains duplicate normalized severities")

    maximums: dict[Severity, int] = {}
    max_raw = gates.get("max_findings", {})
    if not isinstance(max_raw, dict):
        raise ConfigurationError("gates.max_findings must be a TOML table")
    for name, value in max_raw.items():
        severity = Severity.parse(name)
        if severity is Severity.UNKNOWN and str(name).lower() != "unknown":
            raise ConfigurationError(f"invalid severity in gates.max_findings: {name}")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ConfigurationError(f"gates.max_findings.{name} must be a non-negative integer")
        if severity in maximums:
            raise ConfigurationError("gates.max_findings contains duplicate normalized severities")
        maximums[severity] = value

    non_exceptionable_names = _string_tuple(
        exception_controls.get("non_exceptionable_severities", ["critical"]),
        "exception_controls.non_exceptionable_severities",
    )
    non_exceptionable = tuple(Severity.parse(name) for name in non_exceptionable_names)
    if Severity.UNKNOWN in non_exceptionable and "unknown" not in {
        name.casefold() for name in non_exceptionable_names
    }:
        raise ConfigurationError(
            "exception_controls.non_exceptionable_severities contains an invalid severity"
        )
    if len(set(non_exceptionable)) != len(non_exceptionable):
        raise ConfigurationError(
            "exception_controls.non_exceptionable_severities contains duplicate "
            "normalized severities"
        )
    non_suppressible_names = _string_tuple(
        vex.get("non_suppressible_severities", ["critical"]),
        "vex.non_suppressible_severities",
    )
    non_suppressible = tuple(Severity.parse(name) for name in non_suppressible_names)
    if Severity.UNKNOWN in non_suppressible and "unknown" not in {
        name.casefold() for name in non_suppressible_names
    }:
        raise ConfigurationError("vex.non_suppressible_severities contains an invalid severity")
    if len(set(non_suppressible)) != len(non_suppressible):
        raise ConfigurationError(
            "vex.non_suppressible_severities contains duplicate normalized severities"
        )

    policy = policy_type(
        policy_id=_text(_required(metadata, "id", "metadata"), "metadata.id"),
        version=_text(_required(metadata, "version", "metadata"), "metadata.version"),
        name=_text(_required(metadata, "name", "metadata"), "metadata.name"),
        owner=_text(_required(metadata, "owner", "metadata"), "metadata.owner"),
        gate=GatePolicy(
            required_categories=_string_tuple(
                _required(gates, "required_categories", "gates"),
                "gates.required_categories",
            ),
            required_scanners=_string_tuple(
                gates.get("required_scanners", []), "gates.required_scanners"
            ),
            block_severities=block_severities,
            max_findings=maximums,
            min_coverage_percent=_number(
                gates.get("min_coverage_percent", 0), "gates.min_coverage_percent"
            ),
            max_test_failures=_integer(
                gates.get("max_test_failures", 0), "gates.max_test_failures"
            ),
            minimum_test_count=_integer(
                gates.get("minimum_test_count", 1), "gates.minimum_test_count"
            ),
            fail_on_scanner_error=_boolean(
                gates.get("fail_on_scanner_error", True), "gates.fail_on_scanner_error"
            ),
            fail_on_unknown_severity=_boolean(
                gates.get("fail_on_unknown_severity", True),
                "gates.fail_on_unknown_severity",
            ),
            require_fixes_for_blocking_vulnerabilities=_boolean(
                gates.get("require_fixes_for_blocking_vulnerabilities", False),
                "gates.require_fixes_for_blocking_vulnerabilities",
            ),
            minimum_sbom_components=_integer(
                gates.get("minimum_sbom_components", 0),
                "gates.minimum_sbom_components",
            ),
        ),
        licenses=LicensePolicy(
            allowed=_string_tuple(licenses.get("allowed", []), "licenses.allowed"),
            denied=_string_tuple(licenses.get("denied", []), "licenses.denied"),
            review_required=_string_tuple(
                licenses.get("review_required", []), "licenses.review_required"
            ),
            allow_unknown=_boolean(licenses.get("allow_unknown", False), "licenses.allow_unknown"),
        ),
        change=ChangePolicy(
            required=_boolean(change.get("required", True), "change.required"),
            allowed_types=_string_tuple(
                change.get("allowed_types", ["CB", "SR"]), "change.allowed_types"
            ),
            minimum_approvals=_integer(
                change.get("minimum_approvals", 2), "change.minimum_approvals"
            ),
            require_rollback_plan=_boolean(
                change.get("require_rollback_plan", True), "change.require_rollback_plan"
            ),
            require_separation_of_duties=_boolean(
                change.get("require_separation_of_duties", True),
                "change.require_separation_of_duties",
            ),
            require_deployment_window=_boolean(
                change.get("require_deployment_window", True),
                "change.require_deployment_window",
            ),
            maximum_deployment_window_hours=_number(
                change.get("maximum_deployment_window_hours", 24),
                "change.maximum_deployment_window_hours",
            ),
            maximum_evidence_age_hours=_number(
                change.get("maximum_evidence_age_hours", 24),
                "change.maximum_evidence_age_hours",
            ),
            approval_roles=_string_tuple(change.get("approval_roles", []), "change.approval_roles"),
            require_approval_after_build=_boolean(
                change.get("require_approval_after_build", True),
                "change.require_approval_after_build",
            ),
            require_approval_attestation=_boolean(
                change.get("require_approval_attestation", False),
                "change.require_approval_attestation",
            ),
            allowed_approval_issuers=_string_tuple(
                change.get("allowed_approval_issuers", []),
                "change.allowed_approval_issuers",
            ),
            allowed_approval_key_ids=_string_tuple(
                change.get("allowed_approval_key_ids", []),
                "change.allowed_approval_key_ids",
            ),
            allowed_approval_signature_methods=_string_tuple(
                change.get(
                    "allowed_approval_signature_methods",
                    ["hmac-sha256", "cosign"],
                ),
                "change.allowed_approval_signature_methods",
            ),
        ),
        provenance=ProvenancePolicy(
            require_release_subject=_boolean(
                provenance.get("require_release_subject", False),
                "provenance.require_release_subject",
            ),
            require_scan_attestations=_boolean(
                provenance.get("require_scan_attestations", False),
                "provenance.require_scan_attestations",
            ),
            require_signed_attestations=_boolean(
                provenance.get("require_signed_attestations", False),
                "provenance.require_signed_attestations",
            ),
            max_report_age_hours=_number(
                provenance.get("max_report_age_hours", 24),
                "provenance.max_report_age_hours",
            ),
            clock_skew_minutes=_integer(
                provenance.get("clock_skew_minutes", 5),
                "provenance.clock_skew_minutes",
            ),
            artifact_bound_categories=_string_tuple(
                provenance.get("artifact_bound_categories", ["sca", "dast"]),
                "provenance.artifact_bound_categories",
            ),
            allowed_runner_ids=_string_tuple(
                provenance.get("allowed_runner_ids", []),
                "provenance.allowed_runner_ids",
            ),
            allowed_key_ids=_string_tuple(
                provenance.get("allowed_key_ids", []),
                "provenance.allowed_key_ids",
            ),
            ruleset_sha256=_string_mapping(
                provenance.get("ruleset_sha256", {}),
                "provenance.ruleset_sha256",
            ),
            require_database_for_scanners=_string_tuple(
                provenance.get("require_database_for_scanners", []),
                "provenance.require_database_for_scanners",
            ),
            allowed_exit_codes=_exit_code_mapping(
                provenance.get("allowed_exit_codes", {}),
                "provenance.allowed_exit_codes",
            ),
            allowed_command_sha256=_digest_tuple_mapping(
                provenance.get("allowed_command_sha256", {}),
                "provenance.allowed_command_sha256",
            ),
            max_database_age_hours=_number(
                provenance.get("max_database_age_hours", 72),
                "provenance.max_database_age_hours",
            ),
        ),
        exceptions=ExceptionPolicy(
            allowed_categories=_string_tuple(
                exception_controls.get(
                    "allowed_categories", ["lint", "sast", "sca", "dast", "iac"]
                ),
                "exception_controls.allowed_categories",
            ),
            non_exceptionable_severities=non_exceptionable,
            max_validity_days=_integer(
                exception_controls.get("max_validity_days", 30),
                "exception_controls.max_validity_days",
            ),
            max_renewals=_integer(
                exception_controls.get("max_renewals", 0),
                "exception_controls.max_renewals",
            ),
            min_reason_length=_integer(
                exception_controls.get("min_reason_length", 20),
                "exception_controls.min_reason_length",
            ),
            require_compensating_controls=_boolean(
                exception_controls.get("require_compensating_controls", True),
                "exception_controls.require_compensating_controls",
            ),
            require_scope=_boolean(
                exception_controls.get("require_scope", True),
                "exception_controls.require_scope",
            ),
        ),
        vex=VexPolicy(
            accepted_states=_string_tuple(
                vex.get(
                    "accepted_states",
                    ["not_affected", "false_positive", "resolved"],
                ),
                "vex.accepted_states",
            ),
            require_justification=_boolean(
                vex.get("require_justification", True), "vex.require_justification"
            ),
            minimum_detail_length=_integer(
                vex.get("minimum_detail_length", 20), "vex.minimum_detail_length"
            ),
            require_signed_attestation=_boolean(
                vex.get("require_signed_attestation", True),
                "vex.require_signed_attestation",
            ),
            allowed_issuers=_string_tuple(vex.get("allowed_issuers", []), "vex.allowed_issuers"),
            allowed_key_ids=_string_tuple(vex.get("allowed_key_ids", []), "vex.allowed_key_ids"),
            allowed_signature_methods=_string_tuple(
                vex.get("allowed_signature_methods", ["hmac-sha256", "cosign"]),
                "vex.allowed_signature_methods",
            ),
            max_validity_days=_integer(vex.get("max_validity_days", 30), "vex.max_validity_days"),
            non_suppressible_severities=non_suppressible,
        ),
        source_path=path.resolve(),
    )
    policy._validate()
    return policy
