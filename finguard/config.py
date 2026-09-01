"""Strict TOML policy and exception loading."""

from __future__ import annotations

import datetime as dt
import math
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .models import Severity


def _required(mapping: Mapping[str, Any], key: str, context: str) -> Any:
    if key not in mapping:
        raise ConfigurationError(f"{context}.{key} is required")
    return mapping[key]


def _string_tuple(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"{context} must be an array of strings")
    normalized = tuple(item.strip() for item in value)
    if any(not item for item in normalized):
        raise ConfigurationError(f"{context} cannot contain empty strings")
    if len(set(normalized)) != len(normalized):
        raise ConfigurationError(f"{context} cannot contain duplicates")
    return normalized


def _string_mapping(value: object, context: str) -> Mapping[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise ConfigurationError(f"{context} must be a string-to-string TOML table")
    return dict(value)


def _exit_code_mapping(value: object, context: str) -> Mapping[str, tuple[int, ...]]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{context} must be a TOML table")
    result: dict[str, tuple[int, ...]] = {}
    for scanner, codes in value.items():
        if not isinstance(scanner, str) or not scanner.strip():
            raise ConfigurationError(f"{context} scanner names must be non-empty strings")
        if not isinstance(codes, list) or not codes:
            raise ConfigurationError(f"{context}.{scanner} must be a non-empty integer array")
        if any(
            isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255
            for code in codes
        ):
            raise ConfigurationError(
                f"{context}.{scanner} values must be integers between 0 and 255"
            )
        if len(set(codes)) != len(codes):
            raise ConfigurationError(f"{context}.{scanner} contains duplicate exit codes")
        result[scanner] = tuple(codes)
    return result


def _digest_tuple_mapping(value: object, context: str) -> Mapping[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{context} must be a TOML table")
    result: dict[str, tuple[str, ...]] = {}
    for scanner, digests in value.items():
        if not isinstance(scanner, str) or not scanner.strip():
            raise ConfigurationError(f"{context} scanner names must be non-empty strings")
        normalized = _string_tuple(digests, f"{context}.{scanner}")
        if any(
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest.casefold())
            for digest in normalized
        ):
            raise ConfigurationError(f"{context}.{scanner} must contain SHA-256 digests")
        result[scanner] = tuple(digest.casefold() for digest in normalized)
    return result


def _boolean(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{context} must be a boolean")
    return value


def _integer(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{context} must be an integer")
    return value


def _number(value: object, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{context} must be a number")
    try:
        result = float(value)
    except OverflowError as exc:
        raise ConfigurationError(f"{context} must be finite") from exc
    if not math.isfinite(result):
        raise ConfigurationError(f"{context} must be finite")
    return result


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{context} must be a non-empty string")
    return value


def _known_keys(mapping: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ConfigurationError(f"{context} contains unknown keys: {', '.join(unknown)}")


def _representable_hours(value: float, context: str) -> None:
    try:
        dt.timedelta(hours=value)
    except OverflowError as exc:
        raise ConfigurationError(f"{context} exceeds the supported duration") from exc


def _representable_days(value: int, context: str) -> None:
    try:
        dt.timedelta(days=value)
    except OverflowError as exc:
        raise ConfigurationError(f"{context} exceeds the supported duration") from exc


@dataclass(frozen=True)
class GatePolicy:
    required_categories: tuple[str, ...]
    required_scanners: tuple[str, ...]
    block_severities: tuple[Severity, ...]
    max_findings: Mapping[Severity, int]
    min_coverage_percent: float
    max_test_failures: int
    minimum_test_count: int
    fail_on_scanner_error: bool
    fail_on_unknown_severity: bool
    require_fixes_for_blocking_vulnerabilities: bool
    minimum_sbom_components: int


@dataclass(frozen=True)
class LicensePolicy:
    allowed: tuple[str, ...]
    denied: tuple[str, ...]
    review_required: tuple[str, ...]
    allow_unknown: bool


@dataclass(frozen=True)
class ChangePolicy:
    required: bool
    allowed_types: tuple[str, ...]
    minimum_approvals: int
    require_rollback_plan: bool
    require_separation_of_duties: bool
    require_deployment_window: bool
    maximum_deployment_window_hours: float
    maximum_evidence_age_hours: float
    approval_roles: tuple[str, ...]
    require_approval_after_build: bool
    require_approval_attestation: bool
    allowed_approval_issuers: tuple[str, ...]
    allowed_approval_key_ids: tuple[str, ...]
    allowed_approval_signature_methods: tuple[str, ...]


@dataclass(frozen=True)
class ProvenancePolicy:
    require_release_subject: bool
    require_scan_attestations: bool
    require_signed_attestations: bool
    max_report_age_hours: float
    clock_skew_minutes: int
    artifact_bound_categories: tuple[str, ...]
    allowed_runner_ids: tuple[str, ...]
    allowed_key_ids: tuple[str, ...]
    ruleset_sha256: Mapping[str, str]
    require_database_for_scanners: tuple[str, ...]
    allowed_exit_codes: Mapping[str, tuple[int, ...]]
    allowed_command_sha256: Mapping[str, tuple[str, ...]]
    max_database_age_hours: float


@dataclass(frozen=True)
class ExceptionPolicy:
    allowed_categories: tuple[str, ...]
    non_exceptionable_severities: tuple[Severity, ...]
    max_validity_days: int
    max_renewals: int
    min_reason_length: int
    require_compensating_controls: bool
    require_scope: bool


@dataclass(frozen=True)
class VexPolicy:
    accepted_states: tuple[str, ...]
    require_justification: bool
    minimum_detail_length: int
    require_signed_attestation: bool
    allowed_issuers: tuple[str, ...]
    allowed_key_ids: tuple[str, ...]
    allowed_signature_methods: tuple[str, ...]
    max_validity_days: int
    non_suppressible_severities: tuple[Severity, ...]


@dataclass(frozen=True)
class Policy:
    policy_id: str
    version: str
    name: str
    owner: str
    gate: GatePolicy
    licenses: LicensePolicy
    change: ChangePolicy
    provenance: ProvenancePolicy
    exceptions: ExceptionPolicy
    vex: VexPolicy
    source_path: Path

    @classmethod
    def load(cls, path: Path) -> Policy:
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
            raise ConfigurationError(
                "gates.block_severities contains duplicate normalized severities"
            )

        maximums: dict[Severity, int] = {}
        max_raw = gates.get("max_findings", {})
        if not isinstance(max_raw, dict):
            raise ConfigurationError("gates.max_findings must be a TOML table")
        for name, value in max_raw.items():
            severity = Severity.parse(name)
            if severity is Severity.UNKNOWN and str(name).lower() != "unknown":
                raise ConfigurationError(f"invalid severity in gates.max_findings: {name}")
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ConfigurationError(
                    f"gates.max_findings.{name} must be a non-negative integer"
                )
            if severity in maximums:
                raise ConfigurationError(
                    "gates.max_findings contains duplicate normalized severities"
                )
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

        policy = cls(
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
                allow_unknown=_boolean(
                    licenses.get("allow_unknown", False), "licenses.allow_unknown"
                ),
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
                approval_roles=_string_tuple(
                    change.get("approval_roles", []), "change.approval_roles"
                ),
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
                allowed_issuers=_string_tuple(
                    vex.get("allowed_issuers", []), "vex.allowed_issuers"
                ),
                allowed_key_ids=_string_tuple(
                    vex.get("allowed_key_ids", []), "vex.allowed_key_ids"
                ),
                allowed_signature_methods=_string_tuple(
                    vex.get("allowed_signature_methods", ["hmac-sha256", "cosign"]),
                    "vex.allowed_signature_methods",
                ),
                max_validity_days=_integer(
                    vex.get("max_validity_days", 30), "vex.max_validity_days"
                ),
                non_suppressible_severities=non_suppressible,
            ),
            source_path=path.resolve(),
        )
        policy._validate()
        return policy

    def _validate(self) -> None:
        if not self.policy_id.strip() or not self.version.strip():
            raise ConfigurationError("metadata.id and metadata.version cannot be empty")
        if not 0 <= self.gate.min_coverage_percent <= 100:
            raise ConfigurationError("gates.min_coverage_percent must be between 0 and 100")
        if self.gate.max_test_failures < 0:
            raise ConfigurationError("gates.max_test_failures cannot be negative")
        if self.gate.minimum_test_count < 0:
            raise ConfigurationError("gates.minimum_test_count cannot be negative")
        if self.gate.minimum_sbom_components < 0:
            raise ConfigurationError("gates.minimum_sbom_components cannot be negative")
        if self.change.minimum_approvals < 0:
            raise ConfigurationError("change.minimum_approvals cannot be negative")
        if len({role.casefold() for role in self.change.approval_roles}) != len(
            self.change.approval_roles
        ):
            raise ConfigurationError("change.approval_roles contains duplicate normalized roles")
        if self.change.maximum_deployment_window_hours <= 0:
            raise ConfigurationError("change.maximum_deployment_window_hours must be positive")
        _representable_hours(
            self.change.maximum_deployment_window_hours,
            "change.maximum_deployment_window_hours",
        )
        if self.change.maximum_evidence_age_hours <= 0:
            raise ConfigurationError("change.maximum_evidence_age_hours must be positive")
        _representable_hours(
            self.change.maximum_evidence_age_hours,
            "change.maximum_evidence_age_hours",
        )
        if self.change.require_approval_attestation:
            if not self.change.required:
                raise ConfigurationError(
                    "change approval attestations cannot be required when "
                    "change control is optional"
                )
            if not self.change.allowed_approval_issuers:
                raise ConfigurationError(
                    "change.allowed_approval_issuers cannot be empty when "
                    "approval attestations are required"
                )
            if not self.change.allowed_approval_key_ids:
                raise ConfigurationError(
                    "change.allowed_approval_key_ids cannot be empty when "
                    "approval attestations are required"
                )
            if not self.change.allowed_approval_signature_methods:
                raise ConfigurationError(
                    "change.allowed_approval_signature_methods cannot be empty when "
                    "approval attestations are required"
                )
        unknown_approval_methods = set(self.change.allowed_approval_signature_methods) - {
            "hmac-sha256",
            "cosign",
        }
        if unknown_approval_methods:
            raise ConfigurationError(
                f"unsupported change approval signature methods: {sorted(unknown_approval_methods)}"
            )
        if self.provenance.max_report_age_hours <= 0:
            raise ConfigurationError("provenance.max_report_age_hours must be positive")
        _representable_hours(
            self.provenance.max_report_age_hours,
            "provenance.max_report_age_hours",
        )
        if self.provenance.max_database_age_hours <= 0:
            raise ConfigurationError("provenance.max_database_age_hours must be positive")
        _representable_hours(
            self.provenance.max_database_age_hours,
            "provenance.max_database_age_hours",
        )
        if not 0 <= self.provenance.clock_skew_minutes <= 60:
            raise ConfigurationError("provenance.clock_skew_minutes must be between 0 and 60")
        if (
            self.provenance.require_signed_attestations
            and not self.provenance.require_scan_attestations
        ):
            raise ConfigurationError(
                "signed scan attestations cannot be required when scan attestations are optional"
            )
        if self.provenance.require_signed_attestations:
            if not self.provenance.allowed_runner_ids:
                raise ConfigurationError(
                    "provenance.allowed_runner_ids cannot be empty for signed attestations"
                )
            if not self.provenance.allowed_key_ids:
                raise ConfigurationError(
                    "provenance.allowed_key_ids cannot be empty for signed attestations"
                )
        if self.provenance.require_scan_attestations:
            missing_rulesets = sorted(
                set(self.gate.required_scanners) - set(self.provenance.ruleset_sha256)
            )
            if missing_rulesets:
                raise ConfigurationError(
                    "provenance.ruleset_sha256 is missing required scanners: "
                    + ", ".join(missing_rulesets)
                )
            missing_exit_codes = sorted(
                set(self.gate.required_scanners) - set(self.provenance.allowed_exit_codes)
            )
            if missing_exit_codes:
                raise ConfigurationError(
                    "provenance.allowed_exit_codes is missing required scanners: "
                    + ", ".join(missing_exit_codes)
                )
            missing_commands = sorted(
                set(self.gate.required_scanners) - set(self.provenance.allowed_command_sha256)
            )
            if missing_commands:
                raise ConfigurationError(
                    "provenance.allowed_command_sha256 is missing required scanners: "
                    + ", ".join(missing_commands)
                )
        for scanner, digest in self.provenance.ruleset_sha256.items():
            if (
                not scanner.strip()
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest.casefold())
            ):
                raise ConfigurationError(
                    "provenance.ruleset_sha256 must map scanner names to SHA-256 digests"
                )
        if self.exceptions.max_validity_days <= 0:
            raise ConfigurationError("exception_controls.max_validity_days must be positive")
        _representable_days(
            self.exceptions.max_validity_days,
            "exception_controls.max_validity_days",
        )
        if self.exceptions.max_renewals < 0:
            raise ConfigurationError("exception_controls.max_renewals cannot be negative")
        if self.exceptions.min_reason_length < 1:
            raise ConfigurationError("exception_controls.min_reason_length must be positive")
        if self.vex.minimum_detail_length < 0:
            raise ConfigurationError("vex.minimum_detail_length cannot be negative")
        if self.vex.max_validity_days <= 0:
            raise ConfigurationError("vex.max_validity_days must be positive")
        _representable_days(self.vex.max_validity_days, "vex.max_validity_days")
        known_vex_states = {
            "resolved",
            "resolved_with_pedigree",
            "exploitable",
            "in_triage",
            "false_positive",
            "not_affected",
        }
        unknown_vex_states = set(self.vex.accepted_states) - known_vex_states
        if unknown_vex_states:
            raise ConfigurationError(
                f"unsupported accepted VEX states: {sorted(unknown_vex_states)}"
            )
        if self.vex.require_signed_attestation:
            if not self.vex.allowed_issuers:
                raise ConfigurationError(
                    "vex.allowed_issuers cannot be empty for signed VEX attestations"
                )
            if not self.vex.allowed_key_ids:
                raise ConfigurationError(
                    "vex.allowed_key_ids cannot be empty for signed VEX attestations"
                )
            if not self.vex.allowed_signature_methods:
                raise ConfigurationError(
                    "vex.allowed_signature_methods cannot be empty for signed VEX attestations"
                )
        unknown_vex_methods = set(self.vex.allowed_signature_methods) - {
            "hmac-sha256",
            "cosign",
        }
        if unknown_vex_methods:
            raise ConfigurationError(
                f"unsupported VEX signature methods: {sorted(unknown_vex_methods)}"
            )
        license_groups = {
            "allowed": {item.casefold() for item in self.licenses.allowed},
            "denied": {item.casefold() for item in self.licenses.denied},
            "review_required": {item.casefold() for item in self.licenses.review_required},
        }
        for name, values in license_groups.items():
            source = getattr(self.licenses, name)
            if len(values) != len(source):
                raise ConfigurationError(
                    f"licenses.{name} contains duplicate normalized identifiers"
                )
        overlap = (
            (license_groups["allowed"] & license_groups["denied"])
            | (license_groups["allowed"] & license_groups["review_required"])
            | (license_groups["denied"] & license_groups["review_required"])
        )
        if overlap:
            raise ConfigurationError(
                f"licenses cannot appear in multiple dispositions: {sorted(overlap)}"
            )


@dataclass(frozen=True)
class PolicyException:
    exception_id: str
    fingerprint: str
    reason: str
    owner: str
    approver: str
    expires_at: dt.datetime
    ticket: str
    created_at: dt.datetime | None = None
    category: str = ""
    severity: str = ""
    service: str = ""
    environment: str = ""
    policy_id: str = ""
    policy_version: str = ""
    compensating_controls: str = ""
    renewal_count: int = 0
    revoked: bool = False

    @property
    def is_expired(self) -> bool:
        now = dt.datetime.now(dt.UTC)
        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=dt.UTC)
        return expiry <= now


def load_exceptions(path: Path | None) -> list[PolicyException]:
    if path is None:
        return []
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"cannot load exceptions {path}: {exc}") from exc

    entries = raw.get("exceptions", [])
    _known_keys(raw, {"exceptions"}, "exception document")
    if not isinstance(entries, list):
        raise ConfigurationError("exceptions must be an array of TOML tables")
    result: list[PolicyException] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        context = f"exceptions[{index}]"
        if not isinstance(entry, dict):
            raise ConfigurationError(f"{context} must be a TOML table")
        _known_keys(
            entry,
            {
                "id",
                "fingerprint",
                "reason",
                "owner",
                "approver",
                "created_at",
                "expires_at",
                "ticket",
                "category",
                "severity",
                "service",
                "environment",
                "policy_id",
                "policy_version",
                "compensating_controls",
                "renewal_count",
                "revoked",
            },
            context,
        )
        exception_id = _text(_required(entry, "id", context), f"{context}.id")
        if exception_id in seen:
            raise ConfigurationError(f"duplicate exception id: {exception_id}")
        seen.add(exception_id)
        expires = entry.get("expires_at")
        if isinstance(expires, dt.date) and not isinstance(expires, dt.datetime):
            expires = dt.datetime.combine(expires, dt.time.max, tzinfo=dt.UTC)
        if not isinstance(expires, dt.datetime):
            raise ConfigurationError(f"{context}.expires_at must be a TOML date or datetime")
        if expires.tzinfo is None or expires.utcoffset() is None:
            raise ConfigurationError(f"{context}.expires_at must include a timezone")
        created = entry.get("created_at")
        if isinstance(created, dt.date) and not isinstance(created, dt.datetime):
            created = dt.datetime.combine(created, dt.time.min, tzinfo=dt.UTC)
        if created is not None and not isinstance(created, dt.datetime):
            raise ConfigurationError(f"{context}.created_at must be a TOML date or datetime")
        if isinstance(created, dt.datetime) and (
            created.tzinfo is None or created.utcoffset() is None
        ):
            raise ConfigurationError(f"{context}.created_at must include a timezone")
        fingerprint = _text(
            _required(entry, "fingerprint", context), f"{context}.fingerprint"
        ).lower()
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ConfigurationError(f"{context}.fingerprint must be 64 hexadecimal characters")
        renewal_count = entry.get("renewal_count", 0)
        if (
            isinstance(renewal_count, bool)
            or not isinstance(renewal_count, int)
            or renewal_count < 0
        ):
            raise ConfigurationError(f"{context}.renewal_count must be a non-negative integer")
        if created is not None:
            created_utc = _as_utc(created)
            expires_utc = _as_utc(expires)
            if created_utc >= expires_utc:
                raise ConfigurationError(f"{context}.created_at must be earlier than expires_at")
        result.append(
            PolicyException(
                exception_id=exception_id,
                fingerprint=fingerprint,
                reason=_text(_required(entry, "reason", context), f"{context}.reason"),
                owner=_text(_required(entry, "owner", context), f"{context}.owner"),
                approver=_text(_required(entry, "approver", context), f"{context}.approver"),
                expires_at=expires,
                ticket=_text(_required(entry, "ticket", context), f"{context}.ticket"),
                created_at=created,
                category=str(entry.get("category", "")),
                severity=str(entry.get("severity", "")),
                service=str(entry.get("service", "")),
                environment=str(entry.get("environment", "")),
                policy_id=str(entry.get("policy_id", "")),
                policy_version=str(entry.get("policy_version", "")),
                compensating_controls=str(entry.get("compensating_controls", "")),
                renewal_count=renewal_count,
                revoked=_boolean(entry.get("revoked", False), f"{context}.revoked"),
            )
        )
    return result


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC)
