"""Immutable policy models and compatible loading entry points."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .models import Severity


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
        from .config import load_policy

        return load_policy(path, policy_type=cls)

    def _validate(self) -> None:
        from .policy_validation import validate_policy

        validate_policy(self)
