"""Normalized domain model shared by every scanner adapter and policy gate."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any

from .errors import EvidenceVerificationError
from .release import ReleaseSubject
from .safeio import atomic_write_text
from .urls import canonical_http_url

_FULL_GIT_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class Severity(IntEnum):
    """Scanner-independent severity ordered from informational to critical."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    UNKNOWN = 5

    @classmethod
    def parse(cls, value: object, *, default: Severity | None = None) -> Severity:
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().upper()
        aliases = {
            "INFORMATIONAL": cls.INFO,
            "INFORMATION": cls.INFO,
            "NOTE": cls.INFO,
            "WARN": cls.MEDIUM,
            "WARNING": cls.MEDIUM,
            "ERROR": cls.HIGH,
            "MODERATE": cls.MEDIUM,
            "IMPORTANT": cls.HIGH,
            "0": cls.INFO,
            "1": cls.LOW,
            "2": cls.MEDIUM,
            "3": cls.HIGH,
            "4": cls.CRITICAL,
        }
        if text in cls.__members__:
            return cls[text]
        if text in aliases:
            return aliases[text]
        if default is not None:
            return default
        return cls.UNKNOWN

    @property
    def label(self) -> str:
        return self.name.lower()


class ScanStatus(StrEnum):
    PASSED = "passed"
    FINDINGS = "findings"
    ERROR = "error"
    SKIPPED = "skipped"


class Decision(StrEnum):
    PASS = "pass"  # noqa: S105 - policy decision, not a credential
    FAIL = "fail"


@dataclass(frozen=True)
class Finding:
    """One normalized issue with a stable, exception-safe fingerprint."""

    scanner: str
    category: str
    rule_id: str
    severity: Severity
    message: str
    location: str = ""
    component: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    license_id: str = ""
    cwe: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        # Message text is deliberately excluded: scanner wording changes must not
        # invalidate a previously reviewed exception for the same issue location.
        category = self.category.casefold()
        aliases = self.metadata.get("aliases", [])
        if not isinstance(aliases, (list, tuple)):
            aliases = []
        identifiers = sorted(
            {
                self.rule_id.casefold(),
                *(str(item).casefold() for item in aliases if str(item).strip()),
            }
        )
        canonical_rule = next(
            (item for item in identifiers if item.startswith("cve-")),
            identifiers[0] if identifiers else "unknown",
        )
        identity: dict[str, str] = {
            "category": category,
            "rule_id": canonical_rule,
            "component": self.component.casefold(),
        }
        if category == "license" or self.metadata.get("kind") == "dependency_license":
            identity["license_id"] = self.license_id.casefold()
            identity["installed_version"] = self.installed_version.casefold()
        elif category == "sca":
            identity["installed_version"] = self.installed_version.casefold()
        else:
            # Preserve path case because Linux workspaces can contain both
            # ``src/Foo.py`` and ``src/foo.py``. Collapsing those locations can
            # under-count findings against a policy maximum.
            identity["location"] = self.location.replace("\\", "/")
        if category == "dast":
            identity["method"] = str(self.metadata.get("method", "")).casefold()
            identity["parameter"] = str(self.metadata.get("parameter", "")).casefold()
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "scanner": self.scanner,
            "category": self.category,
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "message": self.message,
            "location": self.location,
            "component": self.component,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "license_id": self.license_id,
            "cwe": list(self.cwe),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Finding:
        if not isinstance(data, Mapping):
            raise ValueError("normalized finding must be an object")
        allowed = {
            "fingerprint",
            "scanner",
            "category",
            "rule_id",
            "severity",
            "message",
            "location",
            "component",
            "installed_version",
            "fixed_version",
            "license_id",
            "cwe",
            "metadata",
        }
        _reject_unknown_keys(data, allowed, "normalized finding")
        severity = data.get("severity")
        if not isinstance(severity, str):
            raise ValueError("normalized finding severity must be a string")
        cwe = data.get("cwe", [])
        if not isinstance(cwe, list) or not all(isinstance(item, str) for item in cwe):
            raise ValueError("normalized finding cwe must be an array of strings")
        metadata = data.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ValueError("normalized finding metadata must be an object")
        finding = cls(
            scanner=_required_model_text(data, "scanner", "normalized finding"),
            category=_required_model_text(data, "category", "normalized finding"),
            rule_id=_required_model_text(data, "rule_id", "normalized finding"),
            severity=Severity.parse(severity),
            message=_optional_model_text(data, "message", "normalized finding"),
            location=_optional_model_text(data, "location", "normalized finding"),
            component=_optional_model_text(data, "component", "normalized finding"),
            installed_version=_optional_model_text(data, "installed_version", "normalized finding"),
            fixed_version=_optional_model_text(data, "fixed_version", "normalized finding"),
            license_id=_optional_model_text(data, "license_id", "normalized finding"),
            cwe=tuple(cwe),
            metadata=dict(metadata),
        )
        supplied_fingerprint = data.get("fingerprint")
        if supplied_fingerprint is not None and (
            not isinstance(supplied_fingerprint, str)
            or not hmac.compare_digest(
                supplied_fingerprint.casefold(), finding.fingerprint.casefold()
            )
        ):
            raise ValueError("normalized finding fingerprint does not match its content")
        return finding


@dataclass(frozen=True)
class ScanProvenance:
    """Verified metadata binding a scanner execution to a report and release subject."""

    predicate_type: str
    report_sha256: str
    scanner: str
    category: str
    scanner_version: str
    scanner_uri: str
    source_commit: str
    image_digest: str
    ruleset_sha256: str
    database_sha256: str
    database_updated_at: str
    command_sha256: str
    ci_job_id: str
    runner_id: str
    exit_code: int
    target_uri: str
    started_at: str
    finished_at: str
    complete: bool
    signature_present: bool = False
    signature_verified: bool = False
    key_id: str = ""

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        signature_present: bool | None = None,
        signature_verified: bool | None = None,
    ) -> ScanProvenance:
        provenance = cls(
            predicate_type=str(data.get("predicate_type", "")),
            report_sha256=str(data.get("report_sha256", "")).lower(),
            scanner=str(data.get("scanner", "")),
            category=str(data.get("category", "")),
            scanner_version=str(data.get("scanner_version", "")),
            scanner_uri=str(data.get("scanner_uri", "")),
            source_commit=str(data.get("source_commit", "")).lower(),
            image_digest=str(data.get("image_digest", "")).lower(),
            ruleset_sha256=str(data.get("ruleset_sha256", "")).lower(),
            database_sha256=str(data.get("database_sha256", "")).lower(),
            database_updated_at=str(data.get("database_updated_at", "")),
            command_sha256=str(data.get("command_sha256", "")).lower(),
            ci_job_id=str(data.get("ci_job_id", "")),
            runner_id=str(data.get("runner_id", "")),
            exit_code=_strict_int(data.get("exit_code"), "scan attestation exit_code"),
            target_uri=str(data.get("target_uri", "")),
            started_at=str(data.get("started_at", "")),
            finished_at=str(data.get("finished_at", "")),
            complete=_strict_bool(data.get("complete"), "scan attestation complete"),
            signature_present=(
                _strict_bool(
                    data.get("signature_present", False),
                    "scan attestation signature_present",
                )
                if signature_present is None
                else signature_present
            ),
            signature_verified=(
                _strict_bool(
                    data.get("signature_verified", False),
                    "scan attestation signature_verified",
                )
                if signature_verified is None
                else signature_verified
            ),
            key_id=str(data.get("key_id", "")),
        )
        provenance.validate()
        return provenance

    def validate(self) -> None:
        if self.predicate_type != "https://finguard.dev/attestations/scan/v3":
            raise EvidenceVerificationError("unsupported scan attestation predicate type")
        for field_name in ("report_sha256", "ruleset_sha256", "command_sha256"):
            if not _SHA256.fullmatch(getattr(self, field_name)):
                raise EvidenceVerificationError(
                    f"scan attestation {field_name} must be 64 hexadecimal characters"
                )
        if self.database_sha256 and not _SHA256.fullmatch(self.database_sha256):
            raise EvidenceVerificationError(
                "scan attestation database_sha256 must be 64 hexadecimal characters"
            )
        if self.database_updated_at:
            try:
                _aware_datetime(self.database_updated_at)
            except ValueError as exc:
                raise EvidenceVerificationError(
                    "scan attestation database_updated_at is invalid"
                ) from exc
        if not _FULL_GIT_SHA.fullmatch(self.source_commit):
            raise EvidenceVerificationError(
                "scan attestation source_commit must be a full 40 or 64 character Git object ID"
            )
        if self.image_digest and not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", self.image_digest):
            raise EvidenceVerificationError("scan attestation image_digest is invalid")
        if not 0 <= self.exit_code <= 255:
            raise EvidenceVerificationError("scan attestation exit_code must be between 0 and 255")
        if self.target_uri:
            try:
                canonical_target = canonical_http_url(self.target_uri)
            except ValueError as exc:
                raise EvidenceVerificationError(
                    f"scan attestation target_uri is invalid: {exc}"
                ) from exc
            if canonical_target != self.target_uri:
                raise EvidenceVerificationError("scan attestation target_uri must be canonical")
        required_text = {
            "scanner": self.scanner,
            "category": self.category,
            "scanner_version": self.scanner_version,
            "scanner_uri": self.scanner_uri,
            "ci_job_id": self.ci_job_id,
            "runner_id": self.runner_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }
        missing = sorted(name for name, value in required_text.items() if not value.strip())
        if missing:
            raise EvidenceVerificationError(
                f"scan attestation fields are required: {', '.join(missing)}"
            )
        try:
            started = _aware_datetime(self.started_at)
            finished = _aware_datetime(self.finished_at)
        except ValueError as exc:
            raise EvidenceVerificationError("scan attestation timestamps are invalid") from exc
        if started > finished:
            raise EvidenceVerificationError(
                "scan attestation started_at must not follow finished_at"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "predicate_type": self.predicate_type,
            "report_sha256": self.report_sha256,
            "scanner": self.scanner,
            "category": self.category,
            "scanner_version": self.scanner_version,
            "scanner_uri": self.scanner_uri,
            "source_commit": self.source_commit,
            "image_digest": self.image_digest,
            "ruleset_sha256": self.ruleset_sha256,
            "database_sha256": self.database_sha256,
            "database_updated_at": self.database_updated_at,
            "command_sha256": self.command_sha256,
            "ci_job_id": self.ci_job_id,
            "runner_id": self.runner_id,
            "exit_code": self.exit_code,
            "target_uri": self.target_uri,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "complete": self.complete,
            "signature_present": self.signature_present,
            "signature_verified": self.signature_verified,
            "key_id": self.key_id,
        }


def _strict_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceVerificationError(f"{field} must be a boolean")
    return value


def _strict_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceVerificationError(f"{field} must be an integer")
    return value


def _aware_datetime(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed


@dataclass
class ScanResult:
    """Normalized result of one scanner execution or imported report."""

    scanner: str
    category: str
    status: ScanStatus
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    errors: list[str] = field(default_factory=list)
    generated_at: str = ""
    input_sha256: str = ""
    provenance: ScanProvenance | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "2.0",
            "scanner": self.scanner,
            "category": self.category,
            "status": self.status.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "metrics": self.metrics,
            "source": self.source,
            "errors": self.errors,
            "generated_at": self.generated_at,
            "input_sha256": self.input_sha256,
            "provenance": self.provenance.to_dict() if self.provenance else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanResult:
        if not isinstance(data, Mapping):
            raise ValueError("normalized scan must be an object")
        _reject_unknown_keys(
            data,
            {
                "schema_version",
                "scanner",
                "category",
                "status",
                "findings",
                "metrics",
                "source",
                "errors",
                "generated_at",
                "input_sha256",
                "provenance",
            },
            "normalized scan",
        )
        if data.get("schema_version") != "2.0":
            raise ValueError("normalized scan schema_version must be 2.0")
        findings = data.get("findings", [])
        metrics = data.get("metrics", {})
        errors = data.get("errors", [])
        if not isinstance(findings, list) or not all(
            isinstance(item, Mapping) for item in findings
        ):
            raise ValueError("normalized scan findings must be an array of objects")
        if not isinstance(metrics, Mapping) or not all(isinstance(key, str) for key in metrics):
            raise ValueError("normalized scan metrics must be an object")
        if not isinstance(errors, list) or not all(isinstance(item, str) for item in errors):
            raise ValueError("normalized scan errors must be an array of strings")
        status = data.get("status")
        if not isinstance(status, str):
            raise ValueError("normalized scan status must be a string")
        provenance_raw = data.get("provenance")
        if provenance_raw is not None and not isinstance(provenance_raw, Mapping):
            raise ValueError("normalized scan provenance must be an object or null")
        return cls(
            scanner=_required_model_text(data, "scanner", "normalized scan"),
            category=_required_model_text(data, "category", "normalized scan"),
            status=ScanStatus(status),
            findings=[Finding.from_dict(item) for item in findings],
            metrics=dict(metrics),
            source=_optional_model_text(data, "source", "normalized scan"),
            errors=list(errors),
            generated_at=_optional_model_text(data, "generated_at", "normalized scan"),
            input_sha256=_optional_model_text(data, "input_sha256", "normalized scan"),
            provenance=(
                ScanProvenance.from_dict(provenance_raw)
                if isinstance(provenance_raw, Mapping)
                else None
            ),
        )

    def write_json(self, path: Path) -> None:
        atomic_write_text(
            path,
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n",
            context="normalized scan report",
        )


@dataclass(frozen=True)
class GateViolation:
    code: str
    message: str
    severity: str = "error"
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "details": dict(self.details),
        }


@dataclass
class GateResult:
    decision: Decision
    policy_id: str
    policy_version: str
    violations: list[GateViolation]
    active_findings: list[Finding]
    excepted_findings: list[Finding]
    scan_results: list[ScanResult]
    metrics: dict[str, Any]
    evaluated_at: str
    change_id: str = ""
    release_subject: ReleaseSubject | None = None
    inventory: list[Finding] = field(default_factory=list)
    vexed_findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "2.0",
            "decision": self.decision.value,
            "policy": {"id": self.policy_id, "version": self.policy_version},
            "change_id": self.change_id,
            "release_subject": self.release_subject.to_dict() if self.release_subject else None,
            "release_subject_sha256": (self.release_subject.digest if self.release_subject else ""),
            "evaluated_at": self.evaluated_at,
            "violations": [violation.to_dict() for violation in self.violations],
            "metrics": self.metrics,
            "findings": {
                "active": [finding.to_dict() for finding in self.active_findings],
                "excepted": [finding.to_dict() for finding in self.excepted_findings],
                "vexed": [finding.to_dict() for finding in self.vexed_findings],
            },
            "inventory": [finding.to_dict() for finding in self.inventory],
            "scans": [scan.to_dict() for scan in self.scan_results],
        }


def _reject_unknown_keys(data: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError(f"{context} contains unknown keys: {', '.join(unknown)}")


def _required_model_text(data: Mapping[str, Any], key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} {key} must be a non-empty string")
    return value


def _optional_model_text(data: Mapping[str, Any], key: str, context: str) -> str:
    value = data.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f"{context} {key} must be a string")
    return value
