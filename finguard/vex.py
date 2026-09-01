"""Signed VEX review evidence independent from scanner-controlled SBOM metadata."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigurationError, EvidenceVerificationError
from .jsonio import strict_json_loads
from .release import ReleaseSubject
from .safeio import assert_no_symlink_components, atomic_write_text

PREDICATE_TYPE = "https://finguard.dev/attestations/vex-review/v1"
KNOWN_STATES = frozenset(
    {
        "resolved",
        "resolved_with_pedigree",
        "exploitable",
        "in_triage",
        "false_positive",
        "not_affected",
    }
)


@dataclass(frozen=True)
class VexStatement:
    fingerprint: str
    state: str
    justification: str
    detail: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, context: str) -> VexStatement:
        fingerprint = _required_text(value.get("fingerprint"), f"{context}.fingerprint").lower()
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise EvidenceVerificationError(
                f"{context}.fingerprint must be 64 hexadecimal characters"
            )
        state = _required_text(value.get("state"), f"{context}.state").casefold()
        if state not in KNOWN_STATES:
            raise EvidenceVerificationError(f"{context}.state is not a supported VEX state")
        return cls(
            fingerprint=fingerprint,
            state=state,
            justification=_required_text(value.get("justification"), f"{context}.justification"),
            detail=_required_text(value.get("detail"), f"{context}.detail"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "fingerprint": self.fingerprint,
            "state": self.state,
            "justification": self.justification,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class VexAttestation:
    release_subject_sha256: str
    issuer: str
    source_uri: str
    event_id: str
    approver: str
    issued_at: dt.datetime
    expires_at: dt.datetime
    statements: tuple[VexStatement, ...]
    signature_present: bool
    signature_verified: bool
    signature_method: str
    key_id: str


def create_vex_attestation(
    output: Path,
    *,
    release_subject: ReleaseSubject,
    issuer: str,
    source_uri: str,
    event_id: str,
    approver: str,
    issued_at: dt.datetime,
    expires_at: dt.datetime,
    statements: Iterable[VexStatement],
    key_id: str,
    signing_key: bytes | None = None,
    force: bool = False,
) -> Path:
    statement_list = tuple(statements)
    if not statement_list:
        raise EvidenceVerificationError("VEX attestation must contain at least one statement")
    if not key_id.strip():
        raise EvidenceVerificationError("VEX attestation key_id is required")
    issued = _as_utc(issued_at, "issued_at")
    expires = _as_utc(expires_at, "expires_at")
    if expires <= issued:
        raise EvidenceVerificationError("VEX attestation expires_at must follow issued_at")
    _reject_duplicate_fingerprints(statement_list)
    payload = {
        "schema_version": "1.0",
        "predicate_type": PREDICATE_TYPE,
        "release_subject_sha256": release_subject.digest,
        "issuer": _required_text(issuer, "issuer"),
        "source_uri": _required_text(source_uri, "source_uri"),
        "event_id": _required_text(event_id, "event_id"),
        "approver": _required_text(approver, "approver"),
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "key_id": key_id.strip(),
        "statements": [item.to_dict() for item in statement_list],
    }
    envelope: dict[str, Any] = {"payload": payload}
    if signing_key is not None:
        envelope["signature"] = {
            "algorithm": "hmac-sha256",
            "key_id": key_id.strip(),
            "value": hmac.new(signing_key, _canonical(payload), hashlib.sha256).hexdigest(),
        }
    _write_atomic(output, envelope, force=force)
    return output


def load_vex_attestation(
    path: Path,
    *,
    signing_key: bytes | None = None,
    external_signature_verified: bool = False,
    external_key_id: str = "",
) -> VexAttestation:
    if signing_key is not None and external_signature_verified:
        raise EvidenceVerificationError("choose one VEX signature verification method")
    try:
        envelope = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise EvidenceVerificationError(f"cannot read VEX attestation {path}: {exc}") from exc
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
        raise EvidenceVerificationError("invalid VEX attestation envelope")
    _exact_keys(envelope, {"payload", "signature"}, "VEX envelope", optional={"signature"})
    payload: Mapping[str, Any] = envelope["payload"]
    _exact_keys(
        payload,
        {
            "schema_version",
            "predicate_type",
            "release_subject_sha256",
            "issuer",
            "source_uri",
            "event_id",
            "approver",
            "issued_at",
            "expires_at",
            "key_id",
            "statements",
        },
        "VEX payload",
    )
    if payload.get("schema_version") != "1.0" or payload.get("predicate_type") != PREDICATE_TYPE:
        raise EvidenceVerificationError("unsupported VEX attestation schema")
    payload_key_id = _required_text(payload.get("key_id"), "key_id")
    signature = envelope.get("signature")
    if signature is not None and not isinstance(signature, dict):
        raise EvidenceVerificationError("VEX signature must be an object")
    signature_mapping: Mapping[str, Any] = signature if isinstance(signature, dict) else {}
    signature_present = signature is not None or external_signature_verified
    signature_verified = external_signature_verified
    signature_method = "cosign" if external_signature_verified else ""
    if signature is not None:
        _exact_keys(
            signature_mapping,
            {"algorithm", "key_id", "value"},
            "VEX signature",
        )
        if signature_mapping.get("algorithm") != "hmac-sha256":
            raise EvidenceVerificationError("unsupported VEX signature algorithm")
        if str(signature_mapping.get("key_id", "")) != payload_key_id:
            raise EvidenceVerificationError("VEX signature key_id does not match signed payload")
        signature_method = "hmac-sha256"
    if signing_key is not None:
        if not signature_mapping:
            raise EvidenceVerificationError("VEX attestation signature is missing")
        expected = hmac.new(signing_key, _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(signature_mapping.get("value", "")), expected):
            raise EvidenceVerificationError("VEX attestation signature mismatch")
        signature_verified = True
    if external_signature_verified and external_key_id.strip() != payload_key_id:
        raise EvidenceVerificationError("VEX verification key_id does not match signed payload")

    subject_digest = _required_text(
        payload.get("release_subject_sha256"), "release_subject_sha256"
    ).casefold()
    if len(subject_digest) != 64 or any(
        character not in "0123456789abcdef" for character in subject_digest
    ):
        raise EvidenceVerificationError("VEX release_subject_sha256 is invalid")
    statements_raw = payload.get("statements")
    if not isinstance(statements_raw, list) or not statements_raw:
        raise EvidenceVerificationError("VEX statements must be a non-empty array")
    statements: list[VexStatement] = []
    for index, item in enumerate(statements_raw):
        if not isinstance(item, dict):
            raise EvidenceVerificationError(f"VEX statements[{index}] must be an object")
        _exact_keys(
            item,
            {"fingerprint", "state", "justification", "detail"},
            f"VEX statements[{index}]",
        )
        statements.append(VexStatement.from_mapping(item, context=f"statements[{index}]"))
    _reject_duplicate_fingerprints(statements)
    return VexAttestation(
        release_subject_sha256=subject_digest,
        issuer=_required_text(payload.get("issuer"), "issuer"),
        source_uri=_required_text(payload.get("source_uri"), "source_uri"),
        event_id=_required_text(payload.get("event_id"), "event_id"),
        approver=_required_text(payload.get("approver"), "approver"),
        issued_at=_datetime(payload.get("issued_at"), "issued_at"),
        expires_at=_datetime(payload.get("expires_at"), "expires_at"),
        statements=tuple(statements),
        signature_present=signature_present,
        signature_verified=signature_verified,
        signature_method=signature_method,
        key_id=payload_key_id,
    )


def load_vex_statements(path: Path) -> tuple[VexStatement, ...]:
    try:
        raw = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise EvidenceVerificationError(f"cannot read VEX statements {path}: {exc}") from exc
    if not isinstance(raw, list) or not raw:
        raise EvidenceVerificationError("VEX statements file must be a non-empty JSON array")
    statements: list[VexStatement] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise EvidenceVerificationError(f"VEX statements[{index}] must be an object")
        _exact_keys(
            item,
            {"fingerprint", "state", "justification", "detail"},
            f"VEX statements[{index}]",
        )
        statements.append(VexStatement.from_mapping(item, context=f"statements[{index}]"))
    _reject_duplicate_fingerprints(statements)
    return tuple(statements)


def _reject_duplicate_fingerprints(statements: Iterable[VexStatement]) -> None:
    seen: set[str] = set()
    for statement in statements:
        if statement.fingerprint in seen:
            raise EvidenceVerificationError(
                f"duplicate VEX statement fingerprint: {statement.fingerprint}"
            )
        seen.add(statement.fingerprint)


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceVerificationError(f"VEX attestation {field} is required")
    return value.strip()


def _datetime(value: object, field: str) -> dt.datetime:
    if not isinstance(value, str):
        raise EvidenceVerificationError(f"VEX attestation {field} must be a datetime")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceVerificationError(f"VEX attestation {field} is invalid") from exc
    return _as_utc(result, field)


def _as_utc(value: dt.datetime, field: str) -> dt.datetime:
    if value.tzinfo is None:
        raise EvidenceVerificationError(f"VEX attestation {field} needs a timezone")
    return value.astimezone(dt.UTC)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _write_atomic(path: Path, value: Mapping[str, Any], *, force: bool) -> None:
    try:
        assert_no_symlink_components(path, context="VEX attestation output")
        if path.exists() and not force:
            raise EvidenceVerificationError(f"VEX attestation already exists: {path}")
        atomic_write_text(
            path,
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            context="VEX attestation output",
        )
    except ConfigurationError as exc:
        raise EvidenceVerificationError(str(exc)) from exc


def _exact_keys(
    value: Mapping[str, Any],
    allowed: set[str],
    context: str,
    *,
    optional: set[str] | frozenset[str] = frozenset(),
) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted((allowed - optional) - set(value))
    if unknown or missing:
        raise EvidenceVerificationError(f"{context} fields are invalid")
