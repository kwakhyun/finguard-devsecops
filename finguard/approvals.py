"""Signed external approval evidence bound to a change and release subject."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .change import Approval, ChangeRequest
from .errors import ConfigurationError, EvidenceVerificationError
from .jsonio import strict_json_loads
from .release import ReleaseSubject
from .safeio import assert_no_symlink_components, atomic_write_text

PREDICATE_TYPE = "https://finguard.dev/attestations/change-approval/v2"


@dataclass(frozen=True)
class ApprovalAttestation:
    change_id: str
    change_request_sha256: str
    release_subject_sha256: str
    issuer: str
    source_uri: str
    event_id: str
    issued_at: dt.datetime
    approvals: tuple[Approval, ...]
    signature_present: bool
    signature_verified: bool
    signature_method: str
    key_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "predicate_type": PREDICATE_TYPE,
            "change_id": self.change_id,
            "change_request_sha256": self.change_request_sha256,
            "release_subject_sha256": self.release_subject_sha256,
            "issuer": self.issuer,
            "source_uri": self.source_uri,
            "event_id": self.event_id,
            "issued_at": self.issued_at.isoformat(),
            "approvals": [
                {
                    "approver": item.approver,
                    "role": item.role,
                    "approved_at": _as_utc(item.approved_at).isoformat(),
                }
                for item in self.approvals
            ],
            "signature_present": self.signature_present,
            "signature_verified": self.signature_verified,
            "signature_method": self.signature_method,
            "key_id": self.key_id,
        }


def create_approval_attestation(
    output: Path,
    *,
    change: ChangeRequest,
    release_subject: ReleaseSubject,
    issuer: str,
    source_uri: str,
    event_id: str,
    issued_at: dt.datetime,
    signing_key: bytes | None = None,
    key_id: str = "",
    force: bool = False,
) -> Path:
    normalized_key_id = key_id.strip()
    if not normalized_key_id:
        raise EvidenceVerificationError("approval key_id is required and must be signed")
    if change.release_subject is None or change.release_subject.digest != release_subject.digest:
        raise EvidenceVerificationError("change does not approve the supplied release subject")
    payload = {
        "schema_version": "2.0",
        "predicate_type": PREDICATE_TYPE,
        "change_id": change.change_id,
        "change_request_sha256": change.digest,
        "release_subject_sha256": release_subject.digest,
        "issuer": _required_text(issuer, "issuer"),
        "source_uri": _required_text(source_uri, "source_uri"),
        "event_id": _required_text(event_id, "event_id"),
        "issued_at": _as_utc(issued_at).isoformat(),
        "key_id": normalized_key_id,
        "approvals": [
            {
                "approver": item.approver,
                "role": item.role,
                "approved_at": _as_utc(item.approved_at).isoformat(),
            }
            for item in change.approvals
        ],
    }
    envelope: dict[str, Any] = {"payload": payload}
    if signing_key is not None:
        signature = hmac.new(signing_key, _canonical(payload), hashlib.sha256).hexdigest()
        envelope["signature"] = {
            "algorithm": "hmac-sha256",
            "key_id": normalized_key_id,
            "value": signature,
        }
    _write_atomic(output, envelope, force=force)
    return output


def load_approval_attestation(
    path: Path,
    *,
    signing_key: bytes | None = None,
    external_signature_verified: bool = False,
    external_key_id: str = "",
) -> ApprovalAttestation:
    if signing_key is not None and external_signature_verified:
        raise EvidenceVerificationError("choose one approval signature verification method")
    if external_signature_verified and not external_key_id.strip():
        raise EvidenceVerificationError("external approval signature key_id is required")
    try:
        envelope = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise EvidenceVerificationError(f"cannot read approval attestation {path}: {exc}") from exc
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
        raise EvidenceVerificationError("invalid approval attestation envelope")
    _exact_keys(envelope, {"payload", "signature"}, "approval envelope", optional={"signature"})
    payload = envelope["payload"]
    _exact_keys(
        payload,
        {
            "schema_version",
            "predicate_type",
            "change_id",
            "change_request_sha256",
            "release_subject_sha256",
            "issuer",
            "source_uri",
            "event_id",
            "issued_at",
            "key_id",
            "approvals",
        },
        "approval payload",
    )
    if payload.get("schema_version") != "2.0":
        raise EvidenceVerificationError("unsupported approval attestation schema version")
    if payload.get("predicate_type") != PREDICATE_TYPE:
        raise EvidenceVerificationError("unsupported approval attestation predicate type")
    payload_key_id = _required_text(payload.get("key_id"), "key_id")
    signature = envelope.get("signature")
    if signature is not None and not isinstance(signature, dict):
        raise EvidenceVerificationError("approval signature must be an object")
    signature_mapping: Mapping[str, Any] = signature if isinstance(signature, dict) else {}
    signature_present = signature is not None or external_signature_verified
    if signature is not None:
        _exact_keys(
            signature_mapping,
            {"algorithm", "key_id", "value"},
            "approval signature",
        )
        if signature_mapping.get("algorithm") != "hmac-sha256":
            raise EvidenceVerificationError("unsupported approval signature algorithm")
        if str(signature_mapping.get("key_id", "")) != payload_key_id:
            raise EvidenceVerificationError(
                "approval signature key_id does not match signed payload"
            )
    signature_verified = external_signature_verified
    signature_method = (
        "cosign" if external_signature_verified else str(signature_mapping.get("algorithm", ""))
    )
    if signing_key is not None:
        if not signature_present:
            raise EvidenceVerificationError("approval attestation signature is missing")
        expected = hmac.new(signing_key, _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(signature_mapping.get("value", "")), expected):
            raise EvidenceVerificationError("approval attestation signature mismatch")
        signature_verified = True
        signature_method = "hmac-sha256"
    if external_signature_verified and external_key_id.strip() != payload_key_id:
        raise EvidenceVerificationError(
            "approval verification key_id does not match signed payload"
        )
    approvals_raw = payload.get("approvals", [])
    if not isinstance(approvals_raw, list) or not approvals_raw:
        raise EvidenceVerificationError("approval attestation approvals must be a non-empty list")
    approvals: list[Approval] = []
    for index, item in enumerate(approvals_raw):
        if not isinstance(item, dict):
            raise EvidenceVerificationError(f"approval attestation approvals[{index}] is invalid")
        _exact_keys(
            item,
            {"approver", "role", "approved_at"},
            f"approval approvals[{index}]",
        )
        approvals.append(
            Approval(
                approver=_required_text(item.get("approver"), f"approvals[{index}].approver"),
                role=_required_text(item.get("role"), f"approvals[{index}].role"),
                approved_at=_datetime(item.get("approved_at"), f"approvals[{index}].approved_at"),
            )
        )
    subject_digest = _required_text(
        payload.get("release_subject_sha256"), "release_subject_sha256"
    ).casefold()
    if len(subject_digest) != 64 or any(
        character not in "0123456789abcdef" for character in subject_digest
    ):
        raise EvidenceVerificationError("approval release_subject_sha256 is invalid")
    change_digest = _required_sha256(payload.get("change_request_sha256"), "change_request_sha256")
    return ApprovalAttestation(
        change_id=_required_text(payload.get("change_id"), "change_id"),
        change_request_sha256=change_digest,
        release_subject_sha256=subject_digest,
        issuer=_required_text(payload.get("issuer"), "issuer"),
        source_uri=_required_text(payload.get("source_uri"), "source_uri"),
        event_id=_required_text(payload.get("event_id"), "event_id"),
        issued_at=_datetime(payload.get("issued_at"), "issued_at"),
        approvals=tuple(approvals),
        signature_present=signature_present,
        signature_verified=signature_verified,
        signature_method=signature_method,
        key_id=payload_key_id,
    )


def _datetime(value: object, field: str) -> dt.datetime:
    if not isinstance(value, str):
        raise EvidenceVerificationError(f"approval attestation {field} must be a datetime")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceVerificationError(
            f"approval attestation {field} must be an ISO-8601 datetime"
        ) from exc
    if result.tzinfo is None:
        raise EvidenceVerificationError(f"approval attestation {field} needs a timezone")
    return result.astimezone(dt.UTC)


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceVerificationError(f"approval attestation {field} is required")
    return value.strip()


def _required_sha256(value: object, field: str) -> str:
    result = _required_text(value, field).casefold()
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise EvidenceVerificationError(f"approval attestation {field} is invalid")
    return result


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        raise EvidenceVerificationError("approval timestamps must include a timezone")
    return value.astimezone(dt.UTC)


def _write_atomic(output: Path, value: Mapping[str, Any], *, force: bool) -> None:
    output = output.expanduser()
    try:
        assert_no_symlink_components(output, context="approval output")
        if output.exists() and not force:
            raise EvidenceVerificationError(f"approval output already exists: {output}")
        atomic_write_text(
            output,
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            context="approval output",
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
