"""Strict loading and models for scoped policy exceptions."""

from __future__ import annotations

import datetime as dt
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .config_fields import (
    _boolean,
    _known_keys,
    _required,
    _text,
)
from .errors import ConfigurationError


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
