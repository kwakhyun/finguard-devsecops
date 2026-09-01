"""Change-control manifest used by CB/SR deployment gates."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .release import ReleaseSubject, commit_matches

_FULL_GIT_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


@dataclass(frozen=True)
class Approval:
    approver: str
    role: str
    approved_at: dt.datetime


@dataclass(frozen=True)
class ChangeRequest:
    change_id: str
    request_type: str
    service: str
    environment: str
    summary: str
    risk: str
    commit_sha: str
    requester: str
    deployer: str
    rollback_plan: str
    window_start: dt.datetime | None
    window_end: dt.datetime | None
    approvals: tuple[Approval, ...]
    release_subject: ReleaseSubject | None
    source_path: Path

    def to_dict(self) -> dict[str, Any]:
        """Return the complete semantic change request used for approval binding."""

        return {
            "schema_version": "1.0",
            "change": {
                "id": self.change_id,
                "type": self.request_type,
                "service": self.service,
                "environment": self.environment,
                "summary": self.summary,
                "risk": self.risk,
                "commit_sha": self.commit_sha.lower(),
                "requester": self.requester,
                "deployer": self.deployer,
                "rollback_plan": self.rollback_plan,
                "window_start": _optional_utc(self.window_start),
                "window_end": _optional_utc(self.window_end),
            },
            "release": self.release_subject.to_dict() if self.release_subject else None,
            "approvals": [
                {
                    "approver": approval.approver,
                    "role": approval.role,
                    "approved_at": approval.approved_at.astimezone(dt.UTC).isoformat(),
                }
                for approval in self.approvals
            ],
        }

    @property
    def digest(self) -> str:
        canonical = json.dumps(
            self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def load(cls, path: Path) -> ChangeRequest:
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigurationError(f"cannot load change request {path}: {exc}") from exc
        _known_keys(raw, {"change", "release", "approvals"}, "change document")
        change = raw.get("change", {})
        if not isinstance(change, dict):
            raise ConfigurationError("change must be a TOML table")
        _known_keys(
            change,
            {
                "id",
                "type",
                "service",
                "environment",
                "summary",
                "risk",
                "commit_sha",
                "requester",
                "deployer",
                "rollback_plan",
                "window_start",
                "window_end",
            },
            "change",
        )

        approvals_raw = raw.get("approvals", [])
        if not isinstance(approvals_raw, list):
            raise ConfigurationError("approvals must be an array of TOML tables")
        approvals: list[Approval] = []
        for index, item in enumerate(approvals_raw):
            if not isinstance(item, dict):
                raise ConfigurationError(f"approvals[{index}] must be a TOML table")
            _known_keys(item, {"approver", "role", "approved_at"}, f"approvals[{index}]")
            approved_at = item.get("approved_at")
            if not isinstance(approved_at, dt.datetime):
                raise ConfigurationError(f"approvals[{index}].approved_at must be a datetime")
            _require_timezone(approved_at, f"approvals[{index}].approved_at")
            approvals.append(
                Approval(
                    approver=_text(item, "approver", f"approvals[{index}]"),
                    role=_text(item, "role", f"approvals[{index}]"),
                    approved_at=approved_at,
                )
            )

        window_start = change.get("window_start")
        window_end = change.get("window_end")
        if window_start is not None and not isinstance(window_start, dt.datetime):
            raise ConfigurationError("change.window_start must be a datetime")
        if window_end is not None and not isinstance(window_end, dt.datetime):
            raise ConfigurationError("change.window_end must be a datetime")
        if isinstance(window_start, dt.datetime):
            _require_timezone(window_start, "change.window_start")
        if isinstance(window_end, dt.datetime):
            _require_timezone(window_end, "change.window_end")

        release_raw = raw.get("release")
        if release_raw is not None and not isinstance(release_raw, dict):
            raise ConfigurationError("release must be a TOML table")
        release_subject = (
            ReleaseSubject.from_mapping(release_raw, context="release")
            if isinstance(release_raw, dict)
            else None
        )

        rollback_plan = change.get("rollback_plan", "")
        if not isinstance(rollback_plan, str):
            raise ConfigurationError("change.rollback_plan must be a string")
        request = cls(
            change_id=_text(change, "id", "change"),
            request_type=_text(change, "type", "change").upper(),
            service=_text(change, "service", "change"),
            environment=_text(change, "environment", "change"),
            summary=_text(change, "summary", "change"),
            risk=_text(change, "risk", "change").lower(),
            commit_sha=_text(change, "commit_sha", "change"),
            requester=_text(change, "requester", "change"),
            deployer=_text(change, "deployer", "change"),
            rollback_plan=rollback_plan.strip(),
            window_start=window_start,
            window_end=window_end,
            approvals=tuple(approvals),
            release_subject=release_subject,
            source_path=path.resolve(),
        )
        request._validate_shape()
        return request

    def _validate_shape(self) -> None:
        if self.risk not in {"low", "medium", "high", "critical"}:
            raise ConfigurationError("change.risk must be low, medium, high, or critical")
        if self.window_start and self.window_end and self.window_start >= self.window_end:
            raise ConfigurationError("change.window_start must be earlier than window_end")
        if (self.window_start is None) != (self.window_end is None):
            raise ConfigurationError(
                "change.window_start and change.window_end must be provided together"
            )
        if not _FULL_GIT_SHA.fullmatch(self.commit_sha):
            raise ConfigurationError(
                "change.commit_sha must be a full 40 or 64 character hexadecimal Git object ID"
            )
        if self.release_subject is not None:
            subject = self.release_subject
            if subject.service != self.service:
                raise ConfigurationError("release.service must match change.service")
            if subject.environment != self.environment:
                raise ConfigurationError("release.environment must match change.environment")
            if not commit_matches(subject.commit_sha, self.commit_sha):
                raise ConfigurationError("release.commit_sha must match change.commit_sha")


def _text(mapping: Mapping[str, Any], key: str, context: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{context}.{key} is required and cannot be empty")
    return value.strip()


def _known_keys(mapping: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ConfigurationError(f"{context} contains unknown fields: {', '.join(unknown)}")


def _require_timezone(value: dt.datetime, context: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ConfigurationError(f"{context} must include a timezone")


def _optional_utc(value: dt.datetime | None) -> str | None:
    return value.astimezone(dt.UTC).isoformat() if value is not None else None
