"""Shared canonicalization helpers for policy checks."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable

from ..change import Approval
from ..models import (
    Finding,
)


def _is_inventory(finding: Finding) -> bool:
    return finding.category == "license" or finding.metadata.get("kind") == "dependency_license"


def _parse_timestamp(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(dt.UTC)


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC)


def _roles_have_distinct_approvers(
    approvals: Iterable[Approval], required_roles: Iterable[str]
) -> bool:
    candidates: dict[str, set[str]] = {
        role.casefold(): {
            approval.approver.casefold()
            for approval in approvals
            if approval.role.casefold() == role.casefold()
        }
        for role in required_roles
    }
    identity_to_role: dict[str, str] = {}

    def assign(role: str, visited: set[str]) -> bool:
        for identity in sorted(candidates[role]):
            if identity in visited:
                continue
            visited.add(identity)
            previous = identity_to_role.get(identity)
            if previous is None or assign(previous, visited):
                identity_to_role[identity] = role
                return True
        return False

    return all(assign(role, set()) for role in candidates)


def _approval_tuple(approval: Approval) -> tuple[str, str, str]:
    return (
        approval.approver.casefold(),
        approval.role.casefold(),
        _as_utc(approval.approved_at).isoformat(),
    )
