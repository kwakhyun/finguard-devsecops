"""Strict field readers shared by policy and exception loaders."""

from __future__ import annotations

import datetime as dt
import math
from collections.abc import Mapping
from typing import Any

from .errors import ConfigurationError


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
