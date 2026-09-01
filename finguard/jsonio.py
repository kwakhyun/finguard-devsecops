"""Strict JSON decoding shared by security and evidence trust boundaries."""

from __future__ import annotations

import json
from typing import Any


def strict_json_loads(value: str) -> Any:
    """Reject duplicate object names and non-standard non-finite numbers."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key is not allowed: {key}")
            result[key] = item
        return result

    def reject_constant(constant: str) -> None:
        raise ValueError(f"non-finite JSON number is not allowed: {constant}")

    try:
        return json.loads(
            value,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the safe parser depth") from exc
