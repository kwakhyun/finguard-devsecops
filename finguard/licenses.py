"""Small fail-closed SPDX expression evaluator for policy decisions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum


class LicenseDisposition(IntEnum):
    ALLOWED = 0
    REVIEW = 1
    NOT_ALLOWED = 2
    DENIED = 3
    UNKNOWN = 4


@dataclass(frozen=True)
class LicenseEvaluation:
    disposition: LicenseDisposition
    identifiers: tuple[str, ...]
    valid_expression: bool


_TOKEN = re.compile(r"\s*(\(|\)|AND\b|OR\b|WITH\b|[A-Za-z0-9][A-Za-z0-9.+:-]*)", re.I)


def evaluate_spdx_expression(
    expression: str,
    *,
    allowed: set[str],
    denied: set[str],
    review_required: set[str],
    allow_unknown: bool,
) -> LicenseEvaluation:
    """Evaluate AND/OR/WITH semantics without accepting malformed expressions."""

    text = expression.strip()
    if not text or text.casefold() in {"unknown", "noassertion"}:
        disposition = LicenseDisposition.ALLOWED if allow_unknown else LicenseDisposition.UNKNOWN
        return LicenseEvaluation(disposition, (), False)

    normalized_allowed = {item.casefold() for item in allowed}
    normalized_denied = {item.casefold() for item in denied}
    normalized_review = {item.casefold() for item in review_required}
    exact = text.casefold()
    if exact in normalized_denied:
        return LicenseEvaluation(LicenseDisposition.DENIED, (text,), True)
    if exact in normalized_review:
        return LicenseEvaluation(LicenseDisposition.REVIEW, (text,), True)
    if exact in normalized_allowed:
        return LicenseEvaluation(LicenseDisposition.ALLOWED, (text,), True)

    tokens = _tokenize(text)
    if tokens is None:
        return LicenseEvaluation(LicenseDisposition.UNKNOWN, (), False)
    parser = _Parser(
        tokens,
        allowed=normalized_allowed,
        denied=normalized_denied,
        review=normalized_review,
        allow_unknown=allow_unknown,
    )
    try:
        disposition, identifiers = parser.parse()
    except ValueError:
        return LicenseEvaluation(LicenseDisposition.UNKNOWN, (), False)
    return LicenseEvaluation(disposition, tuple(sorted(identifiers)), True)


def _tokenize(value: str) -> list[str] | None:
    tokens: list[str] = []
    position = 0
    while position < len(value):
        match = _TOKEN.match(value, position)
        if match is None:
            return None
        tokens.append(match.group(1))
        position = match.end()
    return tokens


class _Parser:
    def __init__(
        self,
        tokens: list[str],
        *,
        allowed: set[str],
        denied: set[str],
        review: set[str],
        allow_unknown: bool,
    ) -> None:
        self.tokens = tokens
        self.position = 0
        self.allowed = allowed
        self.denied = denied
        self.review = review
        self.allow_unknown = allow_unknown

    def parse(self) -> tuple[LicenseDisposition, set[str]]:
        result = self._or_expression()
        if self.position != len(self.tokens):
            raise ValueError("trailing SPDX tokens")
        return result

    def _or_expression(self) -> tuple[LicenseDisposition, set[str]]:
        left, identifiers = self._and_expression()
        while self._peek("OR"):
            self.position += 1
            right, right_identifiers = self._and_expression()
            # An OR expression can use the least restrictive valid branch.
            left = min(left, right)
            identifiers |= right_identifiers
        return left, identifiers

    def _and_expression(self) -> tuple[LicenseDisposition, set[str]]:
        left, identifiers = self._with_expression()
        while self._peek("AND"):
            self.position += 1
            right, right_identifiers = self._with_expression()
            # Every AND obligation applies, so preserve the strictest result.
            left = max(left, right)
            identifiers |= right_identifiers
        return left, identifiers

    def _with_expression(self) -> tuple[LicenseDisposition, set[str]]:
        left, identifiers, base = self._primary()
        if self._peek("WITH"):
            self.position += 1
            exception = self._identifier()
            compound = f"{base} WITH {exception}"
            normalized = compound.casefold()
            identifiers.add(compound)
            if normalized in self.denied:
                left = LicenseDisposition.DENIED
            elif normalized in self.review:
                left = LicenseDisposition.REVIEW
            elif normalized in self.allowed:
                left = LicenseDisposition.ALLOWED
            else:
                # An unreviewed exception changes the obligations of the base license.
                left = max(left, LicenseDisposition.REVIEW)
        return left, identifiers

    def _primary(self) -> tuple[LicenseDisposition, set[str], str]:
        if self._peek("("):
            self.position += 1
            disposition, identifiers = self._or_expression()
            if not self._peek(")"):
                raise ValueError("unclosed SPDX expression")
            self.position += 1
            return disposition, identifiers, ""
        identifier = self._identifier()
        normalized = identifier.casefold()
        if normalized in self.denied:
            disposition = LicenseDisposition.DENIED
        elif normalized in self.review:
            disposition = LicenseDisposition.REVIEW
        elif normalized in self.allowed:
            disposition = LicenseDisposition.ALLOWED
        elif self.allow_unknown:
            disposition = LicenseDisposition.ALLOWED
        else:
            disposition = LicenseDisposition.NOT_ALLOWED
        return disposition, {identifier}, identifier

    def _identifier(self) -> str:
        if self.position >= len(self.tokens):
            raise ValueError("missing SPDX identifier")
        token = self.tokens[self.position]
        if token.upper() in {"AND", "OR", "WITH"} or token in {"(", ")"}:
            raise ValueError("expected SPDX identifier")
        self.position += 1
        return token

    def _peek(self, token: str) -> bool:
        return self.position < len(self.tokens) and self.tokens[self.position].upper() == token
