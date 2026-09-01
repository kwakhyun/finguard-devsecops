"""Immutable release subject shared by change, evidence, and deployment controls."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .jsonio import strict_json_loads
from .urls import canonical_http_url

_FULL_GIT_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-fA-F]{64}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_CLUSTER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}$")


@dataclass(frozen=True)
class ReleaseSubject:
    """The exact source, artifact, SBOM, and deployment target approved for release."""

    service: str
    repository: str
    commit_sha: str
    image: str
    sbom_sha256: str
    environment: str
    cluster: str
    namespace: str
    deployment: str
    container: str
    healthcheck_url: str
    builder_id: str
    built_at: dt.datetime

    @classmethod
    def load(cls, path: Path) -> ReleaseSubject:
        try:
            value = strict_json_loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise ConfigurationError(f"cannot load release subject {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise ConfigurationError("release subject must be a JSON object")
        return cls.from_mapping(value, context="release subject")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, context: str = "release") -> ReleaseSubject:
        allowed = {
            "schema_version",
            "service",
            "repository",
            "commit_sha",
            "image",
            "sbom_sha256",
            "environment",
            "cluster",
            "namespace",
            "deployment",
            "container",
            "healthcheck_url",
            "builder_id",
            "built_at",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ConfigurationError(f"{context} contains unknown fields: {', '.join(unknown)}")
        schema_version = value.get("schema_version")
        if schema_version is not None and schema_version != "1.0":
            raise ConfigurationError(f"{context}.schema_version must be 1.0")
        built_at = value.get("built_at")
        if isinstance(built_at, dt.datetime):
            parsed_built_at = built_at
        elif isinstance(built_at, str):
            try:
                parsed_built_at = dt.datetime.fromisoformat(built_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ConfigurationError(
                    f"{context}.built_at must be an ISO-8601 datetime"
                ) from exc
        else:
            raise ConfigurationError(f"{context}.built_at must be a datetime")
        if parsed_built_at.tzinfo is None:
            raise ConfigurationError(f"{context}.built_at must include a timezone")

        def text(name: str) -> str:
            result = value.get(name)
            if not isinstance(result, str) or not result.strip():
                raise ConfigurationError(f"{context}.{name} is required and must be a string")
            return result.strip()

        subject = cls(
            service=text("service"),
            repository=text("repository"),
            commit_sha=text("commit_sha").lower(),
            image=text("image"),
            sbom_sha256=text("sbom_sha256").lower(),
            environment=text("environment"),
            cluster=text("cluster"),
            namespace=text("namespace"),
            deployment=text("deployment"),
            container=text("container"),
            healthcheck_url=text("healthcheck_url"),
            builder_id=text("builder_id"),
            built_at=parsed_built_at.astimezone(dt.UTC),
        )
        subject.validate(context=context)
        return subject

    def validate(self, *, context: str = "release") -> None:
        if not _FULL_GIT_SHA.fullmatch(self.commit_sha):
            raise ConfigurationError(
                f"{context}.commit_sha must be a full 40 or 64 character Git object ID"
            )
        validate_image_reference(self.image, context=f"{context}.image")
        if not _SHA256.fullmatch(self.sbom_sha256):
            raise ConfigurationError(f"{context}.sbom_sha256 must be 64 hexadecimal characters")
        for name, value in (
            ("service", self.service),
            ("namespace", self.namespace),
            ("deployment", self.deployment),
            ("container", self.container),
        ):
            if len(value) > 63 or not _DNS_LABEL.fullmatch(value):
                raise ConfigurationError(f"{context}.{name} must be a Kubernetes DNS label")
        if not _CLUSTER.fullmatch(self.cluster):
            raise ConfigurationError(f"{context}.cluster contains unsupported characters")
        if any(character.isspace() for character in self.repository):
            raise ConfigurationError(f"{context}.repository cannot contain whitespace")
        if any(character.isspace() for character in self.builder_id):
            raise ConfigurationError(f"{context}.builder_id cannot contain whitespace")
        health_url = urllib.parse.urlparse(self.healthcheck_url)
        if health_url.scheme.casefold() not in {"http", "https"} or not health_url.hostname:
            raise ConfigurationError(f"{context}.healthcheck_url must use http or https")
        if health_url.username or health_url.password:
            raise ConfigurationError(f"{context}.healthcheck_url cannot contain credentials")
        try:
            canonical_health_url = canonical_http_url(self.healthcheck_url)
        except ValueError as exc:
            raise ConfigurationError(f"{context}.healthcheck_url is invalid: {exc}") from exc
        if canonical_health_url != self.healthcheck_url:
            raise ConfigurationError(f"{context}.healthcheck_url must be canonical")

    @property
    def image_digest(self) -> str:
        return self.image.rsplit("@", 1)[1].lower()

    @property
    def digest(self) -> str:
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": "1.0",
            "service": self.service,
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "image": self.image,
            "sbom_sha256": self.sbom_sha256,
            "environment": self.environment,
            "cluster": self.cluster,
            "namespace": self.namespace,
            "deployment": self.deployment,
            "container": self.container,
            "healthcheck_url": self.healthcheck_url,
            "builder_id": self.builder_id,
            "built_at": self.built_at.isoformat(),
        }

    def assert_matches_deployment(
        self,
        *,
        cluster: str,
        namespace: str,
        deployment: str,
        container: str,
        image: str,
    ) -> None:
        actual = {
            "cluster": cluster,
            "namespace": namespace,
            "deployment": deployment,
            "container": container,
            "image": image,
        }
        expected = {name: getattr(self, name) for name in actual}
        mismatches = {
            name: {"approved": expected[name], "requested": actual[name]}
            for name in actual
            if actual[name] != expected[name]
        }
        if mismatches:
            fields = ", ".join(sorted(mismatches))
            raise ConfigurationError(
                f"deployment request does not match the approved release subject: {fields}"
            )


def commit_matches(left: str, right: str) -> bool:
    """Compare complete SHA-1 or SHA-256 Git object IDs without prefix ambiguity."""

    normalized_left = left.casefold()
    normalized_right = right.casefold()
    if not all(_FULL_GIT_SHA.fullmatch(value) for value in (normalized_left, normalized_right)):
        return False
    return normalized_left == normalized_right


def validate_image_reference(value: str, *, context: str = "image") -> None:
    if not _IMAGE.fullmatch(value):
        raise ConfigurationError(f"{context} must use an immutable @sha256:<64 hex> reference")
