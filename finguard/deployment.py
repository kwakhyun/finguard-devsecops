"""Evidence-bound Kubernetes deployment with automatic rollout rollback."""

from __future__ import annotations

import datetime as dt
import hmac
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .change import ChangeRequest
from .config import Policy
from .errors import ConfigurationError, DeploymentError, EvidenceVerificationError
from .evidence import sha256_file, verify_evidence_bundle
from .jsonio import strict_json_loads
from .release import ReleaseSubject, commit_matches
from .safeio import assert_no_symlink_components, atomic_write_text
from .signing import Runner as SigningRunner
from .signing import cosign_sign_blob

Runner = Callable[..., subprocess.CompletedProcess[str]]
HealthChecker = Callable[[str, float], bool]
Sleeper = Callable[[float], None]
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
IMMUTABLE_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-fA-F]{64}$")
AUDIT_ANNOTATIONS = (
    "finguard.io/change-id",
    "finguard.io/evidence-sha256",
    "finguard.io/release-subject-sha256",
)


@dataclass(frozen=True)
class DeploymentRequest:
    cluster: str
    namespace: str
    deployment: str
    container: str
    image: str
    expected_policy_id: str
    expected_policy_version: str
    expected_policy_sha256: str
    evidence_dir: Path
    output: Path
    timeout_seconds: int = 300
    require_signature: bool = True
    smoke_test_attempts: int = 3
    smoke_test_timeout_seconds: float = 5.0
    smoke_test_interval_seconds: float = 2.0
    allowed_health_hosts: tuple[str, ...] = ()
    force_output: bool = False

    def validate(self) -> None:
        if (
            not self.cluster
            or len(self.cluster) > 253
            or any(character.isspace() for character in self.cluster)
        ):
            raise ConfigurationError("cluster must be a non-empty Kubernetes context name")
        for label, value in (
            ("namespace", self.namespace),
            ("deployment", self.deployment),
            ("container", self.container),
        ):
            if len(value) > 63 or not DNS_LABEL.fullmatch(value):
                raise ConfigurationError(f"{label} must be a valid Kubernetes DNS label")
        if not IMMUTABLE_IMAGE.fullmatch(self.image):
            raise ConfigurationError("image must use an immutable @sha256:<64 hex> reference")
        for field, value in (
            ("expected_policy_id", self.expected_policy_id),
            ("expected_policy_version", self.expected_policy_version),
        ):
            if not value or value != value.strip():
                raise ConfigurationError(f"{field} must be a non-empty normalized string")
        if not re.fullmatch(r"[0-9a-f]{64}", self.expected_policy_sha256):
            raise ConfigurationError("expected_policy_sha256 must be a lowercase SHA-256 digest")
        if not 10 <= self.timeout_seconds <= 3600:
            raise ConfigurationError("deployment timeout must be between 10 and 3600 seconds")
        if not 1 <= self.smoke_test_attempts <= 10:
            raise ConfigurationError("smoke test attempts must be between 1 and 10")
        if not 0.1 <= self.smoke_test_timeout_seconds <= 30:
            raise ConfigurationError("smoke test timeout must be between 0.1 and 30 seconds")
        if not 0 <= self.smoke_test_interval_seconds <= 30:
            raise ConfigurationError("smoke test interval must be between 0 and 30 seconds")
        if any(
            not value.strip() or any(char.isspace() for char in value)
            for value in self.allowed_health_hosts
        ):
            raise ConfigurationError("allowed health hosts must be non-empty DNS names")


def deploy(
    request: DeploymentRequest,
    *,
    signing_key: bytes | None = None,
    cosign_verification_key: str = "",
    cosign_certificate_identity: str = "",
    cosign_certificate_oidc_issuer: str = "",
    cosign_runner: SigningRunner | None = None,
    result_cosign_signing_key: str = "",
    result_cosign_bundle: Path | None = None,
    result_cosign_runner: SigningRunner | None = None,
    dry_run: bool = False,
    runner: Runner = subprocess.run,
    health_checker: HealthChecker | None = None,
    sleeper: Sleeper = time.sleep,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    request.validate()
    _validate_result_paths(
        request,
        result_cosign_bundle=result_cosign_bundle,
        result_signing_enabled=bool(result_cosign_signing_key),
    )
    if not request.require_signature and not dry_run:
        raise ConfigurationError("unsigned evidence is allowed only for dry-run deployments")
    if not dry_run and not result_cosign_signing_key.strip():
        raise ConfigurationError("actual deployments require a signed deployment result")
    verification = verify_evidence_bundle(
        request.evidence_dir,
        signing_key=signing_key,
        cosign_verification_key=cosign_verification_key,
        cosign_certificate_identity=cosign_certificate_identity,
        cosign_certificate_oidc_issuer=cosign_certificate_oidc_issuer,
        cosign_runner=cosign_runner,
        require_signature=request.require_signature,
    )
    if verification.get("decision") != "pass":
        raise DeploymentError("only a PASS evidence bundle can be deployed")
    verified_policy = verification.get("policy")
    expected_policy = {
        "id": request.expected_policy_id,
        "version": request.expected_policy_version,
    }
    if not isinstance(verified_policy, Mapping) or dict(verified_policy) != expected_policy:
        raise DeploymentError("evidence policy does not match the deployment allowlist")
    if not hmac.compare_digest(
        str(verification.get("policy_sha256", "")), request.expected_policy_sha256
    ):
        raise DeploymentError("evidence policy digest does not match the deployment allowlist")
    policy_path = request.evidence_dir / "inputs/policy.toml"
    try:
        captured_policy = Policy.load(policy_path)
    except ConfigurationError as exc:
        raise DeploymentError("captured evidence policy is invalid") from exc
    if {
        "id": captured_policy.policy_id,
        "version": captured_policy.version,
    } != expected_policy:
        raise DeploymentError("captured policy metadata does not match the deployment allowlist")

    deployment_time = now or dt.datetime.now(dt.UTC)
    if deployment_time.tzinfo is None:
        deployment_time = deployment_time.replace(tzinfo=dt.UTC)
    else:
        deployment_time = deployment_time.astimezone(dt.UTC)
    evidence_time = _evidence_time(verification.get("evaluated_at"))
    clock_skew = dt.timedelta(minutes=captured_policy.provenance.clock_skew_minutes)
    if evidence_time > deployment_time + clock_skew:
        raise DeploymentError("evidence evaluation time is in the future")
    if deployment_time - evidence_time > dt.timedelta(
        hours=captured_policy.change.maximum_evidence_age_hours
    ):
        raise DeploymentError("evidence is older than the deployment policy allows")

    change_id = str(verification.get("change_id", ""))
    if not change_id:
        raise DeploymentError("evidence bundle does not contain a change id")
    change_path = request.evidence_dir / "inputs/change.toml"
    if not change_path.is_file():
        raise DeploymentError("evidence bundle does not contain the change manifest")
    change = ChangeRequest.load(change_path)
    if change.change_id != change_id:
        raise DeploymentError("evidence change id does not match the captured change manifest")
    subject_raw = verification.get("release_subject")
    if not isinstance(subject_raw, dict):
        raise DeploymentError("evidence bundle does not contain a release subject")
    try:
        subject = ReleaseSubject.from_mapping(subject_raw, context="evidence release subject")
        subject.assert_matches_deployment(
            cluster=request.cluster,
            namespace=request.namespace,
            deployment=request.deployment,
            container=request.container,
            image=request.image,
        )
    except ConfigurationError as exc:
        raise DeploymentError(str(exc)) from exc
    if change.release_subject is None:
        raise DeploymentError("change manifest does not contain an approved release subject")
    if change.release_subject.digest != subject.digest:
        raise DeploymentError("evidence release subject does not match the approved change subject")
    if not commit_matches(change.commit_sha, subject.commit_sha):
        raise DeploymentError("release subject commit does not match the change request")
    _validate_healthcheck_target(subject, request.allowed_health_hosts)
    window_start = _as_utc(change.window_start) if change.window_start else None
    window_end = _as_utc(change.window_end) if change.window_end else None
    if not dry_run and (
        window_start is None
        or window_end is None
        or not window_start <= deployment_time <= window_end
    ):
        raise DeploymentError("deployment is outside the approved change window")

    base = [
        "kubectl",
        "--context",
        request.cluster,
        "--namespace",
        request.namespace,
    ]
    set_image = [
        *base,
        "set",
        "image",
        f"deployment/{request.deployment}",
        f"{request.container}={request.image}",
    ]
    annotate = [
        *base,
        "annotate",
        f"deployment/{request.deployment}",
        f"finguard.io/change-id={change_id}",
        f"finguard.io/evidence-sha256={sha256_file(request.evidence_dir / 'manifest.json')}",
        f"finguard.io/release-subject-sha256={subject.digest}",
        "--overwrite",
    ]
    rollout_status = [
        *base,
        "rollout",
        "status",
        f"deployment/{request.deployment}",
        f"--timeout={request.timeout_seconds}s",
    ]
    started_at = dt.datetime.now(dt.UTC)
    record: dict[str, Any] = {
        "schema_version": "2.0",
        "change_id": change_id,
        "policy": expected_policy,
        "policy_sha256": request.expected_policy_sha256,
        "release_subject_sha256": subject.digest,
        "cluster": request.cluster,
        "namespace": request.namespace,
        "deployment": request.deployment,
        "container": request.container,
        "new_image": request.image,
        "evidence_manifest_sha256": sha256_file(request.evidence_dir / "manifest.json"),
        "started_at": started_at.isoformat(),
        "dry_run": dry_run,
        "rollback_performed": False,
        "approved_window": {
            "start": window_start.isoformat() if window_start else None,
            "end": window_end.isoformat() if window_end else None,
        },
        "healthcheck_url": subject.healthcheck_url,
    }
    if dry_run:
        record.update(
            {
                "status": "planned",
                "commands": [set_image, annotate, rollout_status],
                "completed_at": dt.datetime.now(dt.UTC).isoformat(),
            }
        )
        _persist_record(
            request.output,
            record,
            signing_key=result_cosign_signing_key,
            bundle=result_cosign_bundle,
            runner=result_cosign_runner,
            force=request.force_output,
        )
        return record

    preflight = [
        *base,
        "auth",
        "can-i",
        "patch",
        f"deployment/{request.deployment}",
    ]
    current_state_command = [
        *base,
        "get",
        f"deployment/{request.deployment}",
        "-o",
        "json",
    ]
    mutation_attempted = False
    rollback: list[str] = []
    rollback_annotations: list[str] = []
    try:
        authorization = _run(runner, preflight, request.timeout_seconds).stdout.strip().casefold()
        if authorization != "yes":
            raise DeploymentError("kubectl identity cannot patch the target deployment")
        old_image, previous_annotations = _current_deployment_state(
            _run(runner, current_state_command, request.timeout_seconds).stdout,
            container=request.container,
        )
        record["previous_image"] = old_image
        record["previous_audit_annotations"] = {
            key: previous_annotations.get(key) for key in AUDIT_ANNOTATIONS
        }
        rollback = [
            *base,
            "set",
            "image",
            f"deployment/{request.deployment}",
            f"{request.container}={old_image}",
        ]
        rollback_annotations = [
            *base,
            "annotate",
            f"deployment/{request.deployment}",
            *(
                f"{key}={previous_annotations[key]}" if key in previous_annotations else f"{key}-"
                for key in AUDIT_ANNOTATIONS
            ),
            "--overwrite",
        ]
        mutation_attempted = True
        _run(runner, set_image, request.timeout_seconds)
        _run(runner, annotate, request.timeout_seconds)
        _run(runner, rollout_status, request.timeout_seconds)
        attempts_used = _verify_smoke_test(
            subject.healthcheck_url,
            attempts=request.smoke_test_attempts,
            timeout_seconds=request.smoke_test_timeout_seconds,
            interval_seconds=request.smoke_test_interval_seconds,
            checker=health_checker or _http_healthcheck,
            sleeper=sleeper,
        )
        record["smoke_test"] = {
            "status": "passed",
            "attempts": attempts_used,
        }
        record["status"] = "succeeded"
        record["completed_at"] = dt.datetime.now(dt.UTC).isoformat()
        _persist_record(
            request.output,
            record,
            signing_key=result_cosign_signing_key,
            bundle=result_cosign_bundle,
            runner=result_cosign_runner,
            force=request.force_output,
        )
    except (
        subprocess.SubprocessError,
        OSError,
        DeploymentError,
        EvidenceVerificationError,
    ) as exc:
        record["status"] = "failed"
        record["error"] = _safe_error(exc)
        if mutation_attempted:
            try:
                _run(runner, rollback, request.timeout_seconds)
                _run(runner, rollback_annotations, request.timeout_seconds)
                _run(runner, rollout_status, request.timeout_seconds)
                record["rollback_performed"] = True
                record["rollback_status"] = "succeeded"
            except (subprocess.SubprocessError, OSError, DeploymentError) as rollback_error:
                record["rollback_status"] = "failed"
                record["rollback_error"] = _safe_error(rollback_error)
        record["completed_at"] = dt.datetime.now(dt.UTC).isoformat()
        try:
            _persist_record(
                request.output,
                record,
                signing_key=result_cosign_signing_key,
                bundle=result_cosign_bundle,
                runner=result_cosign_runner,
                force=request.force_output,
            )
        except (DeploymentError, EvidenceVerificationError) as record_error:
            raise DeploymentError(
                "deployment failed; rollback status: "
                f"{record.get('rollback_status', 'not-required')}; "
                "deployment result persistence failed"
            ) from record_error
        if not mutation_attempted and isinstance(exc, DeploymentError):
            raise DeploymentError(str(exc)) from exc
        raise DeploymentError(
            f"deployment failed; rollback status: {record.get('rollback_status', 'not-required')}"
        ) from exc
    return record


def _run(runner: Runner, command: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return runner(
        list(command),
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _current_deployment_state(payload: str, *, container: str) -> tuple[str, dict[str, str]]:
    try:
        value = strict_json_loads(payload)
    except ValueError as exc:
        raise DeploymentError("kubectl returned invalid deployment JSON") from exc
    if not isinstance(value, dict):
        raise DeploymentError("kubectl deployment response must be an object")
    metadata = value.get("metadata", {})
    spec = value.get("spec", {})
    if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping):
        raise DeploymentError("kubectl deployment response is missing metadata or spec")
    annotations_raw = metadata.get("annotations", {})
    if annotations_raw is None:
        annotations_raw = {}
    if not isinstance(annotations_raw, Mapping) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in annotations_raw.items()
    ):
        raise DeploymentError("deployment annotations are invalid")
    template = spec.get("template", {})
    if not isinstance(template, Mapping):
        raise DeploymentError("deployment pod template is invalid")
    pod_spec = template.get("spec", {})
    if not isinstance(pod_spec, Mapping):
        raise DeploymentError("deployment pod specification is invalid")
    containers = pod_spec.get("containers")
    if not isinstance(containers, list) or not all(
        isinstance(item, Mapping) for item in containers
    ):
        raise DeploymentError("deployment containers are invalid")
    matches = [item for item in containers if item.get("name") == container]
    if len(matches) != 1:
        raise DeploymentError("target container was not found exactly once in the deployment")
    old_image = matches[0].get("image")
    if not isinstance(old_image, str) or not IMMUTABLE_IMAGE.fullmatch(old_image):
        raise DeploymentError(
            "current deployment image is not immutable; refusing a non-recoverable mutation"
        )
    return old_image, dict(annotations_raw)


def _validate_result_paths(
    request: DeploymentRequest,
    *,
    result_cosign_bundle: Path | None,
    result_signing_enabled: bool,
) -> None:
    if result_cosign_bundle is not None and not result_signing_enabled:
        raise ConfigurationError("deployment result bundle requires a result signing key")
    evidence = request.evidence_dir.expanduser().resolve()
    output = request.output.expanduser()
    assert_no_symlink_components(output, context="deployment result")
    output = output.resolve()
    if output.exists() and not request.force_output:
        raise ConfigurationError(
            "deployment result already exists; choose a unique path or use --force-result"
        )
    if output.exists() and not output.is_file():
        raise ConfigurationError("deployment result output must be a regular file")
    if output == evidence or evidence in output.parents:
        raise ConfigurationError("deployment result must be outside the evidence bundle")
    if result_signing_enabled:
        bundle = (result_cosign_bundle or Path(f"{request.output}.sigstore.json")).expanduser()
        assert_no_symlink_components(bundle, context="deployment result signature")
        bundle = bundle.resolve()
        if bundle.exists() and not request.force_output:
            raise ConfigurationError(
                "deployment result signature already exists; choose a unique path or "
                "use --force-result"
            )
        if bundle.exists() and not bundle.is_file():
            raise ConfigurationError("deployment result signature output must be a regular file")
        if bundle == output:
            raise ConfigurationError("deployment result and signature bundle paths must differ")
        if bundle == evidence or evidence in bundle.parents:
            raise ConfigurationError(
                "deployment result signature must be outside the evidence bundle"
            )


def _write_record(path: Path, record: dict[str, Any]) -> None:
    try:
        atomic_write_text(
            path,
            json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            context="deployment record",
        )
    except ConfigurationError as exc:
        raise DeploymentError(str(exc)) from exc


def _persist_record(
    path: Path,
    record: dict[str, Any],
    *,
    signing_key: str,
    bundle: Path | None,
    runner: SigningRunner | None,
    force: bool,
) -> None:
    _write_record(path, record)
    if not signing_key:
        return
    target_bundle = bundle or Path(f"{path}.sigstore.json")
    if runner is None:
        cosign_sign_blob(path, target_bundle, key=signing_key, force=force)
    else:
        cosign_sign_blob(
            path,
            target_bundle,
            key=signing_key,
            runner=runner,
            force=force,
        )


def _safe_error(error: BaseException) -> str:
    # Do not persist full command output, which can contain cluster or workload data.
    return f"{type(error).__name__}: {str(error)[:300]}"


def _verify_smoke_test(
    url: str,
    *,
    attempts: int,
    timeout_seconds: float,
    interval_seconds: float,
    checker: HealthChecker,
    sleeper: Sleeper,
) -> int:
    for attempt in range(1, attempts + 1):
        try:
            if checker(url, timeout_seconds):
                return attempt
        except (OSError, TimeoutError, ValueError):
            pass
        if attempt < attempts and interval_seconds:
            sleeper(interval_seconds)
    raise DeploymentError("post-deployment smoke test failed")


def _http_healthcheck(url: str, timeout_seconds: float) -> bool:
    request = urllib.request.Request(  # noqa: S310 - URL is bound to the signed release subject
        url,
        headers={"User-Agent": "FinGuard-Deployment-Verifier/1.0"},
    )
    try:
        opener = urllib.request.build_opener(_NoRedirectHandler())
        with opener.open(request, timeout=timeout_seconds) as response:  # noqa: S310
            response.read(4096)
            return 200 <= int(response.status) < 300
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _validate_healthcheck_target(
    subject: ReleaseSubject, additional_allowed_hosts: tuple[str, ...]
) -> None:
    host = (urllib.parse.urlsplit(subject.healthcheck_url).hostname or "").casefold().rstrip(".")
    service = subject.service.casefold()
    namespace = subject.namespace.casefold()
    allowed = {
        service,
        f"{service}.{namespace}",
        f"{service}.{namespace}.svc",
        f"{service}.{namespace}.svc.cluster.local",
        *(value.casefold().rstrip(".") for value in additional_allowed_hosts),
    }
    if host not in allowed:
        raise DeploymentError("healthcheck host is not in the independent deployment allowlist")


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC)


def _evidence_time(value: object) -> dt.datetime:
    if not isinstance(value, str):
        raise DeploymentError("evidence evaluation time is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DeploymentError("evidence evaluation time is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DeploymentError("evidence evaluation time needs a timezone")
    return parsed.astimezone(dt.UTC)
