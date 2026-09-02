from __future__ import annotations

import datetime as dt
import hashlib
import json
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from finguard.change import ChangeRequest
from finguard.config import Policy
from finguard.deployment import (
    DeploymentRequest,
    _current_deployment_state,
    _http_healthcheck,
    _validate_healthcheck_target,
    _validate_result_paths,
    deploy,
)
from finguard.errors import ConfigurationError, DeploymentError
from finguard.evidence import create_evidence_bundle
from finguard.gate import PolicyEngine
from finguard.parsers import discover_reports, parse_report
from finguard.release import ReleaseSubject


def _deployment_state(
    image: str = "registry.example/credit/api@sha256:" + "b" * 64,
    *,
    annotations: dict[str, str] | None = None,
) -> str:
    return json.dumps(
        {
            "metadata": {"annotations": annotations or {}},
            "spec": {"template": {"spec": {"containers": [{"name": "api", "image": image}]}}},
        }
    )


def _successful_signer(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    bundle = Path(command[command.index("--bundle") + 1])
    bundle.write_text('{"verificationMaterial": {}}\n', encoding="utf-8")
    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


def _evidence(project_root: Path, tmp_path: Path) -> tuple[Path, bytes]:
    scenario = project_root / "examples/scenarios/pass"
    report_paths = discover_reports(scenario / "reports")
    policy_path = project_root / "policies/financial-baseline.toml"
    policy = Policy.load(policy_path)
    result = PolicyEngine(policy).evaluate(
        [parse_report(path) for path in report_paths],
        change=ChangeRequest.load(scenario / "change.toml"),
        release_subject=ReleaseSubject.load(scenario / "release-subject.json"),
        now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    )
    output = tmp_path / "evidence"
    key = b"deployment-test-key"
    create_evidence_bundle(
        output,
        result=result,
        policy_path=policy_path,
        report_paths=report_paths,
        change_path=scenario / "change.toml",
        signing_key=key,
    )
    return output, key


def _request(evidence: Path, tmp_path: Path) -> DeploymentRequest:
    return DeploymentRequest(
        cluster="onprem-prod-01",
        namespace="credit-prod",
        deployment="customer-credit-api",
        container="api",
        image="registry.example/credit/api@sha256:" + "a" * 64,
        expected_policy_id="FIN-SW-DEVSECOPS-BASELINE",
        expected_policy_version="5.1.1",
        expected_policy_sha256=hashlib.sha256(
            (evidence / "inputs/policy.toml").read_bytes()
        ).hexdigest(),
        evidence_dir=evidence,
        output=tmp_path / "deployment.json",
    )


def test_dry_run_verifies_evidence_and_plans_commands(project_root: Path, tmp_path: Path) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    result = deploy(
        request,
        signing_key=key,
        dry_run=True,
        now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
    )
    assert result["status"] == "planned"
    assert result["change_id"] == "CB-2026-0107"
    assert result["commands"][0][5:8] == ["set", "image", "deployment/customer-credit-api"]


def test_mutable_image_reference_is_rejected(project_root: Path, tmp_path: Path) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    request = DeploymentRequest(**{**request.__dict__, "image": "registry.example/api:latest"})
    with pytest.raises(ConfigurationError, match="immutable"):
        deploy(request, signing_key=key, dry_run=True)


def test_deployment_request_operational_bounds_fail_closed(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, _ = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    invalid = [
        replace(request, cluster=""),
        replace(request, namespace="INVALID"),
        replace(request, expected_policy_id=" BASELINE"),
        replace(request, expected_policy_sha256="A" * 64),
        replace(request, timeout_seconds=9),
        replace(request, smoke_test_attempts=0),
        replace(request, smoke_test_timeout_seconds=0),
        replace(request, smoke_test_interval_seconds=-1),
        replace(request, allowed_health_hosts=("bad host",)),
    ]

    for candidate in invalid:
        with pytest.raises(ConfigurationError):
            candidate.validate()


def test_kubectl_state_shape_failures_are_rejected() -> None:
    invalid = [
        "not-json",
        "[]",
        json.dumps({"metadata": [], "spec": {}}),
        json.dumps({"metadata": {"annotations": []}, "spec": {}}),
        json.dumps({"metadata": {}, "spec": {"template": []}}),
        json.dumps({"metadata": {}, "spec": {"template": {"spec": []}}}),
        json.dumps({"metadata": {}, "spec": {"template": {"spec": {"containers": {}}}}}),
        json.dumps({"metadata": {}, "spec": {"template": {"spec": {"containers": []}}}}),
    ]

    for payload in invalid:
        with pytest.raises(DeploymentError):
            _current_deployment_state(payload, container="api")


def test_deployment_result_path_combinations_fail_closed(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, _ = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)

    with pytest.raises(ConfigurationError, match="requires a result signing key"):
        _validate_result_paths(
            request,
            result_cosign_bundle=tmp_path / "unexpected.sigstore.json",
            result_signing_enabled=False,
        )

    output_directory = tmp_path / "result-directory"
    output_directory.mkdir()
    with pytest.raises(ConfigurationError, match="regular file"):
        _validate_result_paths(
            replace(request, output=output_directory, force_output=True),
            result_cosign_bundle=None,
            result_signing_enabled=False,
        )

    bundle_directory = tmp_path / "bundle-directory"
    bundle_directory.mkdir()
    with pytest.raises(ConfigurationError, match="signature output must be a regular file"):
        _validate_result_paths(
            replace(request, output=tmp_path / "result-2.json", force_output=True),
            result_cosign_bundle=bundle_directory,
            result_signing_enabled=True,
        )

    same_path = tmp_path / "same.json"
    with pytest.raises(ConfigurationError, match="paths must differ"):
        _validate_result_paths(
            replace(request, output=same_path),
            result_cosign_bundle=same_path,
            result_signing_enabled=True,
        )

    with pytest.raises(ConfigurationError, match="signature must be outside"):
        _validate_result_paths(
            replace(request, output=tmp_path / "result-3.json"),
            result_cosign_bundle=evidence / "result.sigstore.json",
            result_signing_enabled=True,
        )


def test_deployment_rejects_pass_evidence_from_a_different_policy(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = replace(
        _request(evidence, tmp_path),
        expected_policy_id="FIN-SW-DEVSECOPS-RELEASE",
    )

    with pytest.raises(DeploymentError, match="policy does not match"):
        deploy(request, signing_key=key, dry_run=True)

    digest_mismatch = replace(
        _request(evidence, tmp_path),
        expected_policy_sha256="0" * 64,
    )
    with pytest.raises(DeploymentError, match="policy digest does not match"):
        deploy(digest_mismatch, signing_key=key, dry_run=True)


def test_deployment_rejects_policy_file_metadata_inconsistent_with_manifest(
    project_root: Path, tmp_path: Path
) -> None:
    scenario = project_root / "examples/scenarios/pass"
    reports = discover_reports(scenario / "reports")
    baseline = Policy.load(project_root / "policies/financial-baseline.toml")
    result = PolicyEngine(baseline).evaluate(
        [parse_report(path) for path in reports],
        change=ChangeRequest.load(scenario / "change.toml"),
        release_subject=ReleaseSubject.load(scenario / "release-subject.json"),
        now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    )
    mismatched_policy = project_root / "policies/merge-request.toml"
    evidence = tmp_path / "mismatched-policy-evidence"
    key = b"deployment-test-key"
    create_evidence_bundle(
        evidence,
        result=result,
        policy_path=mismatched_policy,
        report_paths=reports,
        change_path=scenario / "change.toml",
        signing_key=key,
    )
    request = replace(
        _request(evidence, tmp_path),
        expected_policy_sha256=hashlib.sha256(mismatched_policy.read_bytes()).hexdigest(),
    )

    with pytest.raises(DeploymentError, match="captured policy metadata"):
        deploy(request, signing_key=key, dry_run=True)


def test_failed_rollout_triggers_rollback(project_root: Path, tmp_path: Path) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    calls: list[list[str]] = []
    status_calls = 0

    def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal status_calls
        calls.append(command)
        if "can-i" in command:
            return subprocess.CompletedProcess(command, 0, stdout="yes\n", stderr="")
        if "get" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=_deployment_state(
                    annotations={
                        "finguard.io/change-id": "CB-PREVIOUS",
                        "finguard.io/evidence-sha256": "previous-evidence",
                    }
                ),
                stderr="",
            )
        if "status" in command:
            status_calls += 1
            if status_calls == 1:
                raise subprocess.CalledProcessError(1, command, stderr="rollout timeout")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    with pytest.raises(DeploymentError, match="rollback status: succeeded"):
        deploy(
            request,
            signing_key=key,
            runner=runner,
            result_cosign_signing_key="kms://deployment-audit",
            result_cosign_runner=_successful_signer,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )
    record = request.output.read_text(encoding="utf-8")
    assert '"rollback_performed": true' in record
    assert any(
        "set" in command and f"api=registry.example/credit/api@sha256:{'b' * 64}" in command
        for command in calls
    )
    assert any(
        "annotate" in command
        and "finguard.io/change-id=CB-PREVIOUS" in command
        and "finguard.io/evidence-sha256=previous-evidence" in command
        and "finguard.io/release-subject-sha256-" in command
        for command in calls
    )
    rollback_annotation = next(
        command
        for command in calls
        if "annotate" in command and "finguard.io/change-id=CB-PREVIOUS" in command
    )
    assert rollback_annotation == [
        "kubectl",
        "--context",
        "onprem-prod-01",
        "--namespace",
        "credit-prod",
        "annotate",
        "deployment/customer-credit-api",
        "finguard.io/change-id=CB-PREVIOUS",
        "finguard.io/evidence-sha256=previous-evidence",
        "finguard.io/release-subject-sha256-",
        "--overwrite",
    ]


def test_actual_deployment_outside_approved_window_is_rejected(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    with pytest.raises(DeploymentError, match="approved change window"):
        deploy(
            request,
            signing_key=key,
            result_cosign_signing_key="kms://deployment-audit",
            now=dt.datetime(2026, 9, 1, 15, 0, tzinfo=dt.UTC),
        )


def test_post_deployment_smoke_failure_triggers_rollback(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    calls: list[list[str]] = []

    def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "can-i" in command:
            return subprocess.CompletedProcess(command, 0, stdout="yes\n", stderr="")
        if "get" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=_deployment_state(),
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    with pytest.raises(DeploymentError, match="rollback status: succeeded"):
        deploy(
            request,
            signing_key=key,
            runner=runner,
            health_checker=lambda url, timeout: False,
            sleeper=lambda seconds: None,
            result_cosign_signing_key="kms://deployment-audit",
            result_cosign_runner=_successful_signer,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )
    record = request.output.read_text(encoding="utf-8")
    assert "post-deployment smoke test failed" in record
    assert any(
        "set" in command and f"api=registry.example/credit/api@sha256:{'b' * 64}" in command
        for command in calls
    )


def test_successful_rollout_records_smoke_verification(project_root: Path, tmp_path: Path) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)

    def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "can-i" in command:
            return subprocess.CompletedProcess(command, 0, stdout="yes\n", stderr="")
        if "get" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=_deployment_state(),
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = deploy(
        request,
        signing_key=key,
        runner=runner,
        health_checker=lambda url, timeout: True,
        result_cosign_signing_key="kms://deployment-audit",
        result_cosign_runner=_successful_signer,
        now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
    )
    assert result["status"] == "succeeded"
    assert result["smoke_test"] == {"status": "passed", "attempts": 1}


def test_deployment_result_signing_failure_triggers_rollback(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    calls: list[list[str]] = []

    def kubectl_runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "can-i" in command:
            return subprocess.CompletedProcess(command, 0, stdout="yes\n", stderr="")
        if "get" in command:
            return subprocess.CompletedProcess(command, 0, stdout=_deployment_state(), stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def failed_signer(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(1, command, stderr="signer unavailable")

    with pytest.raises(DeploymentError, match="rollback status: succeeded"):
        deploy(
            request,
            signing_key=key,
            runner=kubectl_runner,
            health_checker=lambda url, timeout: True,
            result_cosign_signing_key="kms://deployment-audit",
            result_cosign_runner=failed_signer,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )

    assert any(
        "set" in command and f"api=registry.example/credit/api@sha256:{'b' * 64}" in command
        for command in calls
    )
    record = json.loads(request.output.read_text(encoding="utf-8"))
    assert record["status"] == "failed"
    assert record["rollback_status"] == "succeeded"


def test_actual_deployment_never_allows_unsigned_evidence(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, _ = _evidence(project_root, tmp_path)
    request = replace(_request(evidence, tmp_path), require_signature=False)

    with pytest.raises(ConfigurationError, match="only for dry-run"):
        deploy(request, dry_run=False)


def test_actual_deployment_requires_a_signed_result(project_root: Path, tmp_path: Path) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)

    with pytest.raises(ConfigurationError, match="signed deployment result"):
        deploy(
            request,
            signing_key=key,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )


@pytest.mark.parametrize(
    ("deployment_time", "message"),
    [
        (dt.datetime(2026, 9, 3, tzinfo=dt.UTC), "older than"),
        (dt.datetime(2026, 8, 31, 23, 50, tzinfo=dt.UTC), "in the future"),
    ],
)
def test_deployment_rejects_stale_or_future_evidence(
    project_root: Path,
    tmp_path: Path,
    deployment_time: dt.datetime,
    message: str,
) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)

    with pytest.raises(DeploymentError, match=message):
        deploy(
            request,
            signing_key=key,
            result_cosign_signing_key="kms://deployment-audit",
            now=deployment_time,
        )


def test_uncertain_set_image_failure_still_triggers_exact_rollback(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    calls: list[list[str]] = []
    failed_new_image = False

    def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal failed_new_image
        calls.append(command)
        if "can-i" in command:
            return subprocess.CompletedProcess(command, 0, stdout="yes\n", stderr="")
        if "get" in command:
            return subprocess.CompletedProcess(command, 0, stdout=_deployment_state(), stderr="")
        if (
            "set" in command
            and f"api=registry.example/credit/api@sha256:{'a' * 64}" in command
            and not failed_new_image
        ):
            failed_new_image = True
            raise subprocess.CalledProcessError(1, command, stderr="connection reset")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    with pytest.raises(DeploymentError, match="rollback status: succeeded"):
        deploy(
            request,
            signing_key=key,
            runner=runner,
            result_cosign_signing_key="kms://deployment-audit",
            result_cosign_runner=_successful_signer,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )

    assert any(
        "set" in command and f"api=registry.example/credit/api@sha256:{'b' * 64}" in command
        for command in calls
    )
    assert '"rollback_performed": true' in request.output.read_text(encoding="utf-8")


def test_deployment_result_cannot_modify_evidence_bundle(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = replace(_request(evidence, tmp_path), output=evidence / "deployment.json")

    with pytest.raises(ConfigurationError, match="outside the evidence bundle"):
        deploy(request, signing_key=key, dry_run=True)


def test_deployment_refuses_to_overwrite_an_existing_audit_record(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    request.output.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="already exists"):
        deploy(request, signing_key=key, dry_run=True)

    assert request.output.read_text(encoding="utf-8") == "preserve\n"


def test_mutation_is_refused_when_previous_image_is_not_immutable(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    calls: list[list[str]] = []

    def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "can-i" in command:
            return subprocess.CompletedProcess(command, 0, stdout="yes\n", stderr="")
        if "get" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=_deployment_state("registry.example/credit/api:mutable"),
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    with pytest.raises(DeploymentError, match="current deployment image is not immutable"):
        deploy(
            request,
            signing_key=key,
            runner=runner,
            result_cosign_signing_key="kms://deployment-audit",
            result_cosign_runner=_successful_signer,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )
    assert not any("set" in command and "image" in command for command in calls)


def test_healthcheck_host_requires_independent_allowlist(project_root: Path) -> None:
    subject = ReleaseSubject.load(project_root / "examples/scenarios/pass/release-subject.json")
    external = replace(subject, healthcheck_url="https://health.example/ready")

    with pytest.raises(DeploymentError, match="independent deployment allowlist"):
        _validate_healthcheck_target(external, ())
    _validate_healthcheck_target(external, ("health.example",))


def test_http_healthcheck_does_not_accept_redirect_status(monkeypatch) -> None:
    class Response:
        status = 302

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            return b"redirect"

    class Opener:
        def open(self, request: object, timeout: float) -> Response:
            return Response()

    monkeypatch.setattr("urllib.request.build_opener", lambda *handlers: Opener())
    assert _http_healthcheck("https://service.example/health", 1.0) is False
