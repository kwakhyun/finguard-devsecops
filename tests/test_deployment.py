from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import signal
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
from finguard.deployment_guard import DEPLOYMENT_LOCK_ANNOTATION
from finguard.deployment_records import DeploymentRecords
from finguard.deployment_signals import DeploymentInterrupted
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
            "metadata": {
                "uid": "deployment-uid",
                "resourceVersion": "1",
                "annotations": annotations or {},
            },
            "spec": {"template": {"spec": {"containers": [{"name": "api", "image": image}]}}},
        }
    )


class FakeKubernetes:
    """A stateful API double: JSON Patch tests execute atomically on live state."""

    def __init__(self, *, annotations=None, before=None, after=None):
        self.state = json.loads(_deployment_state(annotations=annotations))
        self.calls = []
        self.before = before
        self.after = after

    @property
    def image(self):
        return self.state["spec"]["template"]["spec"]["containers"][0]["image"]

    @image.setter
    def image(self, value):
        self.state["spec"]["template"]["spec"]["containers"][0]["image"] = value
        self.tick()

    def tick(self):
        self.state["metadata"]["resourceVersion"] = str(
            int(self.state["metadata"]["resourceVersion"]) + 1
        )

    @staticmethod
    def operations(command):
        return json.loads(command[command.index("-p") + 1]) if "-p" in command else []

    @classmethod
    def changes_image(cls, command):
        return any(
            op["op"] == "replace" and op["path"].endswith("/image")
            for op in cls.operations(command)
        )

    @property
    def image_patches(self):
        return [command for command in self.calls if self.changes_image(command)]

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        if self.before:
            self.before(self, command)
        stdout = ""
        if "can-i" in command:
            stdout = "yes"
        elif "get" in command:
            stdout = json.dumps(self.state)
        elif "patch" in command:
            candidate = copy.deepcopy(self.state)
            try:
                for operation in self.operations(command):
                    parts = [
                        part.replace("~1", "/").replace("~0", "~")
                        for part in operation["path"].split("/")[1:]
                    ]
                    parent = candidate
                    for part in parts[:-1]:
                        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
                    key = int(parts[-1]) if isinstance(parent, list) else parts[-1]
                    if operation["op"] == "test":
                        if parent[key] != operation["value"]:
                            raise ValueError("JSON Patch test failed")
                    elif operation["op"] == "remove":
                        del parent[key]
                    else:
                        if (
                            operation["op"] == "replace"
                            and key not in parent
                            and not isinstance(parent, list)
                        ):
                            raise ValueError("replace path does not exist")
                        parent[key] = operation["value"]
            except (KeyError, IndexError, ValueError) as exc:
                raise subprocess.CalledProcessError(1, command, stderr=str(exc)) from exc
            self.state = candidate
            self.tick()
        if self.after:
            self.after(self, command)
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


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
    assert result["commands"][0][5:7] == ["get", "deployment/customer-credit-api"]
    assert result["lock_annotation"] == DEPLOYMENT_LOCK_ANNOTATION


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
    previous = {
        "finguard.io/change-id": "CB-PREVIOUS",
        "finguard.io/evidence-sha256": "previous-evidence",
        "unrelated-controller": "preserved",
    }
    status_calls = 0

    def before(api, command):
        nonlocal status_calls
        if "status" in command:
            status_calls += 1
            if status_calls == 1:
                raise subprocess.CalledProcessError(1, command, stderr="rollout timeout")

    runner = FakeKubernetes(annotations=previous, before=before)
    with pytest.raises(DeploymentError, match="rollback status: succeeded"):
        deploy(
            request,
            signing_key=key,
            runner=runner,
            result_cosign_signing_key="kms://deployment-audit",
            result_cosign_runner=_successful_signer,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )
    record = json.loads(request.output.read_text())
    assert record["rollback_performed"] is True
    assert runner.image.endswith("b" * 64)
    assert runner.state["metadata"]["annotations"] == previous
    assert len(runner.image_patches) == 2


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
    runner = FakeKubernetes()
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
    assert "post-deployment smoke test failed" in request.output.read_text()
    assert runner.image.endswith("b" * 64)
    assert len(runner.image_patches) == 2


def test_successful_rollout_records_smoke_verification(project_root: Path, tmp_path: Path) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    runner = FakeKubernetes()
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
    assert runner.image == request.image
    assert DEPLOYMENT_LOCK_ANNOTATION not in runner.state["metadata"]["annotations"]


def test_deployment_result_signing_failure_triggers_rollback(
    project_root: Path, tmp_path: Path
) -> None:
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    runner = FakeKubernetes()

    def failed_signer(command, **kwargs):
        raise subprocess.CalledProcessError(1, command, stderr="signer unavailable")

    with pytest.raises(DeploymentError, match="rollback status: succeeded"):
        deploy(
            request,
            signing_key=key,
            runner=runner,
            health_checker=lambda url, timeout: True,
            result_cosign_signing_key="kms://deployment-audit",
            result_cosign_runner=failed_signer,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )
    assert runner.image.endswith("b" * 64)
    assert len(runner.image_patches) == 2
    assert not request.output.exists()
    assert not Path(f"{request.output}.sigstore.json").exists()
    record = json.loads(Path(f"{request.output}.recovery.json").read_text())
    assert record["record_kind"] == "unsigned-recovery-journal"
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
    failed = False

    def after(api, command):
        nonlocal failed
        if api.changes_image(command) and not failed:
            failed = True
            raise subprocess.CalledProcessError(1, command, stderr="connection reset after apply")

    runner = FakeKubernetes(after=after)
    with pytest.raises(DeploymentError, match="rollback status: succeeded"):
        deploy(
            request,
            signing_key=key,
            runner=runner,
            result_cosign_signing_key="kms://deployment-audit",
            result_cosign_runner=_successful_signer,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )
    assert runner.image.endswith("b" * 64)
    assert len(runner.image_patches) == 2
    assert json.loads(request.output.read_text())["rollback_performed"] is True


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


@pytest.mark.parametrize("stop", ["keyboard", "sigint", "sigterm"])
def test_interrupt_restores_image_and_records_recovery(project_root, tmp_path, stop):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    interrupted = False
    previous_handler = signal.getsignal(signal.SIGTERM)

    def before(api, command):
        nonlocal interrupted
        if api.changes_image(command) and not interrupted:
            journal = json.loads(Path(f"{request.output}.recovery.json").read_text())
            assert journal["previous_image"].endswith("b" * 64)
            assert journal["status"] == "prepared"
        if "status" in command and not interrupted:
            interrupted = True
            if stop == "keyboard":
                raise KeyboardInterrupt()
            os.kill(os.getpid(), signal.SIGTERM if stop == "sigterm" else signal.SIGINT)
        elif "status" in command:
            os.kill(os.getpid(), signal.SIGTERM)

    runner = FakeKubernetes(before=before)
    with pytest.raises(KeyboardInterrupt) as stopped:
        deploy(
            request,
            signing_key=key,
            runner=runner,
            result_cosign_signing_key="test-key",
            result_cosign_runner=_successful_signer,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )
    if stop != "keyboard":
        assert isinstance(stopped.value, DeploymentInterrupted)
        assert stopped.value.signum == (signal.SIGTERM if stop == "sigterm" else signal.SIGINT)
    result = json.loads(request.output.read_text())
    assert result["status"] == "interrupted"
    assert result["rollback_status"] == "succeeded"
    assert len(runner.image_patches) == 2
    assert runner.image.endswith("b" * 64)
    assert DEPLOYMENT_LOCK_ANNOTATION not in runner.state["metadata"]["annotations"]
    assert signal.getsignal(signal.SIGTERM) == previous_handler
    assert not list(tmp_path.glob(".*.finguard-lock"))


def test_concurrent_result_writer_is_preserved_and_deployment_rolled_back(project_root, tmp_path):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)

    def before(api, command):
        if "status" in command:
            request.output.write_text("another writer's audit record\n")

    runner = FakeKubernetes(before=before)
    with pytest.raises(DeploymentError, match="rollback status: succeeded"):
        deploy(
            request,
            signing_key=key,
            runner=runner,
            health_checker=lambda *args: True,
            result_cosign_signing_key="test-key",
            result_cosign_runner=_successful_signer,
            now=dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
        )
    assert request.output.read_text() == "another writer's audit record\n"
    assert len(runner.image_patches) == 2
    assert runner.image.endswith("b" * 64)
    assert not Path(f"{request.output}.sigstore.json").exists()
    assert json.loads(Path(f"{request.output}.recovery.json").read_text())["rollback_performed"]


@pytest.mark.parametrize("force", [False, True])
def test_result_reservation_excludes_second_deployment(tmp_path, force):
    output = tmp_path / "result.json"
    with DeploymentRecords(output, signing_key="", bundle=None, runner=None, force=False):
        with pytest.raises(ConfigurationError, match="reserved"):
            with DeploymentRecords(output, signing_key="", bundle=None, runner=None, force=force):
                pytest.fail("second deployment acquired the same destination")
    assert not list(tmp_path.glob(".*.finguard-lock"))


def test_publish_conflict_removes_only_our_signature(tmp_path, monkeypatch):
    output = tmp_path / "result.json"
    original_link = os.link

    def competing_link(source, target, **kwargs):
        if Path(target) == output:
            output.write_text("concurrent result")
        return original_link(source, target, **kwargs)

    monkeypatch.setattr(os, "link", competing_link)
    with DeploymentRecords(
        output, signing_key="test", bundle=None, runner=_successful_signer, force=False
    ) as records:
        with pytest.raises(DeploymentError, match="cannot publish"):
            records.persist({"status": "succeeded"})
    assert output.read_text() == "concurrent result"
    assert not Path(f"{output}.sigstore.json").exists()


def test_signature_preparation_failure_keeps_existing_pair(tmp_path):
    output = tmp_path / "result.json"
    bundle = tmp_path / "signature.json"
    output.write_text("old result")
    bundle.write_text("old signature")

    def failed_signer(command, **kwargs):
        assert output.read_text() == "old result"
        assert bundle.read_text() == "old signature"
        raise subprocess.CalledProcessError(1, command)

    from finguard.errors import EvidenceVerificationError

    with DeploymentRecords(
        output, signing_key="test", bundle=bundle, runner=failed_signer, force=True
    ) as records:
        with pytest.raises(EvidenceVerificationError):
            records.persist({"status": "succeeded"})
    assert output.read_text() == "old result"
    assert bundle.read_text() == "old signature"


def _execute(request, key, runner, **overrides):
    arguments = {
        "signing_key": key,
        "runner": runner,
        "health_checker": lambda *args: True,
        "result_cosign_signing_key": "test-key",
        "result_cosign_runner": _successful_signer,
        "now": dt.datetime(2026, 9, 1, 13, 30, tzinfo=dt.UTC),
    }
    arguments.update(overrides)
    return deploy(request, **arguments)


def test_target_lock_blocks_another_output_path(project_root, tmp_path):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    second = replace(request, output=tmp_path / "another-ci" / "result.json")
    attempted = False

    def before(api, command):
        nonlocal attempted
        if "status" in command and not attempted:
            attempted = True
            owner = api.state["metadata"]["annotations"][DEPLOYMENT_LOCK_ANNOTATION]
            with pytest.raises(DeploymentError, match="deployment target is locked"):
                _execute(second, key, api)
            assert api.state["metadata"]["annotations"][DEPLOYMENT_LOCK_ANNOTATION] == owner

    runner = FakeKubernetes(before=before)
    assert _execute(request, key, runner)["status"] == "succeeded"
    assert attempted
    assert len(runner.image_patches) == 1
    assert runner.image == request.image
    assert json.loads(second.output.read_text())["status"] == "failed"
    assert DEPLOYMENT_LOCK_ANNOTATION not in runner.state["metadata"]["annotations"]


@pytest.mark.parametrize("fail_rollout", [False, True])
@pytest.mark.parametrize("external_change", ["image", "template", "uid", "owner", "audit"])
def test_external_changes_are_not_reported_as_success_or_overwritten(
    project_root, tmp_path, fail_rollout, external_change
):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    changed = False
    expected = None

    def before(api, command):
        nonlocal changed, expected
        if "status" in command and not changed:
            changed = True
            if external_change == "image":
                api.image = "registry.example/credit/api@sha256:" + "c" * 64
            elif external_change == "template":
                api.state["spec"]["template"]["spec"]["containers"][0]["env"] = [
                    {"name": "OTHER_RELEASE", "value": "true"}
                ]
            elif external_change == "uid":
                api.state["metadata"]["uid"] = "replacement-object"
            elif external_change == "owner":
                api.state["metadata"]["annotations"][DEPLOYMENT_LOCK_ANNOTATION] = "other-owner"
            else:
                api.state["metadata"]["annotations"]["finguard.io/change-id"] = "CB-OTHER"
            expected = copy.deepcopy(api.state)
            if fail_rollout:
                raise subprocess.CalledProcessError(1, command)

    runner = FakeKubernetes(before=before)
    with pytest.raises(DeploymentError, match="rollback status: skipped-conflict"):
        _execute(request, key, runner)
    record = json.loads(request.output.read_text())
    assert record["status"] == "failed"
    assert record["rollback_performed"] is False
    assert len(runner.image_patches) == 1
    assert runner.state["spec"] == expected["spec"]
    assert runner.state["metadata"]["uid"] == expected["metadata"]["uid"]
    assert runner.state["metadata"]["annotations"].get("finguard.io/change-id") == (
        expected["metadata"]["annotations"].get("finguard.io/change-id")
    )
    if external_change in {"owner", "uid"}:
        assert (
            runner.state["metadata"]["annotations"][DEPLOYMENT_LOCK_ANNOTATION]
            == (expected["metadata"]["annotations"][DEPLOYMENT_LOCK_ANNOTATION])
        )
    else:
        assert DEPLOYMENT_LOCK_ANNOTATION not in runner.state["metadata"]["annotations"]


def test_atomic_rollback_rejects_change_after_its_read(project_root, tmp_path):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    competitor = "registry.example/credit/api@sha256:" + "c" * 64

    def before(api, command):
        if "status" in command:
            raise subprocess.CalledProcessError(1, command)
        if api.changes_image(command) and len(api.image_patches) == 2:
            api.image = competitor

    runner = FakeKubernetes(before=before)
    with pytest.raises(DeploymentError, match="rollback status: skipped-conflict"):
        _execute(request, key, runner)
    assert runner.image == competitor
    assert json.loads(request.output.read_text())["rollback_performed"] is False


@pytest.mark.parametrize("existing_audit", [False, True])
def test_new_or_changed_audit_annotation_cannot_be_overwritten(
    project_root, tmp_path, existing_audit
):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    original = {"finguard.io/change-id": "CB-OLD"} if existing_audit else {}

    def before(api, command):
        if api.changes_image(command):
            api.state["metadata"]["annotations"]["finguard.io/change-id"] = "CB-OTHER"
            api.tick()

    runner = FakeKubernetes(annotations=original, before=before)
    with pytest.raises(DeploymentError, match="rollback status: skipped-conflict"):
        _execute(request, key, runner)
    assert runner.image.endswith("b" * 64)
    assert runner.state["metadata"]["annotations"]["finguard.io/change-id"] == "CB-OTHER"


def test_controller_updates_do_not_break_owned_mutation_or_rollback(project_root, tmp_path):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    acquisition_conflict = False
    annotation_conflict = False
    rollouts = 0

    def before(api, command):
        nonlocal acquisition_conflict, annotation_conflict, rollouts
        operations = api.operations(command)
        if any(op["path"] == "/metadata/resourceVersion" for op in operations):
            if not acquisition_conflict:
                acquisition_conflict = True
                api.tick()
        if api.changes_image(command):
            api.tick()  # Status writes must not invalidate the image precondition.
            if not annotation_conflict:
                annotation_conflict = True
                api.state["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = "2"
        if "status" in command:
            api.tick()
            api.state["status"] = {"readyReplicas": 2}
            api.state["spec"]["replicas"] = 2  # HPA updates are outside the owned template.
            rollouts += 1
            if rollouts == 1:
                raise subprocess.CalledProcessError(1, command)

    runner = FakeKubernetes(before=before)
    with pytest.raises(DeploymentError, match="rollback status: succeeded"):
        _execute(request, key, runner)
    assert acquisition_conflict and annotation_conflict
    assert runner.image.endswith("b" * 64)
    assert runner.state["metadata"]["annotations"]["deployment.kubernetes.io/revision"] == "2"
    assert runner.state["spec"]["replicas"] == 2
    assert DEPLOYMENT_LOCK_ANNOTATION not in runner.state["metadata"]["annotations"]


def test_lock_acquisition_with_lost_response_retains_one_owner(project_root, tmp_path):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    failed = False

    def after(api, command):
        nonlocal failed
        if not failed and any(
            op["path"] == "/metadata/resourceVersion" for op in api.operations(command)
        ):
            failed = True
            raise subprocess.CalledProcessError(1, command, stderr="response lost")

    runner = FakeKubernetes(after=after)
    assert _execute(request, key, runner)["status"] == "succeeded"
    assert len(runner.image_patches) == 1
    assert DEPLOYMENT_LOCK_ANNOTATION not in runner.state["metadata"]["annotations"]


def test_existing_stale_lock_is_not_taken_over(project_root, tmp_path):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    runner = FakeKubernetes(annotations={DEPLOYMENT_LOCK_ANNOTATION: "stopped-owner"})
    with pytest.raises(DeploymentError, match="deployment target is locked"):
        _execute(request, key, runner)
    assert not runner.image_patches
    assert runner.state["metadata"]["annotations"][DEPLOYMENT_LOCK_ANNOTATION] == "stopped-owner"


def test_final_state_is_checked_after_signing_before_publication(project_root, tmp_path):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    runner = FakeKubernetes()
    competitor = "registry.example/credit/api@sha256:" + "c" * 64

    def signer(command, **kwargs):
        runner.image = competitor
        return _successful_signer(command, **kwargs)

    with pytest.raises(DeploymentError, match="rollback status: skipped-conflict"):
        _execute(request, key, runner, result_cosign_runner=signer)
    assert runner.image == competitor
    assert json.loads(request.output.read_text())["status"] == "failed"


def test_sigterm_after_success_publication_does_not_contradict_result(
    project_root, tmp_path, monkeypatch
):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    runner = FakeKubernetes()
    original = DeploymentRecords.persist

    def publish_then_signal(self, record, **kwargs):
        original(self, record, **kwargs)
        if record["status"] == "succeeded":
            os.kill(os.getpid(), signal.SIGTERM)

    monkeypatch.setattr(DeploymentRecords, "persist", publish_then_signal)
    result = _execute(request, key, runner)
    assert result["status"] == "succeeded"
    assert runner.image == request.image
    assert len(runner.image_patches) == 1
    assert json.loads(request.output.read_text())["status"] == "succeeded"
    assert Path(f"{request.output}.sigstore.json").is_file()
    assert DEPLOYMENT_LOCK_ANNOTATION not in runner.state["metadata"]["annotations"]


@pytest.mark.parametrize("original_failure", [False, True])
def test_target_lock_release_failure_preserves_recorded_outcome(
    project_root, tmp_path, original_failure
):
    evidence, key = _evidence(project_root, tmp_path)
    request = _request(evidence, tmp_path)
    rollouts = 0

    def before(api, command):
        nonlocal rollouts
        if "status" in command:
            rollouts += 1
            if original_failure and rollouts == 1:
                raise subprocess.CalledProcessError(1, command)
        if any(
            op["op"] == "remove" and op["path"].endswith("deployment-lock")
            for op in api.operations(command)
        ):
            raise subprocess.CalledProcessError(1, command, stderr="release rejected")

    runner = FakeKubernetes(before=before)
    message = "rollback status: succeeded" if original_failure else "target lock release failed"
    with pytest.raises(DeploymentError, match=message):
        _execute(request, key, runner)
    record = json.loads(request.output.read_text())
    assert record["status"] == ("failed" if original_failure else "succeeded")
    assert runner.image.endswith(("b" if original_failure else "a") * 64)
    assert DEPLOYMENT_LOCK_ANNOTATION in runner.state["metadata"]["annotations"]
