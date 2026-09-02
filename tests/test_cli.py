from __future__ import annotations

import datetime as dt
import hashlib
import json
import tomllib
from pathlib import Path

import pytest

from finguard.attestation import load_scan_attestation
from finguard.cli import EXIT_GATE_FAILED, EXIT_INPUT_ERROR, EXIT_OK, main


def test_cli_scan_writes_normalized_report(project_root: Path, tmp_path: Path, capsys) -> None:
    project = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    with pytest.raises(SystemExit) as version_exit:
        main(["--version"])
    assert version_exit.value.code == EXIT_OK
    assert capsys.readouterr().out.strip() == f"finguard {project['project']['version']}"

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "safe.py").write_text("value = 1\n", encoding="utf-8")
    output = tmp_path / "reports"
    code = main(
        [
            "scan",
            "source",
            "--workspace",
            str(workspace),
            "--output",
            str(output),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["finding_count"] == 0
    assert (output / "finguard-native-sast.json").is_file()


def test_cli_gate_sign_verify_and_deploy_dry_run(
    project_root: Path, tmp_path: Path, current_pass_change: Path, monkeypatch, capsys
) -> None:
    scenario = project_root / "examples/scenarios/pass"
    evidence = tmp_path / "evidence"
    monkeypatch.setenv("TEST_EVIDENCE_KEY", "cli-test-key")
    gate_code = main(
        [
            "gate",
            "--policy",
            str(project_root / "policies/financial-baseline.toml"),
            "--reports",
            str(scenario / "reports"),
            "--change",
            str(current_pass_change),
            "--subject",
            str(scenario / "release-subject.json"),
            "--output",
            str(evidence),
            "--signing-key-env",
            "TEST_EVIDENCE_KEY",
        ]
    )
    assert gate_code == EXIT_OK
    capsys.readouterr()

    verify_code = main(
        [
            "verify",
            "--evidence",
            str(evidence),
            "--signing-key-env",
            "TEST_EVIDENCE_KEY",
        ]
    )
    assert verify_code == EXIT_OK
    assert json.loads(capsys.readouterr().out)["signature_verified"] is True

    deployment_record = tmp_path / "deployment-plan.json"
    deploy_code = main(
        [
            "deploy",
            "--cluster",
            "onprem-prod-01",
            "--namespace",
            "credit-prod",
            "--deployment",
            "customer-credit-api",
            "--container",
            "api",
            "--image",
            "registry.example/credit/api@sha256:" + "a" * 64,
            "--expected-policy-id",
            "FIN-SW-DEVSECOPS-BASELINE",
            "--expected-policy-version",
            "5.1.1",
            "--expected-policy-sha256",
            hashlib.sha256((evidence / "inputs/policy.toml").read_bytes()).hexdigest(),
            "--evidence",
            str(evidence),
            "--output",
            str(deployment_record),
            "--signing-key-env",
            "TEST_EVIDENCE_KEY",
            "--require-signature",
            "--dry-run",
        ]
    )
    assert deploy_code == EXIT_OK
    assert json.loads(deployment_record.read_text(encoding="utf-8"))["status"] == "planned"


def test_cli_demo_fail_returns_policy_exit_code(project_root: Path, tmp_path: Path, capsys) -> None:
    code = main(
        [
            "demo",
            "--scenario",
            "fail",
            "--fixtures",
            str(project_root / "examples/scenarios"),
            "--policy",
            str(project_root / "policies/financial-baseline.toml"),
            "--output",
            str(tmp_path / "demo"),
        ]
    )
    assert code == EXIT_GATE_FAILED
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "fail"
    assert {item["code"] for item in payload["violations"]}


def test_cli_demo_pass_refreshes_the_deployment_window(
    project_root: Path, tmp_path: Path, monkeypatch, capsys
) -> None:
    execution_time = dt.datetime(2035, 4, 5, 12, 0, tzinfo=dt.UTC)
    monkeypatch.setattr("finguard.cli._utc_now", lambda: execution_time)
    output = tmp_path / "demo"

    code = main(
        [
            "demo",
            "--scenario",
            "pass",
            "--fixtures",
            str(project_root / "examples/scenarios"),
            "--policy",
            str(project_root / "policies/financial-baseline.toml"),
            "--output",
            str(output),
        ]
    )

    assert code == EXIT_OK
    assert json.loads(capsys.readouterr().out)["decision"] == "pass"
    captured = (output / "pass/inputs/change.toml").read_text(encoding="utf-8")
    assert "window_start = 2035-04-05T11:55:00+00:00" in captured
    assert "window_end = 2035-04-05T12:55:00+00:00" in captured


def test_cli_verify_requires_signature_unless_explicitly_opted_out(
    project_root: Path, tmp_path: Path, current_pass_change: Path, capsys
) -> None:
    scenario = project_root / "examples/scenarios/pass"
    evidence = tmp_path / "unsigned-evidence"
    assert (
        main(
            [
                "gate",
                "--policy",
                str(project_root / "policies/financial-baseline.toml"),
                "--reports",
                str(scenario / "reports"),
                "--change",
                str(current_pass_change),
                "--subject",
                str(scenario / "release-subject.json"),
                "--output",
                str(evidence),
            ]
        )
        == EXIT_OK
    )
    capsys.readouterr()

    assert main(["verify", "--evidence", str(evidence)]) == EXIT_INPUT_ERROR
    assert "verified evidence signature is required" in capsys.readouterr().err
    assert main(["verify", "--evidence", str(evidence), "--allow-unsigned"]) == EXIT_OK


def test_cli_reports_actionable_input_errors(tmp_path: Path, capsys) -> None:
    assert main(["scan", "web", "--output", str(tmp_path)]) == EXIT_INPUT_ERROR
    assert "--url is required" in capsys.readouterr().err
    assert (
        main(
            [
                "verify",
                "--evidence",
                str(tmp_path),
                "--signing-key-env",
                "MISSING_TEST_KEY",
            ]
        )
        == EXIT_INPUT_ERROR
    )
    assert "environment variable is empty" in capsys.readouterr().err


def test_cli_creates_subject_and_signed_scan_attestation(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"bomFormat":"CycloneDX"}\n', encoding="utf-8")
    subject = tmp_path / "subject.json"
    image = "registry.example/service@sha256:" + "a" * 64
    code = main(
        [
            "subject",
            "--service",
            "credit-api",
            "--repository",
            "https://git.example/credit-api.git",
            "--commit",
            "b" * 40,
            "--image",
            image,
            "--sbom",
            str(sbom),
            "--environment",
            "production",
            "--cluster",
            "onprem-prod-01",
            "--namespace",
            "credit-prod",
            "--deployment",
            "credit-api",
            "--container",
            "api",
            "--healthcheck-url",
            "https://credit-api.example/health",
            "--builder-id",
            "gitlab:onprem-protected",
            "--built-at",
            "2026-09-01T00:00:00Z",
            "--output",
            str(subject),
        ]
    )
    assert code == EXIT_OK
    assert json.loads(subject.read_text(encoding="utf-8"))["image"] == image
    capsys.readouterr()

    report = tmp_path / "ruff.json"
    report.write_text("[]\n", encoding="utf-8")
    ruleset = tmp_path / "pyproject.toml"
    ruleset.write_text("[tool.ruff]\n", encoding="utf-8")
    database = tmp_path / "metadata.json"
    database.write_text('{"UpdatedAt":"2026-09-01T00:00:00Z"}\n', encoding="utf-8")
    attestation = tmp_path / "ruff.attestation.json"
    monkeypatch.setenv("TEST_SCAN_KEY", "scan-key")
    code = main(
        [
            "attest-report",
            "--report",
            str(report),
            "--output",
            str(attestation),
            "--scanner",
            "ruff",
            "--category",
            "lint",
            "--scanner-version",
            "1.0",
            "--scanner-uri",
            "tool://ruff@1.0",
            "--source-commit",
            "b" * 40,
            "--ruleset",
            str(ruleset),
            "--database",
            str(database),
            "--command",
            "ruff check",
            "--ci-job-id",
            "job-1",
            "--runner-id",
            "gitlab:onprem-protected",
            "--exit-code",
            "0",
            "--complete",
            "--started-at",
            "2026-09-01T00:00:00Z",
            "--finished-at",
            "2026-09-01T00:01:00Z",
            "--signing-key-env",
            "TEST_SCAN_KEY",
            "--key-id",
            "scan-key-v1",
        ]
    )
    assert code == EXIT_OK
    loaded = load_scan_attestation(attestation, report_path=report, signing_key=b"scan-key")
    assert loaded.signature_verified is True
    assert loaded.key_id == "scan-key-v1"
    assert loaded.database_updated_at == "2026-09-01T00:00:00+00:00"


def test_cli_validates_digest_pinned_images(capsys) -> None:
    pinned = "registry.example/tool@sha256:" + "a" * 64
    assert main(["validate-images", pinned]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["validated"] == 1
    assert main(["validate-images", "registry.example/tool:latest"]) == EXIT_INPUT_ERROR
    assert "immutable" in capsys.readouterr().err
