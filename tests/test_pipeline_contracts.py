from __future__ import annotations

import hashlib
from pathlib import Path


def test_gitlab_pipeline_has_separate_mr_and_release_trust_boundaries(
    project_root: Path,
) -> None:
    pipeline = (project_root / ".gitlab-ci.yml").read_text(encoding="utf-8")
    mr_gate = pipeline.split("quality-gate-merge-request:", 1)[1].split("attest-release:", 1)[0]
    release_gate = pipeline.split("quality-gate-release:", 1)[1].split("deploy-production:", 1)[0]
    assert "FINGUARD_EVIDENCE_KEY" not in mr_gate
    assert "CHANGE_MANIFEST_PATH" not in mr_gate
    assert "policies/merge-request.toml" in mr_gate
    assert "FINGUARD_SCAN_ATTESTATION_KEY" in release_gate
    assert "CHANGE_MANIFEST_PATH" in release_gate
    assert "APPROVAL_ATTESTATION_PATH" in release_gate
    assert "APPROVAL_ATTESTATION_BUNDLE_PATH" in release_gate
    assert "FINGUARD_APPROVAL_COSIGN_PUBLIC_KEY" in release_gate
    assert "--approval-cosign-key-id onprem-itsm-cosign-v1" in release_gate
    assert "FINGUARD_APPROVAL_KEY" not in release_gate
    assert "FINGUARD_EVIDENCE_COSIGN_SIGNING_KEY" in release_gate
    assert "FINGUARD_EVIDENCE_COSIGN_PUBLIC_KEY" in release_gate
    assert "FINGUARD_EVIDENCE_KEY" not in release_gate
    assert "build/release-subject.json" in release_gate


def test_ci_builds_once_before_artifact_scans_and_has_no_floating_tools(
    project_root: Path,
) -> None:
    gitlab = (project_root / ".gitlab-ci.yml").read_text(encoding="utf-8")
    jenkins = (project_root / "Jenkinsfile").read_text(encoding="utf-8")
    combined = f"{gitlab}\n{jenkins}"
    for unsafe in (":latest", ":stable", "docker:27-dind", "DOCKER_TLS_CERTDIR", "RUN_DAST"):
        assert unsafe not in combined
    assert gitlab.index("build-release:") < gitlab.index("sca-release:")
    assert gitlab.index("build-release:") < gitlab.index("dast-release:")
    assert gitlab.index("attest-release:") < gitlab.index("quality-gate-release:")
    assert jenkins.index("Build Candidate Once") < jenkins.index("Release SCA")
    assert jenkins.index("Release Subject") < jenkins.index("Approved Release Gate")
    assert "finguard-itsm-cosign-public-key" in jenkins
    assert "--approval-cosign-verification-key" in jenkins
    assert "finguard-evidence-cosign-signing-key" in jenkins
    assert "finguard-evidence-cosign-public-key" in jenkins
    assert "credentialsId: 'finguard-evidence-key'" not in jenkins
    for variable in (
        "RUFF_VERSION",
        "PYTEST_VERSION",
        "COVERAGE_VERSION",
        "SEMGREP_VERSION",
        "TRIVY_VERSION",
        "ZAP_VERSION",
    ):
        assert variable in gitlab
        assert variable in jenkins
    assert jenkins.index("deleteDir()") < jenkins.index("checkout scm")


def test_onprem_images_are_injected_as_immutable_references(project_root: Path) -> None:
    compose = (project_root / "infra/docker-compose.onprem.yml").read_text(encoding="utf-8")
    assert "postgres:16-alpine" not in compose
    assert "sonarqube:community" not in compose
    assert "POSTGRES_IMAGE must be an immutable @sha256 reference" in compose
    assert "SONARQUBE_IMAGE must be an immutable @sha256 reference" in compose


def test_gitlab_dast_resources_are_unique_per_job(project_root: Path) -> None:
    pipeline = (project_root / ".gitlab-ci.yml").read_text(encoding="utf-8")
    dast = pipeline.split("dast-release:", 1)[1].split("quality-gate-merge-request:", 1)[0]
    assert "finguard-${CI_PIPELINE_ID}-${CI_JOB_ID}" in dast
    assert "finguard-target-${CI_PIPELINE_ID}-${CI_JOB_ID}" in dast
    assert dast.index("prepare_dast_images.py") < dast.index("podman run --detach")


def test_production_job_cannot_be_auto_cancelled(project_root: Path) -> None:
    pipeline = (project_root / ".gitlab-ci.yml").read_text(encoding="utf-8")
    deployment = pipeline.split("deploy-production:", 1)[1]
    assert "interruptible: false" in deployment
    assert "build/deployment-result.json.recovery.json" in deployment


def test_ci_does_not_hide_scanner_operational_failures(project_root: Path) -> None:
    gitlab = (project_root / ".gitlab-ci.yml").read_text(encoding="utf-8")
    jenkins = (project_root / "Jenkinsfile").read_text(encoding="utf-8")
    combined = f"{gitlab}\n{jenkins}"
    for unsafe in (
        'ruff.json" || true',
        'coverage.xml" || true',
        'semgrep.json" . || true',
        "-J zap.json || true",
    ):
        assert unsafe not in combined
    assert combined.count("ruff check . --exit-zero --output-format=json --output-file=") == 2
    assert 'test "$pytest_status" -le 1' in gitlab
    assert 'test "$test_status" -le 1 && completion=--complete' in jenkins
    assert 'test "$(cat build/test.status)" -le 1' in jenkins
    assert 'test "$zap_status" -le 2' in gitlab
    assert 'test "$zap_status" -le 2 && completion=--complete' in jenkins


def test_release_attestations_are_issued_by_each_scanner_job(
    project_root: Path,
) -> None:
    gitlab = (project_root / ".gitlab-ci.yml").read_text(encoding="utf-8")
    jenkins = (project_root / "Jenkinsfile").read_text(encoding="utf-8")
    release_subject_job = gitlab.split("attest-release:", 1)[1].split("quality-gate-release:", 1)[0]
    jenkins_subject = jenkins.split("stage('Release Subject')", 1)[1].split(
        "stage('Approved Release Gate')", 1
    )[0]
    assert "attest-report" not in release_subject_job
    assert "attest-report" not in jenkins_subject

    for start, end in (
        ("source-quality:", "sast:"),
        ("sast:", "sca-merge-request:"),
        ("sca-release:", "dast-release:"),
        ("dast-release:", "quality-gate-merge-request:"),
    ):
        assert "attest-report" in gitlab.split(start, 1)[1].split(end, 1)[0]
    for stage in ("Lint", "Test", "SAST", "Release SCA", "Release DAST"):
        assert "attest-report" in jenkins.split(f"stage('{stage}')", 1)[1]


def test_release_gate_and_deploy_use_separate_pinned_runner_images(
    project_root: Path,
) -> None:
    gitlab = (project_root / ".gitlab-ci.yml").read_text(encoding="utf-8")
    assert 'image: "$GATE_RUNNER_IMAGE"' in gitlab
    assert 'image: "$DEPLOY_RUNNER_IMAGE"' in gitlab
    assert 'validate-images "$PYTHON_IMAGE" "$GATE_RUNNER_IMAGE"' in gitlab
    assert '"$ZAP_IMAGE" "$DEPLOY_RUNNER_IMAGE"' in gitlab
    assert "FINGUARD_TOOL_IMAGE_COSIGN_PUBLIC_KEY" in gitlab


def test_ci_pins_local_rules_and_records_database_target_and_result_signature(
    project_root: Path,
) -> None:
    gitlab = (project_root / ".gitlab-ci.yml").read_text(encoding="utf-8")
    jenkins = (project_root / "Jenkinsfile").read_text(encoding="utf-8")
    combined = f"{gitlab}\n{jenkins}"
    assert "p/python" not in combined
    assert ".semgrep/secure-coding.yml" in gitlab
    assert ".semgrep/secure-coding.yml" in jenkins
    assert '--database "$TRIVY_DB_METADATA_PATH"' in combined
    assert "--target-uri" in gitlab
    assert "--target-uri" in jenkins
    assert "--result-cosign-signing-key" in gitlab
    assert "--result-cosign-signing-key" in jenkins
    assert '--expected-policy-id "$RELEASE_POLICY_ID"' in gitlab
    assert '--expected-policy-version "$RELEASE_POLICY_VERSION"' in gitlab
    assert '--expected-policy-sha256 "$RELEASE_POLICY_SHA256"' in gitlab
    assert '--expected-policy-id "$RELEASE_POLICY_ID"' in jenkins
    assert '--expected-policy-version "$RELEASE_POLICY_VERSION"' in jenkins
    assert '--expected-policy-sha256 "$RELEASE_POLICY_SHA256"' in jenkins
    release_policy_sha256 = hashlib.sha256(
        (project_root / "policies/financial-release.toml").read_bytes()
    ).hexdigest()
    assert f'RELEASE_POLICY_SHA256: "{release_policy_sha256}"' in gitlab
    assert f"RELEASE_POLICY_SHA256 = '{release_policy_sha256}'" in jenkins


def test_public_portfolio_ci_runs_real_security_tools_with_immutable_inputs(
    project_root: Path,
) -> None:
    workflow = (project_root / ".github/workflows/portfolio-ci.yml").read_text(encoding="utf-8")
    assert 'bin/semgrep" scan' in workflow
    assert "aquasec/trivy@sha256:" in workflow
    assert "ghcr.io/zaproxy/zaproxy@sha256:" in workflow
    assert "python -m finguard gate" in workflow
    assert "--policy policies/merge-request.toml" in workflow
    assert "python -m finguard verify" in workflow
    assert "--evidence build/public-ci/evidence" in workflow
    for action in ("actions/checkout", "actions/setup-python", "actions/upload-artifact"):
        references = [line.strip() for line in workflow.splitlines() if action in line]
        assert references
        assert all("@v" not in line and "@main" not in line for line in references)


def test_public_portfolio_ci_routes_findings_to_finguard_without_hiding_tool_errors(
    project_root: Path,
) -> None:
    workflow = (project_root / ".github/workflows/portfolio-ci.yml").read_text(encoding="utf-8")
    quality = workflow.split("- name: Require shared quality reports", 1)[1].split(
        "- name: Run Semgrep SAST", 1
    )[0]
    semgrep = workflow.split("- name: Run Semgrep SAST", 1)[1].split("- name: Run Trivy SCA", 1)[0]
    gate = workflow.split("- name: Evaluate the real reports with FinGuard", 1)[1].split(
        "- name: Preserve scanner reports", 1
    )[0]

    assert "test -s build/public-ci/reports/junit.xml" in quality
    assert "test -s build/public-ci/reports/coverage.xml" in quality
    assert "--skip-tests" in workflow
    assert "QUALITY_REPORT_DIR=build/public-ci/reports" in workflow
    assert "pytest " not in workflow
    assert "Enforce quality check outcome" in workflow
    assert "if: always() && steps.quality.outcome != 'success'" in workflow
    assert "--error" not in semgrep
    assert "gate_status=0" in gate
    assert "|| gate_status=$?" in gate
    assert 'test "$gate_status" -eq 0 || test "$gate_status" -eq 2' in gate
    assert "python -m finguard verify" in gate
    assert 'exit "$gate_status"' in gate


def test_dependabot_tracks_python_and_github_actions_dependencies(project_root: Path) -> None:
    dependabot = (project_root / ".github/dependabot.yml").read_text(encoding="utf-8")
    assert 'package-ecosystem: "pip"' in dependabot
    assert 'package-ecosystem: "github-actions"' in dependabot
    assert dependabot.count('interval: "weekly"') == 2
