from __future__ import annotations

import base64
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from finguard.errors import ConfigurationError, FinGuardError


def _load_script(project_root: Path, name: str) -> ModuleType:
    path = project_root / "scripts" / name
    spec = importlib.util.spec_from_file_location(f"test_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_onprem_validator_requires_pinned_and_signed_images(
    project_root: Path, monkeypatch, capsys
) -> None:
    validator = _load_script(project_root, "validate_onprem_images.py")
    postgres = "registry.example/postgres@sha256:" + "a" * 64
    sonarqube = "registry.example/sonarqube@sha256:" + "b" * 64
    key = "/run/secrets/tool-image-cosign.pub"
    commands: list[list[str]] = []

    def successful_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setenv("POSTGRES_IMAGE", postgres)
    monkeypatch.setenv("SONARQUBE_IMAGE", sonarqube)
    monkeypatch.setenv("FINGUARD_TOOL_IMAGE_COSIGN_PUBLIC_KEY", key)
    monkeypatch.setattr(validator.subprocess, "run", successful_run)

    validator.main()
    assert "signatures are verified" in capsys.readouterr().out
    assert commands == [
        ["cosign", "verify", "--key", key, postgres],
        ["cosign", "verify", "--key", key, sonarqube],
    ]

    monkeypatch.setenv("SONARQUBE_IMAGE", "sonarqube:community")
    with pytest.raises(ConfigurationError, match="immutable"):
        validator.main()

    monkeypatch.setenv("SONARQUBE_IMAGE", sonarqube)
    monkeypatch.delenv("FINGUARD_TOOL_IMAGE_COSIGN_PUBLIC_KEY")
    with pytest.raises(FinGuardError, match="must be set"):
        validator.main()

    monkeypatch.setenv("FINGUARD_TOOL_IMAGE_COSIGN_PUBLIC_KEY", key)

    def failed_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(1, command, stderr="signature is not trusted")

    monkeypatch.setattr(validator.subprocess, "run", failed_run)
    with pytest.raises(FinGuardError, match="POSTGRES_IMAGE signature verification failed"):
        validator.main()


def test_clean_script_targets_only_repository_build_directory(project_root: Path) -> None:
    cleaner = _load_script(project_root, "clean_build.py")
    source = (project_root / "scripts/clean_build.py").read_text(encoding="utf-8")
    assert 'project_root / "build"' in source
    assert "target.parent != project_root" in source
    assert callable(cleaner.main)


def test_dast_pulls_both_images_into_cold_storage_and_removes_auth(project_root, monkeypatch):
    script = _load_script(project_root, "prepare_dast_images.py")
    images = ["registry.example/app@sha256:" + "a" * 64, "registry.example/zap@sha256:" + "b" * 64]
    monkeypatch.setattr(sys, "argv", ["prepare_dast_images.py", *images])
    monkeypatch.setenv("CI_REGISTRY", "registry.example")
    monkeypatch.setenv("CI_REGISTRY_USER", "ci-test")
    monkeypatch.setenv("CI_REGISTRY_PASSWORD", "test-only-password")
    storage = set()
    auth_paths = []

    def podman(command, **kwargs):
        assert "test-only-password" not in command
        auth = Path(command[command.index("--authfile") + 1])
        auth_paths.append(auth)
        if command[1] == "login":
            assert kwargs["input"] == "test-only-password"
            auth.write_text("test auth")
        else:
            assert auth.is_file()
            storage.add(command[-1])
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(script.subprocess, "run", podman)
    script.main()
    assert storage == set(images)
    assert all(not path.exists() for path in auth_paths)


def test_dast_pull_failure_stops_preparation(project_root, monkeypatch):
    script = _load_script(project_root, "prepare_dast_images.py")
    monkeypatch.setattr(
        sys, "argv", ["prepare_dast_images.py", "registry.example/app@sha256:" + "a" * 64]
    )
    for name in ("CI_REGISTRY", "CI_REGISTRY_USER", "CI_REGISTRY_PASSWORD"):
        monkeypatch.delenv(name, raising=False)

    def unavailable(command, **kwargs):
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(script.subprocess, "run", unavailable)
    with pytest.raises(subprocess.CalledProcessError):
        script.main()


@pytest.mark.parametrize("scan_format", ["json", "cyclonedx"])
@pytest.mark.parametrize("outcome", [0, 1, "timeout"])
def test_release_sca_scopes_credentials_and_cleans_up(
    project_root, tmp_path, monkeypatch, scan_format, outcome
):
    script = _load_script(project_root, "scan_release_image.py")
    image = "registry.example/team/app@sha256:" + "a" * 64
    report = tmp_path / "report.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["scan_release_image.py", image, "--format", scan_format, "--output", str(report)],
    )
    monkeypatch.setenv("CI_REGISTRY", "registry.example")
    monkeypatch.setenv("CI_REGISTRY_USER", "ci-job-user")
    monkeypatch.setenv("CI_REGISTRY_PASSWORD", "job-test-password")
    monkeypatch.setenv("TRIVY_USERNAME", "ambient-user")
    monkeypatch.setenv("TRIVY_PASSWORD", "ambient-password")
    monkeypatch.setenv("TRIVY_REGISTRY_TOKEN", "ambient-token")
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "existing-auth"))
    auth_directories = []

    def trivy(command, **kwargs):
        auth_directory = Path(kwargs["env"]["DOCKER_CONFIG"])
        auth_directories.append(auth_directory)
        config = auth_directory / "config.json"
        assert stat.S_IMODE(auth_directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        credentials = json.loads(config.read_text())["auths"]
        assert set(credentials) == {"registry.example"}
        assert base64.b64decode(credentials["registry.example"]["auth"]).decode() == (
            "ci-job-user:job-test-password"
        )
        assert "job-test-password" not in command
        assert "CI_REGISTRY_PASSWORD" not in kwargs["env"]
        assert "TRIVY_USERNAME" not in kwargs["env"]
        assert "TRIVY_PASSWORD" not in kwargs["env"]
        assert "TRIVY_REGISTRY_TOKEN" not in kwargs["env"]
        assert command[:4] == ["trivy", "--config", "config/trivy.yaml", "image"]
        assert command[-1] == image
        assert ("--scanners" in command) == (scan_format == "json")
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(command, 600)
        return subprocess.CompletedProcess(command, outcome)

    monkeypatch.setattr(script.subprocess, "run", trivy)
    if outcome == "timeout":
        with pytest.raises(subprocess.TimeoutExpired):
            script.main()
    else:
        assert script.main() == outcome
    assert len(auth_directories) == 1
    assert not auth_directories[0].exists()
    assert os.environ["DOCKER_CONFIG"] == str(tmp_path / "existing-auth")


@pytest.mark.parametrize("registry,password", [("registry.example", ""), ("other.example", "test")])
def test_release_sca_rejects_missing_or_mismatched_registry_auth(
    project_root, tmp_path, monkeypatch, registry, password
):
    script = _load_script(project_root, "scan_release_image.py")
    image = "registry.example/app@sha256:" + "a" * 64
    monkeypatch.setattr(
        sys,
        "argv",
        ["scan_release_image.py", image, "--format", "json", "--output", str(tmp_path / "out")],
    )
    monkeypatch.setenv("CI_REGISTRY", registry)
    monkeypatch.setenv("CI_REGISTRY_USER", "ci-user")
    monkeypatch.setenv("CI_REGISTRY_PASSWORD", password)

    def unexpected_scan(*args, **kwargs):
        pytest.fail("invalid authentication must fail before invoking Trivy")

    monkeypatch.setattr(script.subprocess, "run", unexpected_scan)
    with pytest.raises(FinGuardError):
        script.main()


@pytest.mark.parametrize("scan_status", [0, 1, 2, 3])
def test_rootless_zap_uses_private_mapped_directory_and_preserves_exit_code(
    project_root, tmp_path, monkeypatch, scan_status
):
    script = _load_script(project_root, "run_zap_scan.py")
    image = "registry.example/zap@sha256:" + "a" * 64
    reports = tmp_path / "reports"
    reports.mkdir(mode=0o750)
    other_report = reports / "trivy.json"
    other_report.write_text("keep existing scanner report")
    other_report.chmod(0o640)
    output = reports / "zap.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_zap_scan.py",
            "--image",
            image,
            "--network",
            "job-network",
            "--target",
            "http://target:8080/",
            "--rules",
            str(project_root / "config/zap-rules.conf"),
            "--output",
            str(output),
        ],
    )
    monkeypatch.setattr(script.os, "geteuid", lambda: 1234)
    work_directories = []
    container_names = []

    def podman(command, **kwargs):
        if command[1] == "rm":
            assert command == ["podman", "rm", "--force", "--ignore", container_names[0]]
            assert kwargs["timeout"] == 30
            assert work_directories[0].is_dir()
            return subprocess.CompletedProcess(command, 0)
        container_names.append(command[command.index("--name") + 1])
        assert container_names[0].startswith("finguard-zap-")
        assert "--userns=keep-id:uid=1000,gid=1000" in command
        assert command[command.index("--user") + 1] == "1000:1000"
        mount = command[command.index("--volume") + 1]
        assert mount.endswith(":/zap/wrk:rw,Z")
        work = Path(mount.removesuffix(":/zap/wrk:rw,Z"))
        work_directories.append(work)
        assert work != reports and work.parent == reports
        assert stat.S_IMODE(work.stat().st_mode) == 0o700
        assert not (work / "trivy.json").exists()
        assert (work / "zap-rules.conf").read_bytes() == (
            project_root / "config/zap-rules.conf"
        ).read_bytes()
        (work / "zap.json").write_text('{"site": []}')
        (work / "unrelated-output.txt").write_text("do not collect")
        return subprocess.CompletedProcess(command, scan_status)

    monkeypatch.setattr(script.subprocess, "run", podman)
    assert script.main() == scan_status
    assert output.read_text() == '{"site": []}'
    assert len(work_directories) == 1 and not work_directories[0].exists()
    assert stat.S_IMODE(reports.stat().st_mode) == 0o750
    assert stat.S_IMODE(other_report.stat().st_mode) == 0o640
    assert other_report.read_text() == "keep existing scanner report"
    assert set(reports.iterdir()) == {other_report, output}


@pytest.mark.parametrize("failure", ["missing-report", "timeout"])
def test_zap_operational_failure_cleans_private_directory(
    project_root, tmp_path, monkeypatch, failure
):
    script = _load_script(project_root, "run_zap_scan.py")
    image = "registry.example/zap@sha256:" + "a" * 64
    output = tmp_path / "zap.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_zap_scan.py",
            "--image",
            image,
            "--network",
            "job-network",
            "--target",
            "http://target:8080/",
            "--rules",
            str(project_root / "config/zap-rules.conf"),
            "--output",
            str(output),
        ],
    )
    monkeypatch.setattr(script.os, "geteuid", lambda: 1234)
    work_directories = []
    commands = []

    def podman(command, **kwargs):
        commands.append(command)
        if command[1] == "rm":
            assert kwargs["timeout"] == 30
            assert work_directories[0].is_dir()
            return subprocess.CompletedProcess(command, 0)
        work_directories.append(
            Path(command[command.index("--volume") + 1].removesuffix(":/zap/wrk:rw,Z"))
        )
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 600)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(script.subprocess, "run", podman)
    with pytest.raises((FinGuardError, subprocess.TimeoutExpired)):
        script.main()
    assert not output.exists()
    assert len(work_directories) == 1 and not work_directories[0].exists()
    container = commands[0][commands[0].index("--name") + 1]
    assert commands[1] == ["podman", "rm", "--force", "--ignore", container]


def test_rootful_zap_changes_ownership_only_of_private_scan_directory(
    project_root, tmp_path, monkeypatch
):
    script = _load_script(project_root, "run_zap_scan.py")
    image = "registry.example/zap@sha256:" + "a" * 64
    output = tmp_path / "zap.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_zap_scan.py",
            "--image",
            image,
            "--network",
            "job-network",
            "--target",
            "http://target:8080/",
            "--rules",
            str(project_root / "config/zap-rules.conf"),
            "--output",
            str(output),
        ],
    )
    monkeypatch.setattr(script.os, "geteuid", lambda: 0)
    chowns = []
    monkeypatch.setattr(script.os, "chown", lambda path, uid, gid: chowns.append((path, uid, gid)))

    def podman(command, **kwargs):
        if command[1] == "rm":
            assert chowns[0][0].is_dir()
            return subprocess.CompletedProcess(command, 0)
        assert not any(value.startswith("--userns") for value in command)
        work = Path(command[command.index("--volume") + 1].removesuffix(":/zap/wrk:rw,Z"))
        assert chowns == [(work, 1000, 1000)]
        assert work.parent == tmp_path
        (work / "zap.json").write_text('{"site": []}')
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(script.subprocess, "run", podman)
    assert script.main() == 0
    assert not chowns[0][0].exists()


@pytest.mark.parametrize("scan_status", [0, 1, 2, 3])
def test_zap_cleanup_failure_retains_directory_and_preserves_only_operational_failures(
    project_root, tmp_path, monkeypatch, capsys, scan_status
):
    script = _load_script(project_root, "run_zap_scan.py")
    work = tmp_path / "active-bind-mount"
    work.mkdir()
    (work / "zap.json").write_text('{"site": []}')

    def failed_cleanup(command, **kwargs):
        assert command == ["podman", "rm", "--force", "--ignore", "unique-container"]
        assert kwargs["timeout"] == 30
        raise subprocess.CalledProcessError(125, command)

    monkeypatch.setattr(script.subprocess, "run", failed_cleanup)
    if scan_status <= 2:
        with pytest.raises(FinGuardError, match="cleanup failed; retained scan directory"):
            script.cleanup_scan(
                "unique-container", work, primary_error=None, scan_status=scan_status
            )
    else:
        script.cleanup_scan("unique-container", work, primary_error=None, scan_status=scan_status)
        assert str(work) in capsys.readouterr().err
    assert (work / "zap.json").is_file()


def test_zap_cleanup_timeout_keeps_original_timeout_and_active_bind_mount(
    project_root, tmp_path, monkeypatch, capsys
):
    script = _load_script(project_root, "run_zap_scan.py")
    primary = subprocess.TimeoutExpired(["podman", "run"], 600)

    def cleanup_timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(script.subprocess, "run", cleanup_timeout)
    with pytest.raises(subprocess.TimeoutExpired) as failure:
        try:
            raise primary
        finally:
            script.cleanup_scan(
                "unique-container", tmp_path, primary_error=sys.exception(), scan_status=None
            )
    assert failure.value is primary
    assert "cleanup failed" in primary.__notes__[0]
    assert str(tmp_path) in capsys.readouterr().err
    assert tmp_path.is_dir()


def test_zap_cli_marks_missing_report_as_operational_failure(project_root, tmp_path):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    podman = binaries / "podman"
    podman.write_text("#!/bin/sh\nexit 0\n")
    podman.chmod(0o755)
    reports = tmp_path / "reports"
    output = reports / "zap.json"
    command = [
        sys.executable,
        str(project_root / "scripts/run_zap_scan.py"),
        "--image",
        "registry.example/zap@sha256:" + "a" * 64,
        "--network",
        "job-network",
        "--target",
        "http://target:8080/",
        "--rules",
        str(project_root / "config/zap-rules.conf"),
        "--output",
        str(output),
    ]
    result = subprocess.run(  # noqa: S603 - fixed project script and test-owned paths
        command,
        env={**os.environ, "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 3
    assert "did not produce a regular zap.json" in result.stderr
    assert not output.exists()
    assert list(reports.iterdir()) == []


def test_release_sca_cli_preserves_scanner_failure_and_removes_credentials(project_root, tmp_path):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    trivy = binaries / "trivy"
    trivy.write_text("#!/bin/sh\nexit 17\n")
    trivy.chmod(0o755)
    temporary = tmp_path / "private-scanner-temp"
    temporary.mkdir()
    command = [
        sys.executable,
        str(project_root / "scripts/scan_release_image.py"),
        "registry.example/app@sha256:" + "a" * 64,
        "--format",
        "json",
        "--output",
        str(tmp_path / "trivy.json"),
    ]
    result = subprocess.run(  # noqa: S603 - fixed project script and test-owned paths
        command,
        env={
            **os.environ,
            "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
            "TMPDIR": str(temporary),
            "CI_REGISTRY": "registry.example",
            "CI_REGISTRY_USER": "ci-user",
            "CI_REGISTRY_PASSWORD": "cli-test-password",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 17
    assert "cli-test-password" not in result.stdout + result.stderr
    assert list(temporary.iterdir()) == []


@pytest.mark.parametrize("failed_command", ["export", "delete", "rm"])
def test_release_cleanup_attempts_all_resources_on_failure(
    project_root, tmp_path, monkeypatch, failed_command
):
    script = _load_script(project_root, "integration_release.py")
    commands = []

    def run(*command, **kwargs):
        commands.append(command)
        if failed_command in command:
            raise RuntimeError(f"injected {failed_command} failure")

    monkeypatch.setattr(script, "run", run)
    with pytest.raises(ExceptionGroup, match="resource cleanup failed"):
        script.cleanup_resources(
            "cluster", "registry", tmp_path, started_cluster=True, started_registry=True
        )
    assert [command[:2] for command in commands] == [
        ("kind", "export"),
        ("kind", "delete"),
        ("docker", "rm"),
    ]


def test_release_cleanup_preserves_primary_failure(project_root, tmp_path, monkeypatch):
    script = _load_script(project_root, "integration_release.py")

    def run(*command, **kwargs):
        raise RuntimeError("injected cleanup failure")

    monkeypatch.setattr(script, "run", run)
    primary = RuntimeError("original deployment failure")
    with pytest.raises(RuntimeError, match="original deployment failure") as failure:
        try:
            raise primary
        finally:
            script.cleanup_resources(
                "cluster",
                "registry",
                tmp_path,
                started_cluster=True,
                started_registry=True,
                primary_error=sys.exception(),
            )
    assert failure.value is primary
    assert len(primary.__notes__) == 3
