from __future__ import annotations

import importlib.util
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
