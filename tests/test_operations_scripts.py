from __future__ import annotations

import importlib.util
import subprocess
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
