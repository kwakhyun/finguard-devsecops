from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from finguard.errors import ConfigurationError


def _load_script(project_root: Path, name: str) -> ModuleType:
    path = project_root / "scripts" / name
    spec = importlib.util.spec_from_file_location(f"test_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_onprem_validator_requires_digest_pinned_images(
    project_root: Path, monkeypatch, capsys
) -> None:
    validator = _load_script(project_root, "validate_onprem_images.py")
    monkeypatch.setenv("POSTGRES_IMAGE", "registry.example/postgres@sha256:" + "a" * 64)
    monkeypatch.setenv("SONARQUBE_IMAGE", "registry.example/sonarqube@sha256:" + "b" * 64)

    validator.main()
    assert "immutable" in capsys.readouterr().out

    monkeypatch.setenv("SONARQUBE_IMAGE", "sonarqube:community")
    with pytest.raises(ConfigurationError, match="immutable"):
        validator.main()


def test_clean_script_targets_only_repository_build_directory(project_root: Path) -> None:
    cleaner = _load_script(project_root, "clean_build.py")
    source = (project_root / "scripts/clean_build.py").read_text(encoding="utf-8")
    assert 'project_root / "build"' in source
    assert "target.parent != project_root" in source
    assert callable(cleaner.main)
