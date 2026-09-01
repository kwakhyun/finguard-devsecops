from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from finguard.errors import EvidenceVerificationError
from finguard.evidence import create_evidence_bundle, verify_evidence_bundle
from finguard.models import Decision, GateResult
from finguard.signing import cosign_sign_blob, cosign_verify_blob


def _successful_cosign(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    if "sign-blob" in command:
        bundle = Path(command[command.index("--bundle") + 1])
        bundle.write_text('{"mediaType":"application/vnd.dev.sigstore.bundle"}\n')
    return subprocess.CompletedProcess(command, 0, stdout="verified\n", stderr="")


def test_cosign_adapter_uses_argument_vectors_and_bundle(tmp_path: Path) -> None:
    blob = tmp_path / "manifest.json"
    blob.write_text("{}\n", encoding="utf-8")
    bundle = tmp_path / "manifest.sigstore.json"
    calls: list[list[str]] = []

    def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return _successful_cosign(command, **kwargs)

    cosign_sign_blob(blob, bundle, key="hashivault://finguard", runner=runner)
    cosign_verify_blob(blob, bundle, key="hashivault://finguard", runner=runner)
    assert calls[0][:3] == ["cosign", "sign-blob", "--yes"]
    assert calls[1][:2] == ["cosign", "verify-blob"]
    assert Path(calls[0][-1]).is_absolute()
    assert Path(calls[1][-1]).is_absolute()
    assert bundle.is_file()


def test_keyless_verification_requires_identity_and_issuer(tmp_path: Path) -> None:
    blob = tmp_path / "manifest.json"
    bundle = tmp_path / "bundle.json"
    blob.write_text("{}", encoding="utf-8")
    bundle.write_text("{}", encoding="utf-8")
    with pytest.raises(EvidenceVerificationError, match="identity and OIDC issuer"):
        cosign_verify_blob(blob, bundle, runner=_successful_cosign)

    cosign_verify_blob(
        blob,
        bundle,
        certificate_identity="release@company.example",
        certificate_oidc_issuer="https://gitlab.company.example",
        runner=_successful_cosign,
    )


def test_cosign_rejects_mixed_key_and_keyless_constraints(tmp_path: Path) -> None:
    blob = tmp_path / "manifest.json"
    bundle = tmp_path / "bundle.json"
    blob.write_text("{}", encoding="utf-8")
    bundle.write_text("{}", encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="cannot mix"):
        cosign_verify_blob(
            blob,
            bundle,
            key="kms://verification-key",
            certificate_identity="release@company.example",
            certificate_oidc_issuer="https://gitlab.company.example",
            runner=_successful_cosign,
        )


def test_cosign_failure_does_not_expose_command_output(tmp_path: Path) -> None:
    blob = tmp_path / "manifest.json"
    blob.write_text("{}", encoding="utf-8")

    def failed(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(1, command, stderr="sensitive signer detail")

    with pytest.raises(EvidenceVerificationError, match="CalledProcessError") as caught:
        cosign_sign_blob(blob, tmp_path / "bundle.json", key="kms://key", runner=failed)
    assert "sensitive" not in str(caught.value)


def test_cosign_failure_never_publishes_a_partial_bundle(tmp_path: Path) -> None:
    blob = tmp_path / "manifest.json"
    blob.write_text("{}", encoding="utf-8")
    bundle = tmp_path / "bundle.json"

    def partial_then_failed(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        staging = Path(command[command.index("--bundle") + 1])
        staging.write_text('{"partial":true}', encoding="utf-8")
        raise subprocess.CalledProcessError(1, command, stderr="signer unavailable")

    with pytest.raises(EvidenceVerificationError, match="CalledProcessError"):
        cosign_sign_blob(blob, bundle, key="kms://key", runner=partial_then_failed)

    assert not bundle.exists()
    assert list(tmp_path.glob(".bundle.json.*.tmp")) == []


def test_cosign_signing_rejects_symlinked_bundle_parent(tmp_path: Path) -> None:
    blob = tmp_path / "manifest.json"
    blob.write_text("{}\n", encoding="utf-8")
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    with pytest.raises(EvidenceVerificationError, match="unsafe Cosign bundle output"):
        cosign_sign_blob(
            blob,
            linked / "bundle.json",
            key="kms://key",
            runner=_successful_cosign,
        )


def test_cosign_verification_rejects_symlinked_input(tmp_path: Path) -> None:
    blob = tmp_path / "manifest.json"
    blob.write_text("{}\n", encoding="utf-8")
    link = tmp_path / "linked-manifest.json"
    link.symlink_to(blob)
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}\n", encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="missing or unsafe"):
        cosign_verify_blob(link, bundle, key="kms://key", runner=_successful_cosign)


def test_cosign_never_overwrites_input_or_existing_bundle(tmp_path: Path) -> None:
    blob = tmp_path / "manifest.json"
    blob.write_text("{}\n", encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="unsafe Cosign bundle output"):
        cosign_sign_blob(blob, blob, key="kms://key", runner=_successful_cosign)

    existing = tmp_path / "bundle.json"
    existing.write_text("preserve\n", encoding="utf-8")
    with pytest.raises(EvidenceVerificationError, match="unsafe Cosign bundle output"):
        cosign_sign_blob(blob, existing, key="kms://key", runner=_successful_cosign)
    assert existing.read_text(encoding="utf-8") == "preserve\n"


def test_evidence_bundle_supports_cosign_verification(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text("policy", encoding="utf-8")
    result = GateResult(
        decision=Decision.PASS,
        policy_id="TEST",
        policy_version="1",
        violations=[],
        active_findings=[],
        excepted_findings=[],
        scan_results=[],
        metrics={},
        evaluated_at="2026-09-01T00:00:00+00:00",
    )
    output = tmp_path / "evidence"
    create_evidence_bundle(
        output,
        result=result,
        policy_path=policy,
        report_paths=[],
        cosign_signing_key="hashivault://finguard",
        cosign_runner=_successful_cosign,
    )
    verified = verify_evidence_bundle(
        output,
        cosign_verification_key="hashivault://finguard",
        cosign_runner=_successful_cosign,
    )
    assert verified["cosign_bundle_present"] is True
    assert verified["cosign_verified"] is True
    assert json.loads((output / "manifest.sigstore.json").read_text())["mediaType"]
