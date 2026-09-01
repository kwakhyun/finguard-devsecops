from __future__ import annotations

import datetime as dt
import json
from dataclasses import replace
from pathlib import Path

import pytest

from finguard.approvals import create_approval_attestation, load_approval_attestation
from finguard.change import ChangeRequest
from finguard.errors import EvidenceVerificationError
from finguard.release import ReleaseSubject


def _inputs(project_root: Path) -> tuple[ChangeRequest, ReleaseSubject]:
    scenario = project_root / "examples/scenarios/pass"
    return (
        ChangeRequest.load(scenario / "change.toml"),
        ReleaseSubject.load(scenario / "release-subject.json"),
    )


def _create_unsigned(project_root: Path, output: Path, *, force: bool = False) -> Path:
    change, subject = _inputs(project_root)
    return create_approval_attestation(
        output,
        change=change,
        release_subject=subject,
        issuer="itsm://change-management",
        source_uri="https://itsm.example/changes/CB-2026-0107",
        event_id="event-1",
        issued_at=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
        key_id="onprem-itsm-cosign-v1",
        force=force,
    )


def test_cosign_verified_approval_has_asymmetric_signature_identity(
    project_root: Path, tmp_path: Path
) -> None:
    path = _create_unsigned(project_root, tmp_path / "approval.json")
    approval = load_approval_attestation(
        path,
        external_signature_verified=True,
        external_key_id="onprem-itsm-cosign-v1",
    )

    assert approval.signature_present is True
    assert approval.signature_verified is True
    assert approval.signature_method == "cosign"
    assert approval.to_dict()["release_subject_sha256"] == approval.release_subject_sha256


def test_approval_output_refuses_overwrite_unless_explicitly_forced(
    project_root: Path, tmp_path: Path
) -> None:
    output = _create_unsigned(project_root, tmp_path / "approval.json")

    with pytest.raises(EvidenceVerificationError, match="already exists"):
        _create_unsigned(project_root, output)

    _create_unsigned(project_root, output, force=True)
    assert output.is_file()


def test_approval_creation_rejects_partial_signing_and_subject_mismatch(
    project_root: Path, tmp_path: Path
) -> None:
    change, subject = _inputs(project_root)
    arguments = {
        "change": change,
        "release_subject": subject,
        "issuer": "itsm://change-management",
        "source_uri": "https://itsm.example/changes/CB-2026-0107",
        "event_id": "event-1",
        "issued_at": dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    }

    with pytest.raises(EvidenceVerificationError, match="key_id"):
        create_approval_attestation(
            tmp_path / "partial.json",
            **arguments,
            signing_key=b"secret",
        )

    with pytest.raises(EvidenceVerificationError, match="does not approve"):
        create_approval_attestation(
            tmp_path / "mismatch.json",
            **{
                **arguments,
                "release_subject": replace(
                    subject,
                    image="registry.example/api@sha256:" + "b" * 64,
                ),
            },
            key_id="onprem-itsm-cosign-v1",
        )

    with pytest.raises(EvidenceVerificationError, match="timezone"):
        create_approval_attestation(
            tmp_path / "naive-time.json",
            **{
                **arguments,
                "issued_at": dt.datetime(2026, 9, 1),
            },
            key_id="onprem-itsm-cosign-v1",
        )


def test_approval_loading_rejects_ambiguous_external_verification(
    project_root: Path, tmp_path: Path
) -> None:
    path = _create_unsigned(project_root, tmp_path / "approval.json")

    with pytest.raises(EvidenceVerificationError, match="choose one"):
        load_approval_attestation(
            path,
            signing_key=b"secret",
            external_signature_verified=True,
            external_key_id="key-v1",
        )
    with pytest.raises(EvidenceVerificationError, match="key_id"):
        load_approval_attestation(path, external_signature_verified=True)
    with pytest.raises(EvidenceVerificationError, match="signature is missing"):
        load_approval_attestation(path, signing_key=b"secret")


def test_approval_rejects_non_object_signature(project_root: Path, tmp_path: Path) -> None:
    path = _create_unsigned(project_root, tmp_path / "approval.json")
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["signature"] = "not-an-object"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="signature must be an object"):
        load_approval_attestation(
            path,
            external_signature_verified=True,
            external_key_id="onprem-itsm-cosign-v1",
        )


def test_approval_output_rejects_symlink(project_root: Path, tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("preserve\n", encoding="utf-8")
    link = tmp_path / "approval.json"
    link.symlink_to(target)

    with pytest.raises(EvidenceVerificationError, match="symlink"):
        _create_unsigned(project_root, link, force=True)
    assert target.read_text(encoding="utf-8") == "preserve\n"


def test_approval_output_rejects_symlinked_parent(project_root: Path, tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    with pytest.raises(EvidenceVerificationError, match="symlink approval output"):
        _create_unsigned(project_root, linked / "approval.json")
