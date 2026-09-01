from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path

import pytest

from finguard.change import ChangeRequest
from finguard.config import Policy
from finguard.errors import EvidenceVerificationError
from finguard.evidence import (
    _verify_manifest_shape,
    create_evidence_bundle,
    verify_evidence_bundle,
)
from finguard.gate import PolicyEngine
from finguard.parsers import discover_reports, parse_report
from finguard.release import ReleaseSubject


def _bundle(project_root: Path, output: Path, key: bytes) -> Path:
    scenario = project_root / "examples/scenarios/pass"
    report_paths = discover_reports(scenario / "reports")
    scans = [parse_report(path) for path in report_paths]
    policy_path = project_root / "policies/financial-baseline.toml"
    policy = Policy.load(policy_path)
    change_path = scenario / "change.toml"
    result = PolicyEngine(policy).evaluate(
        scans,
        change=ChangeRequest.load(change_path),
        release_subject=ReleaseSubject.load(scenario / "release-subject.json"),
        now=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    )
    return create_evidence_bundle(
        output,
        result=result,
        policy_path=policy_path,
        report_paths=report_paths,
        change_path=change_path,
        signing_key=key,
    )


def test_signed_evidence_round_trip(project_root: Path, tmp_path: Path) -> None:
    key = b"portfolio-test-signing-key"
    output = tmp_path / "evidence"
    _bundle(project_root, output, key)
    verified = verify_evidence_bundle(output, signing_key=key)
    assert verified["verified"] is True
    assert verified["signature_verified"] is True
    assert verified["decision"] == "pass"
    assert verified["evaluated_at"] == "2026-09-01T00:00:00+00:00"
    assert (
        verified["policy_sha256"]
        == hashlib.sha256((output / "inputs/policy.toml").read_bytes()).hexdigest()
    )


def test_evidence_tampering_is_detected(project_root: Path, tmp_path: Path) -> None:
    key = b"portfolio-test-signing-key"
    output = tmp_path / "evidence"
    _bundle(project_root, output, key)
    (output / "decision.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(EvidenceVerificationError, match="hash mismatch"):
        verify_evidence_bundle(output, signing_key=key)


def test_manifest_shape_variants_fail_closed() -> None:
    base: dict[str, object] = {
        "schema_version": "3.0",
        "bundle_type": "finguard-evidence",
        "bundle_id": "a" * 32,
        "decision": "pass",
        "policy": {"id": "POLICY", "version": "1"},
        "change_id": "CB-1",
        "release_subject": None,
        "release_subject_sha256": "",
        "evaluated_at": "2026-09-01T00:00:00+00:00",
        "shadow_policy": None,
        "files": {},
    }

    def changed(**values: object) -> dict[str, object]:
        return {**base, **values}

    invalid = [
        {**base, "unexpected": True},
        changed(bundle_id="bad"),
        changed(decision="unknown"),
        changed(policy={"id": "POLICY"}),
        changed(change_id=1),
        changed(evaluated_at=""),
        changed(evaluated_at="not-a-time"),
        changed(evaluated_at="2026-09-01T00:00:00"),
        changed(shadow_policy={"id": "CANDIDATE"}),
        changed(release_subject_sha256="a" * 64),
        changed(release_subject={}, release_subject_sha256="bad"),
    ]

    for manifest in invalid:
        with pytest.raises(EvidenceVerificationError):
            _verify_manifest_shape(manifest)
