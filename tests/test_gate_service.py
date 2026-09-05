from __future__ import annotations

import json
from pathlib import Path

import pytest

from finguard.errors import FinGuardError
from finguard.evidence import verify_evidence_bundle
from finguard.gate_service import GateRequest, execute_gate
from finguard.models import Decision


def test_service_runs_without_cli_and_preserves_signed_shadow_evidence(
    project_root: Path, tmp_path: Path
) -> None:
    policy = project_root / "policies/merge-request.toml"
    request = GateRequest(
        policy=policy,
        shadow_policy=policy,
        reports=project_root / "examples/scenarios/pass/reports",
        output=tmp_path / "evidence",
        signing_key=b"service-test-only",
    )
    execution = execute_gate(request)
    assert execution.result.decision is Decision.PASS
    assert execution.comparison is not None
    assert execution.comparison["decision_changed"] is False
    assert execution.to_dict()["shadow"] == execution.comparison
    assert json.loads((request.output / "policy-comparison.json").read_text()) == (
        execution.comparison
    )
    assert verify_evidence_bundle(request.output, signing_key=request.signing_key)["verified"]
    assert "service-test-only" not in repr(request)


def test_service_rejects_input_before_parsing_and_publishing(
    project_root: Path, tmp_path: Path, monkeypatch
) -> None:
    from finguard import gate_service
    from finguard.snapshots import InputSnapshot

    monkeypatch.setattr(gate_service, "InputSnapshot", lambda: InputSnapshot(max_file_bytes=1))
    output = tmp_path / "evidence"
    with pytest.raises(FinGuardError, match="file limit"):
        execute_gate(
            GateRequest(policy=project_root / "policies/merge-request.toml", output=output)
        )
    assert not output.exists()
