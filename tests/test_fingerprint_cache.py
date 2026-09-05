from __future__ import annotations

from dataclasses import replace

import pytest

from finguard.models import Finding, Severity


def test_fingerprint_reuses_hash_but_tracks_mutable_aliases(monkeypatch):
    import finguard.models as models

    calls = 0
    original = models.hashlib.sha256

    def count_hash(value):
        nonlocal calls
        calls += 1
        return original(value)

    monkeypatch.setattr(models.hashlib, "sha256", count_hash)
    aliases = ["GHSA-original"]
    finding = Finding(
        "test",
        "sca",
        "GHSA-original",
        Severity.HIGH,
        "issue",
        component="pkg",
        metadata={"aliases": aliases},
    )
    first = finding.fingerprint
    assert finding.fingerprint == first
    assert calls == 1
    aliases.append("CVE-2099-1000")
    assert finding.fingerprint != first
    assert calls == 2
    assert replace(finding, installed_version="2").fingerprint != finding.fingerprint
    assert Finding.from_dict(finding.to_dict()).fingerprint == finding.fingerprint


@pytest.mark.parametrize("field", ["method", "parameter"])
def test_fingerprint_invalidates_when_dast_identity_changes(field):
    metadata = {"method": "GET", "parameter": "q"}
    finding = Finding("test", "dast", "RULE", Severity.HIGH, "issue", metadata=metadata)
    first = finding.fingerprint
    metadata[field] = "changed"
    assert finding.fingerprint != first
    assert Finding.from_dict(finding.to_dict()).fingerprint == finding.fingerprint
