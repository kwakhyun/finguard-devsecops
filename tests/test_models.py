from __future__ import annotations

from finguard.models import Finding, ScanResult, ScanStatus, Severity


def test_severity_aliases_are_normalized() -> None:
    assert Severity.parse("ERROR") is Severity.HIGH
    assert Severity.parse("warning") is Severity.MEDIUM
    assert Severity.parse("4") is Severity.CRITICAL
    assert Severity.parse("not-a-severity") is Severity.UNKNOWN


def test_fingerprint_is_stable_when_message_changes() -> None:
    base = Finding(
        scanner="semgrep",
        category="sast",
        rule_id="rule.one",
        severity=Severity.HIGH,
        message="old wording",
        location="src/app.py:10",
    )
    revised = Finding(
        scanner="SEMGREP",
        category="SAST",
        rule_id="RULE.ONE",
        severity=Severity.CRITICAL,
        message="new scanner wording",
        location="src\\app.py:10",
    )
    assert base.fingerprint == revised.fingerprint


def test_fingerprint_does_not_merge_case_sensitive_paths_or_license_versions() -> None:
    upper_path = Finding(
        scanner="semgrep",
        category="sast",
        rule_id="rule.one",
        severity=Severity.MEDIUM,
        message="finding",
        location="src/Foo.py:10",
    )
    lower_path = Finding(
        scanner="semgrep",
        category="sast",
        rule_id="rule.one",
        severity=Severity.MEDIUM,
        message="finding",
        location="src/foo.py:10",
    )
    version_one = Finding(
        scanner="cyclonedx",
        category="license",
        rule_id="license.detected",
        severity=Severity.INFO,
        message="license",
        component="shared-library",
        installed_version="1.0.0",
        license_id="MIT",
        metadata={"kind": "dependency_license"},
    )
    version_two = Finding(
        scanner="cyclonedx",
        category="license",
        rule_id="license.detected",
        severity=Severity.INFO,
        message="license",
        component="shared-library",
        installed_version="2.0.0",
        license_id="MIT",
        metadata={"kind": "dependency_license"},
    )

    assert upper_path.fingerprint != lower_path.fingerprint
    assert version_one.fingerprint != version_two.fingerprint


def test_normalized_scan_round_trip() -> None:
    original = ScanResult(
        scanner="native",
        category="sast",
        status=ScanStatus.FINDINGS,
        findings=[
            Finding(
                scanner="native",
                category="sast",
                rule_id="rule",
                severity=Severity.MEDIUM,
                message="message",
            )
        ],
        metrics={"files": 3},
    )
    restored = ScanResult.from_dict(original.to_dict())
    assert restored.status is ScanStatus.FINDINGS
    assert restored.findings[0].severity is Severity.MEDIUM
    assert restored.metrics == {"files": 3}
