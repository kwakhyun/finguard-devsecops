from __future__ import annotations

import datetime as dt
import json
from dataclasses import replace
from pathlib import Path

import pytest

from finguard.attestation import create_scan_attestation, load_scan_attestation
from finguard.change import ChangeRequest
from finguard.cli import _snapshot_evidence_directory, _snapshot_file
from finguard.config import Policy, load_exceptions
from finguard.errors import (
    ConfigurationError,
    EvidenceVerificationError,
    ReportParseError,
)
from finguard.evidence import create_evidence_bundle, verify_evidence_bundle
from finguard.models import Decision, GateResult, ScanResult, ScanStatus
from finguard.parsers import parse_report
from finguard.release import ReleaseSubject

NOW = dt.datetime(2026, 9, 1, tzinfo=dt.UTC)


def _minimal_result() -> GateResult:
    return GateResult(
        decision=Decision.PASS,
        policy_id="TEST",
        policy_version="1",
        violations=[],
        active_findings=[],
        excepted_findings=[],
        scan_results=[],
        metrics={},
        evaluated_at=NOW.isoformat(),
    )


def _scan_attestation(tmp_path: Path, *, exit_code: int = 0, target_uri: str = ""):
    report = tmp_path / "ruff.json"
    report.write_text("[]\n", encoding="utf-8")
    output = tmp_path / "ruff.attestation.json"
    create_scan_attestation(
        output,
        report_path=report,
        scanner="ruff",
        category="lint",
        scanner_version="1.0.0",
        scanner_uri="toolcache://ruff/1.0.0",
        source_commit="a" * 40,
        image_digest="",
        ruleset_sha256="b" * 64,
        command_sha256="c" * 64,
        ci_job_id="job-100",
        runner_id="gitlab:onprem-protected",
        exit_code=exit_code,
        complete=True,
        target_uri=target_uri,
        started_at=NOW,
        finished_at=NOW + dt.timedelta(minutes=1),
        signing_key=b"scan-key",
        key_id="scan-key-v1",
    )
    return report, output


def test_scan_signer_key_id_is_inside_signed_payload(tmp_path: Path) -> None:
    report, output = _scan_attestation(tmp_path)
    envelope = json.loads(output.read_text(encoding="utf-8"))
    assert envelope["payload"]["key_id"] == "scan-key-v1"
    envelope["signature"]["key_id"] = "allowed-but-not-signed"
    output.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="does not match signed payload"):
        load_scan_attestation(output, report_path=report, signing_key=b"scan-key")


def test_scan_attestation_rejects_non_object_signature(tmp_path: Path) -> None:
    _, output = _scan_attestation(tmp_path)
    envelope = json.loads(output.read_text(encoding="utf-8"))
    envelope["signature"] = "not-an-object"
    output.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="signature must be an object"):
        load_scan_attestation(output)


def test_gate_input_snapshot_is_independent_from_mutable_source(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_text('{"decision":"pass"}\n', encoding="utf-8")
    snapshot = _snapshot_file(source, tmp_path / "private/snapshot.json")

    source.write_text('{"decision":"fail"}\n', encoding="utf-8")

    assert snapshot.read_text(encoding="utf-8") == '{"decision":"pass"}\n'


def test_deployment_evidence_snapshot_is_independent_from_source(tmp_path: Path) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    manifest = source / "manifest.json"
    manifest.write_text('{"decision":"pass"}\n', encoding="utf-8")
    snapshot = _snapshot_evidence_directory(source, tmp_path / "private/evidence")

    manifest.write_text('{"decision":"fail"}\n', encoding="utf-8")

    assert (snapshot / "manifest.json").read_text(encoding="utf-8") == ('{"decision":"pass"}\n')


def test_scan_provenance_serializes_exit_code_and_target(tmp_path: Path) -> None:
    report, output = _scan_attestation(
        tmp_path,
        exit_code=1,
        target_uri="https://service.example/health",
    )
    provenance = load_scan_attestation(output, report_path=report, signing_key=b"scan-key")

    assert provenance.to_dict()["exit_code"] == 1
    assert provenance.to_dict()["target_uri"] == "https://service.example/health"


def test_scan_attestation_output_rejects_symlinked_parent(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    with pytest.raises(EvidenceVerificationError, match="symlink scan attestation"):
        _scan_attestation(linked)


def test_normalized_report_cannot_self_assert_verified_provenance(tmp_path: Path) -> None:
    report = tmp_path / "normalized.json"
    result = ScanResult(scanner="native", category="lint", status=ScanStatus.PASSED)
    payload = result.to_dict()
    payload["provenance"] = {
        "predicate_type": "https://finguard.dev/attestations/scan/v3",
        "report_sha256": "a" * 64,
        "scanner": "native",
        "category": "lint",
        "scanner_version": "1.0",
        "scanner_uri": "attacker://self-asserted",
        "source_commit": "b" * 40,
        "image_digest": "",
        "ruleset_sha256": "c" * 64,
        "database_sha256": "",
        "command_sha256": "d" * 64,
        "ci_job_id": "forged",
        "runner_id": "gitlab:onprem-protected",
        "exit_code": 0,
        "target_uri": "",
        "started_at": NOW.isoformat(),
        "finished_at": NOW.isoformat(),
        "complete": True,
        "signature_present": True,
        "signature_verified": True,
        "key_id": "onprem-scan-attestor-v1",
    }
    report.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReportParseError, match="cannot carry trusted provenance"):
        parse_report(report, "normalized")


@pytest.mark.parametrize(
    "payload",
    [
        {"version": "2.1.0", "runs": [None]},
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "scanner"}}, "results": [None]}],
        },
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "scanner",
                            "rules": [
                                {
                                    "id": "RULE-1",
                                    "properties": {"security-severity": "NaN"},
                                }
                            ],
                        }
                    },
                    "results": [{"ruleId": "RULE-1", "message": {"text": "unsafe behavior"}}],
                }
            ],
        },
    ],
)
def test_sarif_malformed_nested_records_fail_closed(tmp_path: Path, payload: object) -> None:
    report = tmp_path / "result.sarif"
    report.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReportParseError):
        parse_report(report, "sarif")


@pytest.mark.parametrize(
    ("name", "payload", "report_type"),
    [
        ("semgrep.json", {"results": ["bad"], "errors": []}, "semgrep"),
        ("semgrep-empty.json", {"results": [{}], "errors": []}, "semgrep"),
        (
            "semgrep-error.json",
            {"version": "1.0", "results": [], "errors": [42]},
            "semgrep",
        ),
        ("ruff.json", [{}], "ruff"),
        ("trivy.json", {"Results": [{"Vulnerabilities": ["bad"]}]}, "trivy"),
        (
            "trivy-empty.json",
            {
                "SchemaVersion": 2,
                "Results": [{"Target": "requirements.lock", "Vulnerabilities": [{}]}],
            },
            "trivy",
        ),
        ("trivy-schema.json", {"SchemaVersion": 1, "Results": []}, "trivy"),
        ("pip-audit.json", {}, "pip-audit"),
        (
            "pip-audit-empty.json",
            {"dependencies": [{"name": "demo", "version": "1.0", "vulns": [{}]}]},
            "pip-audit",
        ),
        (
            "zap.json",
            {"site": [{"@name": "https://service.example/", "alerts": ["bad"]}]},
            "zap",
        ),
        (
            "zap-empty.json",
            {"site": [{"@name": "https://service.example/", "alerts": [{}]}]},
            "zap",
        ),
    ],
)
def test_json_scanners_do_not_skip_malformed_records(
    tmp_path: Path, name: str, payload: object, report_type: str
) -> None:
    report = tmp_path / name
    report.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReportParseError):
        parse_report(report, report_type)


def test_zap_instance_cannot_escape_scanned_target_origin(tmp_path: Path) -> None:
    report = tmp_path / "zap.json"
    report.write_text(
        json.dumps(
            {
                "site": [
                    {
                        "@name": "https://service.example/",
                        "alerts": [
                            {
                                "pluginid": "10020",
                                "alert": "Missing security header",
                                "riskcode": "2",
                                "instances": [{"uri": "https://other.example/private"}],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReportParseError, match="target origin"):
        parse_report(report)


def test_nonfinite_json_number_is_rejected(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    report.write_text('{"Results": NaN}', encoding="utf-8")

    with pytest.raises(ReportParseError, match="non-finite"):
        parse_report(report, "trivy")


def test_duplicate_json_object_key_is_rejected(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    report.write_text('{"Results": [], "Results": []}', encoding="utf-8")

    with pytest.raises(ReportParseError, match="duplicate JSON object key"):
        parse_report(report, "trivy")


def test_excessive_json_nesting_fails_as_a_report_error(tmp_path: Path) -> None:
    report = tmp_path / "ruff.json"
    report.write_text("[" * 2_000 + "0" + "]" * 2_000, encoding="utf-8")

    with pytest.raises(ReportParseError, match="safe parser depth"):
        parse_report(report, "ruff")


@pytest.mark.parametrize("payload", [{"site": []}, {"site": [{"@name": "https://a/"}]}])
def test_zap_requires_a_scanned_site_and_alert_inventory(tmp_path: Path, payload: object) -> None:
    report = tmp_path / "zap.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReportParseError):
        parse_report(report, "zap")


def test_zap_rejects_out_of_range_risk_code(tmp_path: Path) -> None:
    report = tmp_path / "zap.json"
    report.write_text(
        json.dumps(
            {
                "site": [
                    {
                        "@name": "https://service.example/",
                        "alerts": [
                            {
                                "pluginid": "10020",
                                "alert": "Malformed severity",
                                "riskcode": "99",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReportParseError, match="0 through 4"):
        parse_report(report, "zap")


@pytest.mark.parametrize(
    "xml",
    [
        '<coverage line-rate="NaN" />',
        '<coverage line-rate="1.1" />',
        '<coverage line-rate="0.9" />',
        '<coverage line-rate="0.9" lines-valid="10" lines-covered="8" />',
        (
            '<coverage line-rate="0.8" branch-rate="0.5" lines-valid="10" '
            'lines-covered="8" branches-valid="4" branches-covered="1" />'
        ),
    ],
)
def test_coverage_invalid_or_inconsistent_metrics_fail_closed(tmp_path: Path, xml: str) -> None:
    report = tmp_path / "coverage.xml"
    report.write_text(xml, encoding="utf-8")

    with pytest.raises(ReportParseError):
        parse_report(report)


def test_coverage_threshold_uses_raw_counts_without_rounding_up(tmp_path: Path) -> None:
    report = tmp_path / "coverage.xml"
    report.write_text(
        '<coverage line-rate="0.84995" lines-valid="20000" lines-covered="16999" />',
        encoding="utf-8",
    )

    result = parse_report(report)

    assert result.metrics["coverage_percent"] == pytest.approx(84.995)
    assert result.metrics["coverage_percent"] < 85


@pytest.mark.parametrize(
    "xml",
    [
        '<testsuite tests="-1" failures="0" errors="0" skipped="0" />',
        '<testsuite tests="42" failures="0" errors="0" skipped="0" />',
        (
            '<testsuite tests="1" failures="0" errors="0" skipped="0">'
            '<testcase name="broken"><failure message="failed" /></testcase>'
            "</testsuite>"
        ),
    ],
)
def test_junit_invalid_counts_fail_closed(tmp_path: Path, xml: str) -> None:
    report = tmp_path / "junit.xml"
    report.write_text(xml, encoding="utf-8")

    with pytest.raises(ReportParseError):
        parse_report(report)


def test_cyclonedx_uses_highest_rating_and_all_affected_components(tmp_path: Path) -> None:
    report = tmp_path / "sbom.cdx.json"
    report.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "pkg:pypi/a@1",
                        "name": "a",
                        "version": "1",
                        "licenses": [{"expression": "MIT OR Apache-2.0"}],
                    },
                    {
                        "bom-ref": "pkg:pypi/b@2",
                        "name": "b",
                        "version": "2",
                        "licenses": [{"license": {"id": "MIT"}}],
                    },
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2099-2000",
                        "ratings": [{"severity": "low"}, {"severity": "high"}],
                        "affects": [{"ref": "pkg:pypi/a@1"}, {"ref": "pkg:pypi/b@2"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = parse_report(report)
    vulnerabilities = [item for item in result.findings if item.category == "sca"]
    assert result.metrics["component_count"] == 2
    assert {item.component for item in vulnerabilities} == {"a", "b"}
    assert {item.severity.label for item in vulnerabilities} == {"high"}
    assert next(item for item in result.findings if item.component == "a").license_id == (
        "MIT OR Apache-2.0"
    )


def test_cyclonedx_duplicate_component_reference_is_rejected(tmp_path: Path) -> None:
    report = tmp_path / "duplicate.cdx.json"
    report.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"bom-ref": "duplicate", "name": "a", "version": "1"},
                    {"bom-ref": "duplicate", "name": "b", "version": "2"},
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReportParseError, match="duplicate CycloneDX"):
        parse_report(report)


def test_policy_rejects_quoted_boolean_and_unknown_key(project_root: Path, tmp_path: Path) -> None:
    source = (project_root / "policies/merge-request.toml").read_text(encoding="utf-8")
    quoted = tmp_path / "quoted.toml"
    quoted.write_text(
        source.replace("fail_on_scanner_error = true", 'fail_on_scanner_error = "false"'),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="must be a boolean"):
        Policy.load(quoted)

    unknown = tmp_path / "unknown.toml"
    unknown.write_text(
        source.replace("[gates]", "[gates]\nunknown_setting = true"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="unknown keys"):
        Policy.load(unknown)

    huge_duration = tmp_path / "huge-duration.toml"
    huge_duration.write_text(
        source.replace("maximum_evidence_age_hours = 24", "maximum_evidence_age_hours = 1e308"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="supported duration"):
        Policy.load(huge_duration)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            'block_severities = ["critical", "high"]',
            'block_severities = ["critical", "high", "ERROR"]',
        ),
        (
            "[gates.max_findings]\nmedium = 0",
            "[gates.max_findings]\nmedium = 0\nMEDIUM = 1",
        ),
        (
            'approval_roles = ["security", "release_manager"]',
            'approval_roles = ["security", "SECURITY"]',
        ),
        (
            '  "0BSD",\n',
            '  "0BSD",\n  "mit",\n',
        ),
    ],
)
def test_policy_rejects_semantically_duplicate_controls(
    project_root: Path,
    tmp_path: Path,
    needle: str,
    replacement: str,
) -> None:
    source = (project_root / "policies/financial-baseline.toml").read_text(encoding="utf-8")
    path = tmp_path / "ambiguous-policy.toml"
    path.write_text(source.replace(needle, replacement), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="duplicate normalized"):
        Policy.load(path)


def test_policy_numeric_control_bounds_fail_closed(project_root: Path) -> None:
    policy = Policy.load(project_root / "policies/financial-baseline.toml")
    invalid = [
        replace(policy, policy_id=""),
        replace(policy, gate=replace(policy.gate, min_coverage_percent=101)),
        replace(policy, gate=replace(policy.gate, max_test_failures=-1)),
        replace(policy, gate=replace(policy.gate, minimum_test_count=-1)),
        replace(policy, gate=replace(policy.gate, minimum_sbom_components=-1)),
        replace(policy, change=replace(policy.change, minimum_approvals=-1)),
        replace(policy, change=replace(policy.change, maximum_deployment_window_hours=0)),
        replace(policy, change=replace(policy.change, maximum_evidence_age_hours=0)),
        replace(policy, provenance=replace(policy.provenance, max_report_age_hours=0)),
        replace(policy, provenance=replace(policy.provenance, max_database_age_hours=0)),
        replace(policy, provenance=replace(policy.provenance, clock_skew_minutes=61)),
        replace(policy, exceptions=replace(policy.exceptions, max_validity_days=0)),
        replace(policy, exceptions=replace(policy.exceptions, max_renewals=-1)),
        replace(policy, exceptions=replace(policy.exceptions, min_reason_length=0)),
        replace(policy, vex=replace(policy.vex, minimum_detail_length=-1)),
        replace(policy, vex=replace(policy.vex, max_validity_days=0)),
    ]

    for candidate in invalid:
        with pytest.raises(ConfigurationError):
            candidate._validate()


def test_change_and_release_inputs_reject_schema_drift(project_root: Path, tmp_path: Path) -> None:
    scenario = project_root / "examples/scenarios/pass"
    change_text = (scenario / "change.toml").read_text(encoding="utf-8")
    unknown_change = tmp_path / "unknown-change.toml"
    unknown_change.write_text(
        change_text.replace('risk = "medium"', 'risk = "medium"\nunknown = true'),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="unknown fields"):
        ChangeRequest.load(unknown_change)

    naive_change = tmp_path / "naive-change.toml"
    naive_change.write_text(
        change_text.replace("2026-09-01T22:00:00+09:00", "2026-09-01T22:00:00"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="timezone"):
        ChangeRequest.load(naive_change)

    partial_window = tmp_path / "partial-window.toml"
    partial_window.write_text(
        change_text.replace("window_end = 2026-09-01T23:00:00+09:00\n", ""),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="provided together"):
        ChangeRequest.load(partial_window)

    release_payload = json.loads((scenario / "release-subject.json").read_text(encoding="utf-8"))
    release_payload["unknown"] = True
    release_path = tmp_path / "release.json"
    release_path.write_text(json.dumps(release_payload), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="unknown fields"):
        ReleaseSubject.load(release_path)


@pytest.mark.parametrize("field", ["created_at", "expires_at"])
def test_exception_datetimes_require_a_timezone(tmp_path: Path, field: str) -> None:
    exception = tmp_path / "exceptions.toml"
    created_at = "2026-09-01T00:00:00Z"
    expires_at = "2026-09-02T00:00:00Z"
    if field == "created_at":
        created_at = "2026-09-01T00:00:00"
    else:
        expires_at = "2026-09-02T00:00:00"
    exception.write_text(
        f"""
[[exceptions]]
id = "EXC-NAIVE"
fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
reason = "A documented temporary exception requiring explicit timezone handling"
owner = "owner@example.com"
approver = "security@example.com"
created_at = {created_at}
expires_at = {expires_at}
ticket = "RISK-1"
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="timezone"):
        load_exceptions(exception)


def test_forged_ownership_marker_does_not_authorize_force_replacement(
    tmp_path: Path,
) -> None:
    target = tmp_path / "important"
    target.mkdir()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    bundle_id = "a" * 32
    (target / ".finguard-evidence").write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "bundle_type": "finguard-evidence",
                "bundle_id": bundle_id,
            }
        ),
        encoding="utf-8",
    )
    (target / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "3.0",
                "bundle_type": "finguard-evidence",
                "bundle_id": bundle_id,
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "policy.toml"
    policy.write_text("policy", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="not owned"):
        create_evidence_bundle(
            target,
            result=_minimal_result(),
            policy_path=policy,
            report_paths=[],
            force=True,
        )
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_evidence_verification_is_closed_world(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text("policy", encoding="utf-8")
    output = tmp_path / "evidence"
    create_evidence_bundle(
        output,
        result=_minimal_result(),
        policy_path=policy,
        report_paths=[],
    )
    (output / "untracked.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="unmanifested"):
        verify_evidence_bundle(output)


def test_evidence_hmac_signer_identity_is_covered_by_signature(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text("policy", encoding="utf-8")
    output = tmp_path / "evidence"
    create_evidence_bundle(
        output,
        result=_minimal_result(),
        policy_path=policy,
        report_paths=[],
        signing_key=b"evidence-key",
        signing_key_id="evidence-key-v1",
    )
    signature = json.loads((output / "manifest.sig").read_text(encoding="utf-8"))
    signature["key_id"] = "tampered-key-id"
    (output / "manifest.sig").write_text(json.dumps(signature), encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="signature mismatch"):
        verify_evidence_bundle(output, signing_key=b"evidence-key")


def test_unverified_hmac_sidecar_must_still_have_a_valid_structure(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text("policy", encoding="utf-8")
    output = tmp_path / "evidence"
    create_evidence_bundle(
        output,
        result=_minimal_result(),
        policy_path=policy,
        report_paths=[],
        signing_key=b"evidence-key",
        signing_key_id="evidence-key-v1",
    )
    signature = json.loads((output / "manifest.sig").read_text(encoding="utf-8"))
    signature["value"] = "not-a-sha256-signature"
    (output / "manifest.sig").write_text(json.dumps(signature), encoding="utf-8")

    with pytest.raises(EvidenceVerificationError, match="signature value is invalid"):
        verify_evidence_bundle(output)


def test_evidence_captures_vex_payload_and_signature_bundle(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text("policy", encoding="utf-8")
    vex = tmp_path / "vex.json"
    vex.write_text("{}\n", encoding="utf-8")
    signature = tmp_path / "vex.sigstore.json"
    signature.write_text("{}\n", encoding="utf-8")
    output = tmp_path / "evidence"

    create_evidence_bundle(
        output,
        result=_minimal_result(),
        policy_path=policy,
        report_paths=[],
        vex_attestation_path=vex,
        vex_signature_path=signature,
    )

    assert (output / "inputs/vex-attestation.json").is_file()
    assert (output / "inputs/vex-attestation.sigstore.json").is_file()
    assert verify_evidence_bundle(output)["verified"] is True


def test_evidence_rejects_input_below_symlinked_parent(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "policy.toml").write_text("policy", encoding="utf-8")
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    with pytest.raises(ConfigurationError, match="symlink evidence input"):
        create_evidence_bundle(
            tmp_path / "evidence",
            result=_minimal_result(),
            policy_path=linked / "policy.toml",
            report_paths=[],
        )


def test_normalized_report_output_refuses_symlink_path(tmp_path: Path) -> None:
    target = tmp_path / "preserve.json"
    target.write_text("preserve\n", encoding="utf-8")
    output = tmp_path / "report.json"
    output.symlink_to(target)

    with pytest.raises(ConfigurationError, match="symlink normalized scan report"):
        ScanResult(scanner="native", category="lint", status=ScanStatus.PASSED).write_json(output)
    assert target.read_text(encoding="utf-8") == "preserve\n"
