"""Adapters for JSON reports emitted by common DevSecOps scanners."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from pathlib import Path

from finguard.errors import EvidenceVerificationError, ReportParseError
from finguard.models import Finding, ScanResult, ScanStatus, Severity
from finguard.urls import canonical_dast_location, canonical_http_url

from .common import generated_at, location


def _status(findings: list[Finding], errors: list[str] | None = None) -> ScanStatus:
    if errors:
        return ScanStatus.ERROR
    return ScanStatus.FINDINGS if findings else ScanStatus.PASSED


def _object_list(value: object, field: str, path: Path) -> list[dict[str, object]]:
    """Return a scanner array without silently discarding malformed records."""

    if value is None:
        return []
    if not isinstance(value, list):
        raise ReportParseError(f"{field} must be an array in {path}")
    result: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ReportParseError(f"{field}[{index}] must be an object in {path}")
        result.append(item)
    return result


def _object(value: object, field: str, path: Path) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ReportParseError(f"{field} must be an object in {path}")
    return value


def _required_string(value: object, field: str, path: Path) -> str:
    """Return a non-empty string for an integrity-relevant scanner field."""

    if not isinstance(value, str) or not value.strip():
        raise ReportParseError(f"{field} must be a non-empty string in {path}")
    return value.strip()


def _optional_string(value: object, field: str, path: Path) -> str:
    """Normalize an optional string without converting JSON null into ``"None"``."""

    if value is None:
        return ""
    if not isinstance(value, str):
        raise ReportParseError(f"{field} must be a string or null in {path}")
    return value.strip()


def _required_identifier(value: object, field: str, path: Path) -> str:
    """Accept textual or integer IDs while rejecting booleans and empty values."""

    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ReportParseError(f"{field} must be a non-empty identifier in {path}")
    identifier = str(value).strip()
    if not identifier:
        raise ReportParseError(f"{field} must be a non-empty identifier in {path}")
    return identifier


def _positive_integer(value: object, field: str, path: Path) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ReportParseError(f"{field} must be a positive integer in {path}")
    return value


def _string_list(value: object, field: str, path: Path) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ReportParseError(f"{field} must be an array of strings in {path}")
    return value


def parse_normalized(data: object, path: Path) -> ScanResult:
    if not isinstance(data, dict):
        raise ReportParseError(f"normalized report must be a JSON object: {path}")
    if data.get("provenance") is not None:
        raise ReportParseError(
            f"normalized report cannot carry trusted provenance; use --attestations: {path}"
        )
    try:
        result = ScanResult.from_dict(data)
    except (TypeError, ValueError, KeyError, EvidenceVerificationError) as exc:
        raise ReportParseError(f"invalid normalized report {path}: {exc}") from exc
    result.source = str(path)
    if not result.generated_at:
        result.generated_at = generated_at(path)
    return result


def parse_semgrep(data: object, path: Path) -> ScanResult:
    if (
        not isinstance(data, dict)
        or "results" not in data
        or not isinstance(data.get("results"), list)
        or "errors" not in data
        or not isinstance(data.get("errors"), list)
    ):
        raise ReportParseError(f"invalid Semgrep report: {path}")
    _required_string(data.get("version"), "version", path)
    findings: list[Finding] = []
    for index, item in enumerate(_object_list(data.get("results", []), "results", path)):
        extra = _object(item.get("extra", {}), f"results[{index}].extra", path)
        start = _object(item.get("start", {}), f"results[{index}].start", path)
        metadata = _object(extra.get("metadata", {}), f"results[{index}].extra.metadata", path)
        cwe_raw = metadata.get("cwe", [])
        if isinstance(cwe_raw, str):
            cwe_raw = [cwe_raw]
        if not isinstance(cwe_raw, list):
            raise ReportParseError(f"results[{index}].extra.metadata.cwe is invalid in {path}")
        if not all(isinstance(value, str) and value.strip() for value in cwe_raw):
            raise ReportParseError(
                f"results[{index}].extra.metadata.cwe must contain strings in {path}"
            )
        rule_id = _required_string(item.get("check_id"), f"results[{index}].check_id", path)
        message = _required_string(extra.get("message"), f"results[{index}].extra.message", path)
        severity_text = _required_string(
            extra.get("severity"), f"results[{index}].extra.severity", path
        )
        source_path = _required_string(item.get("path"), f"results[{index}].path", path)
        line = _positive_integer(start.get("line"), f"results[{index}].start.line", path)
        column = _positive_integer(start.get("col"), f"results[{index}].start.col", path)
        findings.append(
            Finding(
                scanner="semgrep",
                category="sast",
                rule_id=rule_id,
                severity=Severity.parse(severity_text),
                message=message,
                location=location(source_path, line, column),
                cwe=tuple(value.strip() for value in cwe_raw),
                metadata={
                    "confidence": metadata.get("confidence", ""),
                    "technology": metadata.get("technology", []),
                },
            )
        )
    errors_raw = data.get("errors", [])
    if not isinstance(errors_raw, list):
        raise ReportParseError(f"errors must be an array in {path}")
    errors: list[str] = []
    for index, item in enumerate(errors_raw):
        if isinstance(item, str):
            errors.append(item.strip() or f"Semgrep error record {index}")
        elif isinstance(item, dict):
            errors.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
        else:
            raise ReportParseError(f"errors[{index}] must be a string or object in {path}")
    return ScanResult(
        scanner="semgrep",
        category="sast",
        status=_status(findings, errors),
        findings=findings,
        errors=errors,
        source=str(path),
        generated_at=generated_at(path),
    )


def parse_ruff(data: object, path: Path) -> ScanResult:
    if not isinstance(data, list):
        raise ReportParseError(f"invalid Ruff report: {path}")
    findings: list[Finding] = []
    for index, item in enumerate(_object_list(data, "ruff", path)):
        loc = _object(item.get("location", {}), f"ruff[{index}].location", path)
        code = _required_string(item.get("code"), f"ruff[{index}].code", path)
        message = _required_string(item.get("message"), f"ruff[{index}].message", path)
        filename = _required_string(item.get("filename"), f"ruff[{index}].filename", path)
        row = _positive_integer(loc.get("row"), f"ruff[{index}].location.row", path)
        column = _positive_integer(loc.get("column"), f"ruff[{index}].location.column", path)
        severity = Severity.MEDIUM if code.startswith(("E", "F", "S", "B")) else Severity.LOW
        findings.append(
            Finding(
                scanner="ruff",
                category="lint",
                rule_id=code,
                severity=severity,
                message=message,
                location=location(filename, row, column),
                metadata={"url": item.get("url", "")},
            )
        )
    return ScanResult(
        scanner="ruff",
        category="lint",
        status=_status(findings),
        findings=findings,
        source=str(path),
        generated_at=generated_at(path),
    )


def parse_trivy(data: object, path: Path) -> ScanResult:
    if (
        not isinstance(data, dict)
        or "Results" not in data
        or not isinstance(data.get("Results"), list)
    ):
        raise ReportParseError(f"invalid Trivy report: {path}")
    schema_version = data.get("SchemaVersion")
    if isinstance(schema_version, bool) or schema_version != 2:
        raise ReportParseError(f"unsupported Trivy SchemaVersion in {path}")
    findings: list[Finding] = []
    for result_index, result in enumerate(_object_list(data.get("Results", []), "Results", path)):
        target = _required_string(result.get("Target"), f"Results[{result_index}].Target", path)
        for vulnerability_index, vulnerability in enumerate(
            _object_list(
                result.get("Vulnerabilities"), f"Results[{result_index}].Vulnerabilities", path
            )
        ):
            cwe = vulnerability.get("CweIDs", [])
            cwe = _string_list(
                cwe,
                f"Results[{result_index}].Vulnerabilities[{vulnerability_index}].CweIDs",
                path,
            )
            prefix = f"Results[{result_index}].Vulnerabilities[{vulnerability_index}]"
            vulnerability_id = _required_string(
                vulnerability.get("VulnerabilityID"), f"{prefix}.VulnerabilityID", path
            )
            package_name = _required_string(vulnerability.get("PkgName"), f"{prefix}.PkgName", path)
            installed_version = _required_string(
                vulnerability.get("InstalledVersion"), f"{prefix}.InstalledVersion", path
            )
            severity_text = _required_string(
                vulnerability.get("Severity"), f"{prefix}.Severity", path
            )
            findings.append(
                Finding(
                    scanner="trivy",
                    category="sca",
                    rule_id=vulnerability_id,
                    severity=Severity.parse(severity_text),
                    message=str(
                        vulnerability.get("Title")
                        or vulnerability.get("Description")
                        or "Dependency vulnerability"
                    ),
                    location=target,
                    component=package_name,
                    installed_version=installed_version,
                    fixed_version=_optional_string(
                        vulnerability.get("FixedVersion"), f"{prefix}.FixedVersion", path
                    ),
                    cwe=tuple(str(value) for value in cwe),
                    metadata={"primary_url": vulnerability.get("PrimaryURL", "")},
                )
            )
        for misconfiguration_index, misconfiguration in enumerate(
            _object_list(
                result.get("Misconfigurations"),
                f"Results[{result_index}].Misconfigurations",
                path,
            )
        ):
            prefix = f"Results[{result_index}].Misconfigurations[{misconfiguration_index}]"
            rule_id = _required_string(misconfiguration.get("ID"), f"{prefix}.ID", path)
            severity_text = _required_string(
                misconfiguration.get("Severity"), f"{prefix}.Severity", path
            )
            findings.append(
                Finding(
                    scanner="trivy",
                    category="iac",
                    rule_id=rule_id,
                    severity=Severity.parse(severity_text),
                    message=str(misconfiguration.get("Title", "Infrastructure misconfiguration")),
                    location=target,
                    metadata={"resolution": misconfiguration.get("Resolution", "")},
                )
            )
        for secret_index, secret in enumerate(
            _object_list(result.get("Secrets"), f"Results[{result_index}].Secrets", path)
        ):
            prefix = f"Results[{result_index}].Secrets[{secret_index}]"
            rule_id = _required_string(secret.get("RuleID"), f"{prefix}.RuleID", path)
            severity_text = _required_string(secret.get("Severity"), f"{prefix}.Severity", path)
            findings.append(
                Finding(
                    scanner="trivy",
                    category="secret",
                    rule_id=rule_id,
                    severity=Severity.parse(severity_text),
                    message=str(secret.get("Title", "Secret detected")),
                    location=location(target, secret.get("StartLine")),
                )
            )
        for license_index, license_item in enumerate(
            _object_list(result.get("Licenses"), f"Results[{result_index}].Licenses", path)
        ):
            prefix = f"Results[{result_index}].Licenses[{license_index}]"
            license_id = _required_string(license_item.get("Name"), f"{prefix}.Name", path)
            package_name = _required_string(license_item.get("PkgName"), f"{prefix}.PkgName", path)
            package_version = _optional_string(
                license_item.get("PkgVersion", license_item.get("Version")),
                f"{prefix}.PkgVersion",
                path,
            )
            findings.append(
                Finding(
                    scanner="trivy",
                    category="license",
                    rule_id="license.detected",
                    severity=Severity.INFO,
                    message=f"License detected: {license_id}",
                    location=target,
                    component=package_name,
                    installed_version=package_version,
                    license_id=license_id,
                    metadata={"kind": "dependency_license"},
                )
            )
    return ScanResult(
        scanner="trivy",
        category="sca",
        status=_status(findings),
        findings=findings,
        source=str(path),
        generated_at=generated_at(path),
    )


def parse_pip_audit(data: object, path: Path) -> ScanResult:
    dependencies: object
    if isinstance(data, dict):
        if "dependencies" not in data:
            raise ReportParseError(f"dependencies is required in pip-audit report: {path}")
        dependencies = data.get("dependencies")
    else:
        dependencies = data
    if not isinstance(dependencies, list):
        raise ReportParseError(f"invalid pip-audit report: {path}")
    findings: list[Finding] = []
    for dependency_index, dependency in enumerate(_object_list(dependencies, "dependencies", path)):
        name = _required_string(
            dependency.get("name"), f"dependencies[{dependency_index}].name", path
        )
        version = _required_string(
            dependency.get("version"), f"dependencies[{dependency_index}].version", path
        )
        for vulnerability_index, vulnerability in enumerate(
            _object_list(
                dependency.get("vulns", []), f"dependencies[{dependency_index}].vulns", path
            )
        ):
            prefix = f"dependencies[{dependency_index}].vulns[{vulnerability_index}]"
            vulnerability_id = _required_string(vulnerability.get("id"), f"{prefix}.id", path)
            fix_versions = vulnerability.get("fix_versions", []) or []
            fix_versions = _string_list(fix_versions, f"{prefix}.fix_versions", path)
            aliases = _string_list(vulnerability.get("aliases", []), f"{prefix}.aliases", path)
            findings.append(
                Finding(
                    scanner="pip-audit",
                    category="sca",
                    rule_id=vulnerability_id,
                    # pip-audit JSON does not guarantee a CVSS severity. Treating an
                    # unranked dependency vulnerability as high is fail-safe.
                    severity=Severity.HIGH,
                    message=str(vulnerability.get("description", "Dependency vulnerability")),
                    component=name,
                    installed_version=version,
                    fixed_version=", ".join(str(item) for item in fix_versions),
                    metadata={"aliases": aliases},
                )
            )
    return ScanResult(
        scanner="pip-audit",
        category="sca",
        status=_status(findings),
        findings=findings,
        source=str(path),
        generated_at=generated_at(path),
    )


def parse_zap(data: object, path: Path) -> ScanResult:
    if not isinstance(data, dict) or "site" not in data or not isinstance(data.get("site"), list):
        raise ReportParseError(f"invalid OWASP ZAP report: {path}")
    findings: list[Finding] = []
    targets: set[str] = set()
    sites = _object_list(data.get("site", []), "site", path)
    if not sites:
        raise ReportParseError(f"OWASP ZAP report contains no scanned site: {path}")
    for site_index, site in enumerate(sites):
        base_url = str(site.get("@name", ""))
        if not base_url:
            raise ReportParseError(f"site[{site_index}].@name is required in {path}")
        try:
            canonical_target = canonical_http_url(base_url)
        except ValueError as exc:
            raise ReportParseError(f"site[{site_index}].@name is invalid in {path}: {exc}") from exc
        targets.add(canonical_target)
        if "alerts" not in site:
            raise ReportParseError(f"site[{site_index}].alerts is required in {path}")
        alerts = _object_list(site.get("alerts"), f"site[{site_index}].alerts", path)
        for alert_index, alert in enumerate(alerts):
            alert_prefix = f"site[{site_index}].alerts[{alert_index}]"
            alert_id = _required_identifier(
                alert.get("pluginid", alert.get("alertRef")), f"{alert_prefix}.pluginid", path
            )
            alert_message = _required_string(
                alert.get("alert", alert.get("name")), f"{alert_prefix}.alert", path
            )
            risk = _required_identifier(alert.get("riskcode"), f"{alert_prefix}.riskcode", path)
            if not risk.isascii() or not risk.isdigit() or not 0 <= int(risk) <= 4:
                raise ReportParseError(
                    f"{alert_prefix}.riskcode must be an integer from 0 through 4 in {path}"
                )
            instances = _object_list(
                alert.get("instances", []),
                f"site[{site_index}].alerts[{alert_index}].instances",
                path,
            ) or [{}]
            severity = Severity.parse(risk)
            seen_instances: set[tuple[str, str, str]] = set()
            for current in instances:
                raw_uri = str(current.get("uri", base_url))
                try:
                    stable_location, observed_uri = canonical_dast_location(
                        raw_uri, base_url=canonical_target
                    )
                except ValueError as exc:
                    raise ReportParseError(
                        f"site[{site_index}].alerts[{alert_index}] contains an invalid URI: {exc}"
                    ) from exc
                identity = (
                    stable_location,
                    str(current.get("method", "")),
                    str(current.get("param", "")),
                )
                if identity in seen_instances:
                    continue
                seen_instances.add(identity)
                findings.append(
                    Finding(
                        scanner="owasp-zap",
                        category="dast",
                        rule_id=alert_id,
                        severity=severity,
                        message=alert_message,
                        location=identity[0],
                        cwe=(str(alert.get("cweid")),) if alert.get("cweid") else (),
                        metadata={
                            "confidence": alert.get("confidence", ""),
                            "method": identity[1],
                            "parameter": identity[2],
                            "observed_uri": observed_uri,
                            "target_uri": canonical_target,
                            "solution": alert.get("solution", ""),
                        },
                    )
                )
    return ScanResult(
        scanner="owasp-zap",
        category="dast",
        status=_status(findings),
        findings=findings,
        metrics={"targets": sorted(targets)},
        source=str(path),
        generated_at=generated_at(path),
    )


def parse_cyclonedx(data: object, path: Path) -> ScanResult:
    if (
        not isinstance(data, dict)
        or str(data.get("bomFormat", "")).lower() != "cyclonedx"
        or "components" not in data
        or not isinstance(data.get("components"), list)
    ):
        raise ReportParseError(f"invalid CycloneDX report: {path}")
    spec_version = data.get("specVersion")
    if spec_version not in {"1.3", "1.4", "1.5", "1.6"}:
        raise ReportParseError(f"unsupported CycloneDX specVersion in {path}")
    findings: list[Finding] = []
    component_refs: dict[str, tuple[str, str]] = {}
    components = _cyclonedx_components(data.get("components", []), path)
    for component_context, component in components:
        name = _required_string(component.get("name"), f"{component_context}.name", path)
        version = _optional_string(component.get("version"), f"{component_context}.version", path)
        reference_raw = component.get("bom-ref")
        reference = (
            _required_string(reference_raw, f"{component_context}.bom-ref", path)
            if reference_raw is not None
            else f"{name}@{version}"
        )
        if reference in component_refs:
            raise ReportParseError(f"duplicate CycloneDX component reference {reference} in {path}")
        component_refs[reference] = (name, version)
        licenses = _object_list(
            component.get("licenses", []), f"{component_context}.licenses", path
        )
        if not licenses:
            licenses = [{"license": {"id": "UNKNOWN"}}]
        for license_index, license_wrapper in enumerate(licenses):
            expression = license_wrapper.get("expression")
            if expression is not None:
                if not isinstance(expression, str) or not expression.strip():
                    raise ReportParseError(
                        f"{component_context}.licenses[{license_index}].expression "
                        f"must be a non-empty string in {path}"
                    )
                license_id = expression.strip()
            else:
                license_data = _object(
                    license_wrapper.get("license", license_wrapper),
                    f"{component_context}.licenses[{license_index}].license",
                    path,
                )
                raw_license = license_data.get("id") or license_data.get("name")
                license_id = (
                    _required_string(
                        raw_license,
                        f"{component_context}.licenses[{license_index}].license.id",
                        path,
                    )
                    if raw_license is not None
                    else "UNKNOWN"
                )
            findings.append(
                Finding(
                    scanner="cyclonedx",
                    category="license",
                    rule_id="license.detected",
                    severity=Severity.INFO,
                    message=f"{name} uses {license_id}",
                    component=name,
                    installed_version=version,
                    license_id=license_id,
                    metadata={"kind": "dependency_license"},
                )
            )
    for vulnerability_index, vulnerability in enumerate(
        _object_list(data.get("vulnerabilities", []), "vulnerabilities", path)
    ):
        vulnerability_id = vulnerability.get("id")
        if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
            raise ReportParseError(
                f"vulnerabilities[{vulnerability_index}].id is required in {path}"
            )
        ratings = _object_list(
            vulnerability.get("ratings", []),
            f"vulnerabilities[{vulnerability_index}].ratings",
            path,
        )
        parsed_ratings = [
            (
                _cyclonedx_rating_severity(
                    item,
                    f"vulnerabilities[{vulnerability_index}].ratings[{rating_index}]",
                    path,
                ),
                item,
            )
            for rating_index, item in enumerate(ratings)
        ]
        severity, rating = (
            max(parsed_ratings, key=lambda item: int(item[0]))
            if parsed_ratings
            else (Severity.UNKNOWN, {})
        )
        affects = _object_list(
            vulnerability.get("affects", []),
            f"vulnerabilities[{vulnerability_index}].affects",
            path,
        ) or [{}]
        recommendation = str(vulnerability.get("recommendation", ""))
        analysis = _object(
            vulnerability.get("analysis", {}),
            f"vulnerabilities[{vulnerability_index}].analysis",
            path,
        )
        for field in ("state", "justification", "detail"):
            value = analysis.get(field, "")
            if not isinstance(value, str):
                raise ReportParseError(
                    f"vulnerabilities[{vulnerability_index}].analysis.{field} "
                    f"must be a string in {path}"
                )
        response = analysis.get("response", [])
        if not isinstance(response, list) or not all(isinstance(item, str) for item in response):
            raise ReportParseError(
                f"vulnerabilities[{vulnerability_index}].analysis.response "
                f"must be an array of strings in {path}"
            )
        fixed_version = ""
        for item in _object_list(
            vulnerability.get("properties", []),
            f"vulnerabilities[{vulnerability_index}].properties",
            path,
        ):
            property_name = _optional_string(
                item.get("name"),
                f"vulnerabilities[{vulnerability_index}].properties.name",
                path,
            )
            if property_name.casefold() == "finguard:fixed-version":
                fixed_version = _optional_string(
                    item.get("value"),
                    f"vulnerabilities[{vulnerability_index}].properties.value",
                    path,
                )
                break
        seen_affects: set[str] = set()
        for affect_index, affected in enumerate(affects):
            reference = str(affected.get("ref", ""))
            if affects != [{}] and not reference:
                raise ReportParseError(
                    f"vulnerabilities[{vulnerability_index}].affects[{affect_index}].ref "
                    f"is required in {path}"
                )
            if reference in seen_affects:
                raise ReportParseError(
                    f"vulnerabilities[{vulnerability_index}] contains duplicate affect "
                    f"reference {reference} in {path}"
                )
            seen_affects.add(reference)
            name, version = component_refs.get(reference, (reference, ""))
            findings.append(
                Finding(
                    scanner="cyclonedx",
                    category="sca",
                    rule_id=vulnerability_id.strip(),
                    severity=severity,
                    message=str(vulnerability.get("description", "SBOM vulnerability")),
                    component=name,
                    installed_version=version,
                    fixed_version=fixed_version,
                    metadata={
                        "bom_ref": reference,
                        "score": rating.get("score"),
                        "recommendation": recommendation,
                        # Scanner-provided VEX is retained for audit only. The gate
                        # requires a separately signed VEX attestation to suppress it.
                        "reported_vex_state": str(analysis.get("state", "")).casefold(),
                        "reported_vex_justification": str(analysis.get("justification", "")),
                        "reported_vex_detail": str(analysis.get("detail", "")),
                        "reported_vex_response": response,
                    },
                )
            )
    return ScanResult(
        scanner="cyclonedx",
        category="sca",
        status=_status(findings),
        findings=findings,
        metrics={"component_count": len(components)},
        source=str(path),
        generated_at=generated_at(path),
    )


def _cyclonedx_components(value: object, path: Path) -> list[tuple[str, dict[str, object]]]:
    """Flatten CycloneDX nested components while retaining precise error paths."""

    roots = _object_list(value, "components", path)
    pending = [(f"components[{index}]", item) for index, item in reversed(list(enumerate(roots)))]
    result: list[tuple[str, dict[str, object]]] = []
    while pending:
        context, component = pending.pop()
        result.append((context, component))
        children = _object_list(component.get("components", []), f"{context}.components", path)
        pending.extend(
            (f"{context}.components[{index}]", item)
            for index, item in reversed(list(enumerate(children)))
        )
    return result


def _cyclonedx_rating_severity(rating: Mapping[str, object], context: str, path: Path) -> Severity:
    """Use the stricter of the declared severity and numeric CVSS score."""

    values: list[Severity] = []
    severity_raw = rating.get("severity")
    if severity_raw not in (None, ""):
        severity_text = _required_string(severity_raw, f"{context}.severity", path)
        values.append(Severity.parse(severity_text))

    score_raw = rating.get("score")
    if score_raw not in (None, ""):
        if isinstance(score_raw, bool) or not isinstance(score_raw, (str, int, float)):
            raise ReportParseError(f"{context}.score must be numeric in {path}")
        try:
            score = float(score_raw)
        except (ValueError, OverflowError) as exc:
            raise ReportParseError(f"{context}.score must be numeric in {path}") from exc
        if not math.isfinite(score) or not 0 <= score <= 10:
            raise ReportParseError(f"{context}.score must be between 0 and 10 in {path}")
        values.append(
            Severity.CRITICAL
            if score >= 9
            else Severity.HIGH
            if score >= 7
            else Severity.MEDIUM
            if score >= 4
            else Severity.LOW
            if score > 0
            else Severity.INFO
        )

    if not values or Severity.UNKNOWN in values:
        return Severity.UNKNOWN
    return max(values, key=int)


def looks_normalized(data: object) -> bool:
    return isinstance(data, Mapping) and {"scanner", "category", "status"}.issubset(data)
