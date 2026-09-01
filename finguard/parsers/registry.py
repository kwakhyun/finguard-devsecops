"""Report auto-detection and safe recursive discovery."""

from __future__ import annotations

from pathlib import Path

from finguard.attestation import sha256_path
from finguard.errors import ReportParseError
from finguard.models import ScanResult

from .common import load_json
from .json_scanners import (
    looks_normalized,
    parse_cyclonedx,
    parse_normalized,
    parse_pip_audit,
    parse_ruff,
    parse_semgrep,
    parse_trivy,
    parse_zap,
)
from .sarif import parse_sarif
from .xml_scanners import parse_coverage, parse_junit

SUPPORTED_SUFFIXES = {".json", ".xml", ".sarif"}


def discover_reports(directory: Path) -> list[Path]:
    if not directory.is_dir():
        raise ReportParseError(f"report directory does not exist: {directory}")
    return sorted(
        path
        for path in directory.rglob("*")
        if path.is_file()
        and path.suffix.lower() in SUPPORTED_SUFFIXES
        and not path.name.endswith(".attestation.json")
    )


def parse_report(path: Path, report_type: str | None = None) -> ScanResult:
    if not path.is_file():
        raise ReportParseError(f"report does not exist: {path}")
    kind = (report_type or "").lower().replace("_", "-")
    name = path.name.lower()
    if path.suffix.lower() == ".xml":
        if kind == "coverage" or (not kind and "coverage" in name):
            return _bind_input(parse_coverage(path), path)
        if kind in {"junit", "test"} or (not kind and any(x in name for x in ("junit", "test"))):
            return _bind_input(parse_junit(path), path)
        raise ReportParseError(f"cannot detect XML report type for {path}; use an explicit type")
    if path.suffix.lower() not in {".json", ".sarif"}:
        raise ReportParseError(f"unsupported report extension: {path.suffix}")

    data = load_json(path)
    parsers = {
        "normalized": parse_normalized,
        "finguard": parse_normalized,
        "semgrep": parse_semgrep,
        "ruff": parse_ruff,
        "sarif": parse_sarif,
        "trivy": parse_trivy,
        "pip-audit": parse_pip_audit,
        "zap": parse_zap,
        "owasp-zap": parse_zap,
        "cyclonedx": parse_cyclonedx,
        "sbom": parse_cyclonedx,
    }
    if kind:
        parser = parsers.get(kind)
        if parser is None:
            raise ReportParseError(f"unsupported report type: {report_type}")
        return _bind_input(parser(data, path), path)
    if looks_normalized(data):
        return _bind_input(parse_normalized(data, path), path)
    if isinstance(data, dict):
        if isinstance(data.get("runs"), list) and str(data.get("version", "")).startswith("2"):
            return _bind_input(parse_sarif(data, path), path)
        if str(data.get("bomFormat", "")).lower() == "cyclonedx":
            return _bind_input(parse_cyclonedx(data, path), path)
        if "Results" in data:
            return _bind_input(parse_trivy(data, path), path)
        if "site" in data:
            return _bind_input(parse_zap(data, path), path)
        if "results" in data and "errors" in data:
            return _bind_input(parse_semgrep(data, path), path)
        if "dependencies" in data:
            return _bind_input(parse_pip_audit(data, path), path)
    if isinstance(data, list):
        if "ruff" in name or not data or (isinstance(data[0], dict) and "filename" in data[0]):
            return _bind_input(parse_ruff(data, path), path)
        if "audit" in name:
            return _bind_input(parse_pip_audit(data, path), path)
    raise ReportParseError(f"cannot detect JSON report type for {path}; use an explicit type")


def _bind_input(result: ScanResult, path: Path) -> ScanResult:
    result.input_sha256 = sha256_path(path)
    return result
