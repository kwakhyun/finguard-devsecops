from __future__ import annotations

from pathlib import Path
from typing import Any

from finguard.models import ScanStatus, Severity
from finguard.scanners import scan_dependencies, scan_lint, scan_source, scan_web


def test_native_sast_detects_dangerous_python(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.py"
    source.write_text("def run(value):\n    return eval(value)\n", encoding="utf-8")
    result = scan_source(tmp_path)
    assert result.status is ScanStatus.FINDINGS
    assert result.findings[0].severity is Severity.CRITICAL
    assert result.findings[0].rule_id == "python.eval"


def test_native_dependency_scan_requires_exact_pins(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests>=2.0\nflask==3.0.0\n", encoding="utf-8")
    result = scan_dependencies(tmp_path)
    assert result.metrics["dependency_count"] == 2
    assert [item.component for item in result.findings] == ["requests"]


def test_native_lint_reports_trailing_whitespace(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1  \n", encoding="utf-8")
    result = scan_lint(tmp_path)
    assert result.findings[0].rule_id == "lint.trailing-whitespace"


def test_native_dast_accepts_hardened_sample_service(monkeypatch: Any) -> None:
    class Response:
        status = 200
        headers = {
            "Content-Security-Policy": "default-src 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        }

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            return b'{"status":"healthy"}'

    class Opener:
        def open(self, request: object, timeout: float) -> Response:
            return Response()

    monkeypatch.setattr("urllib.request.build_opener", lambda *handlers: Opener())
    result = scan_web("http://sample-service:8080/health")
    assert result.status is ScanStatus.PASSED
    assert result.metrics["status_code"] == 200
