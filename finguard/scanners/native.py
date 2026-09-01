"""Fast local scanners that complement, but do not replace, enterprise tools."""

from __future__ import annotations

import ast
import datetime as dt
import re
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path

from finguard.models import Finding, ScanResult, ScanStatus, Severity
from finguard.urls import canonical_http_url

DEFAULT_EXCLUDES = {
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "evidence",
    "reports",
    "tests/fixtures/insecure",
}
SECRET_NAME = re.compile(r"(?:password|passwd|secret|api_?key|access_?token|private_?key)", re.I)


def scan_source(workspace: Path, excludes: Iterable[str] = ()) -> ScanResult:
    workspace = workspace.resolve()
    findings: list[Finding] = []
    errors: list[str] = []
    files = list(_python_files(workspace, excludes))
    for path in files:
        relative = path.relative_to(workspace).as_posix()
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=relative)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            errors.append(f"{relative}: {exc}")
            continue
        visitor = _SecureCodingVisitor(relative)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    return ScanResult(
        scanner="finguard-native-sast",
        category="sast",
        status=_status(findings, errors),
        findings=findings,
        metrics={"files_scanned": len(files)},
        errors=errors,
        generated_at=_now(),
    )


def scan_lint(workspace: Path, excludes: Iterable[str] = ()) -> ScanResult:
    workspace = workspace.resolve()
    findings: list[Finding] = []
    errors: list[str] = []
    files = list(_python_files(workspace, excludes))
    for path in files:
        relative = path.relative_to(workspace).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{relative}: {exc}")
            continue
        for line_number, line in enumerate(lines, start=1):
            if "\t" in line[: len(line) - len(line.lstrip())]:
                findings.append(
                    _finding(
                        "lint.tab-indentation",
                        Severity.LOW,
                        "Tab indentation reduces formatting consistency",
                        relative,
                        line_number,
                        category="lint",
                        scanner="finguard-native-lint",
                    )
                )
            if line.rstrip() != line:
                findings.append(
                    _finding(
                        "lint.trailing-whitespace",
                        Severity.LOW,
                        "Trailing whitespace detected",
                        relative,
                        line_number,
                        category="lint",
                        scanner="finguard-native-lint",
                    )
                )
            if len(line) > 120:
                findings.append(
                    _finding(
                        "lint.line-too-long",
                        Severity.LOW,
                        "Line exceeds 120 characters",
                        relative,
                        line_number,
                        category="lint",
                        scanner="finguard-native-lint",
                    )
                )
    return ScanResult(
        scanner="finguard-native-lint",
        category="lint",
        status=_status(findings, errors),
        findings=findings,
        metrics={"files_scanned": len(files)},
        errors=errors,
        generated_at=_now(),
    )


def scan_dependencies(workspace: Path) -> ScanResult:
    workspace = workspace.resolve()
    findings: list[Finding] = []
    dependency_count = 0
    files = sorted({*workspace.glob("requirements*.txt"), *workspace.glob("requirements*.lock")})
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            return ScanResult(
                scanner="finguard-native-sca",
                category="sca",
                status=ScanStatus.ERROR,
                errors=[f"{path.name}: {exc}"],
                generated_at=_now(),
            )
        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(("-r", "--requirement")):
                continue
            dependency_count += 1
            location = f"{path.name}:{line_number}"
            if line.startswith(("git+", "http://", "https://", "-e ", "--editable")):
                findings.append(
                    Finding(
                        scanner="finguard-native-sca",
                        category="sca",
                        rule_id="dependency.untrusted-source",
                        severity=Severity.HIGH,
                        message="Dependency is installed from a mutable or non-index source",
                        location=location,
                        component=line,
                    )
                )
            elif "==" not in line or "*" in line:
                component = re.split(r"[<>=!~\[]", line, maxsplit=1)[0].strip()
                findings.append(
                    Finding(
                        scanner="finguard-native-sca",
                        category="sca",
                        rule_id="dependency.not-pinned",
                        severity=Severity.MEDIUM,
                        message="Dependency is not pinned to an exact version",
                        location=location,
                        component=component,
                    )
                )
    return ScanResult(
        scanner="finguard-native-sca",
        category="sca",
        status=_status(findings),
        findings=findings,
        metrics={"dependency_files": len(files), "dependency_count": dependency_count},
        generated_at=_now(),
    )


def scan_web(url: str, timeout_seconds: float = 5.0) -> ScanResult:
    findings: list[Finding] = []
    try:
        target_url = canonical_http_url(url)
    except ValueError:
        return ScanResult(
            scanner="finguard-native-dast",
            category="dast",
            status=ScanStatus.ERROR,
            errors=["target URL must use the http or https scheme"],
            metrics={"target": url},
            generated_at=_now(),
        )
    request = urllib.request.Request(  # noqa: S310 - scheme restricted above
        target_url,
        headers={"User-Agent": "FinGuard-DAST/0.1", "Accept": "application/json,text/html"},
    )
    try:
        opener = urllib.request.build_opener(_NoRedirectHandler())
        with opener.open(request, timeout=timeout_seconds) as response:  # noqa: S310
            status_code = int(response.status)
            headers = {key.casefold(): value for key, value in response.headers.items()}
            response.read(64 * 1024)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return ScanResult(
            scanner="finguard-native-dast",
            category="dast",
            status=ScanStatus.ERROR,
            errors=[f"target request failed: {exc}"],
            metrics={"target": target_url},
            generated_at=_now(),
        )

    if not 200 <= status_code < 300:
        findings.append(
            Finding(
                scanner="finguard-native-dast",
                category="dast",
                rule_id="http.unexpected-status",
                severity=Severity.HIGH,
                message=f"Target returned unexpected HTTP status {status_code}",
                location=target_url,
            )
        )
    required_headers = {
        "content-security-policy": "Content-Security-Policy header is missing",
        "x-content-type-options": "X-Content-Type-Options header is missing",
        "x-frame-options": "X-Frame-Options header is missing",
        "referrer-policy": "Referrer-Policy header is missing",
    }
    for header, message in required_headers.items():
        if header not in headers:
            findings.append(
                Finding(
                    scanner="finguard-native-dast",
                    category="dast",
                    rule_id=f"http.header.{header}.missing",
                    severity=Severity.MEDIUM,
                    message=message,
                    location=target_url,
                    cwe=("CWE-693",),
                )
            )
    if target_url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                scanner="finguard-native-dast",
                category="dast",
                rule_id="http.header.hsts.missing",
                severity=Severity.MEDIUM,
                message="Strict-Transport-Security header is missing",
                location=target_url,
                cwe=("CWE-319",),
            )
        )
    if headers.get("access-control-allow-origin", "").strip() == "*":
        findings.append(
            Finding(
                scanner="finguard-native-dast",
                category="dast",
                rule_id="http.cors.wildcard",
                severity=Severity.HIGH,
                message="CORS permits every origin",
                location=target_url,
                cwe=("CWE-942",),
            )
        )
    return ScanResult(
        scanner="finguard-native-dast",
        category="dast",
        status=_status(findings),
        findings=findings,
        metrics={"target": target_url, "status_code": status_code},
        generated_at=_now(),
    )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


class _SecureCodingVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _call_name(node.func)
        rules: dict[str, tuple[str, Severity, str, str]] = {
            "eval": (
                "python.eval",
                Severity.CRITICAL,
                "Dynamic eval can execute untrusted code",
                "CWE-95",
            ),
            "exec": (
                "python.exec",
                Severity.CRITICAL,
                "Dynamic exec can execute untrusted code",
                "CWE-95",
            ),
            "os.system": (
                "python.os-system",
                Severity.HIGH,
                "os.system can introduce command injection",
                "CWE-78",
            ),
            "pickle.load": (
                "python.unsafe-deserialization",
                Severity.HIGH,
                "pickle can execute code during deserialization",
                "CWE-502",
            ),
            "pickle.loads": (
                "python.unsafe-deserialization",
                Severity.HIGH,
                "pickle can execute code during deserialization",
                "CWE-502",
            ),
            "tempfile.mktemp": (
                "python.insecure-tempfile",
                Severity.HIGH,
                "tempfile.mktemp is vulnerable to race conditions",
                "CWE-377",
            ),
            "hashlib.md5": (
                "python.weak-hash",
                Severity.MEDIUM,
                "MD5 is unsuitable for security-sensitive hashing",
                "CWE-328",
            ),
            "hashlib.sha1": (
                "python.weak-hash",
                Severity.MEDIUM,
                "SHA-1 is unsuitable for security-sensitive hashing",
                "CWE-328",
            ),
        }
        if name in rules:
            rule, severity, message, cwe = rules[name]
            self.findings.append(
                _finding(rule, severity, message, self.path, node.lineno, cwe=(cwe,))
            )
        if name.startswith("subprocess.") and any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            self.findings.append(
                _finding(
                    "python.subprocess-shell",
                    Severity.HIGH,
                    "subprocess with shell=True can introduce command injection",
                    self.path,
                    node.lineno,
                    cwe=("CWE-78",),
                )
            )
        if name in {"requests.get", "requests.post", "requests.request"} and any(
            keyword.arg == "verify"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        ):
            self.findings.append(
                _finding(
                    "python.tls-verification-disabled",
                    Severity.HIGH,
                    "TLS certificate verification is disabled",
                    self.path,
                    node.lineno,
                    cwe=("CWE-295",),
                )
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            for target in node.targets:
                name = target.id if isinstance(target, ast.Name) else ""
                looks_sensitive = SECRET_NAME.search(name) and len(value) >= 8
                if looks_sensitive and not value.startswith(("${", "<")):
                    self.findings.append(
                        _finding(
                            "python.hardcoded-secret",
                            Severity.CRITICAL,
                            "Potential hard-coded secret assigned to a sensitive variable",
                            self.path,
                            node.lineno,
                            cwe=("CWE-798",),
                        )
                    )
        self.generic_visit(node)


def _python_files(workspace: Path, excludes: Iterable[str]) -> Iterable[Path]:
    excluded = {item.strip("/") for item in (*DEFAULT_EXCLUDES, *excludes)}
    for path in sorted(workspace.rglob("*.py")):
        relative = path.relative_to(workspace).as_posix()
        if any(relative == item or relative.startswith(f"{item}/") for item in excluded):
            continue
        yield path


def _call_name(node: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _finding(
    rule_id: str,
    severity: Severity,
    message: str,
    path: str,
    line: int,
    *,
    category: str = "sast",
    scanner: str = "finguard-native-sast",
    cwe: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        scanner=scanner,
        category=category,
        rule_id=rule_id,
        severity=severity,
        message=message,
        location=f"{path}:{line}",
        cwe=cwe,
    )


def _status(findings: list[Finding], errors: list[str] | None = None) -> ScanStatus:
    if errors:
        return ScanStatus.ERROR
    return ScanStatus.FINDINGS if findings else ScanStatus.PASSED


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()
