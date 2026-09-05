"""CLI argument declarations, separate from command execution."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from pathlib import Path

from . import __version__


def build_parser(
    handlers: Mapping[str, Callable[[argparse.Namespace], int]],
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="finguard",
        description="Policy-as-code DevSecOps quality gate for regulated delivery",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="run dependency-free local feedback scanners")
    scan.add_argument("kind", choices=["source", "lint", "dependencies", "web", "all"])
    scan.add_argument("--workspace", type=Path, default=Path("."))
    scan.add_argument("--output", type=Path, default=Path("build/reports/native"))
    scan.add_argument("--url", help="HTTP target for web/all scans")
    scan.add_argument("--timeout", type=float, default=5.0)
    scan.add_argument("--exclude", action="append", default=[])
    scan.set_defaults(handler=handlers["scan"])

    gate = commands.add_parser("gate", help="evaluate reports and produce audit evidence")
    gate.add_argument("--policy", type=Path, default=Path("policies/financial-baseline.toml"))
    gate.add_argument("--shadow-policy", type=Path)
    gate.add_argument(
        "--reports", type=Path, help="directory recursively containing scanner reports"
    )
    gate.add_argument(
        "--report",
        action="append",
        default=[],
        metavar="[TYPE=]PATH",
        help="individual report; TYPE resolves ambiguous formats",
    )
    gate.add_argument("--change", type=Path)
    gate.add_argument("--subject", type=Path, help="immutable release subject JSON")
    gate.add_argument("--exceptions", type=Path)
    gate.add_argument("--attestations", type=Path, help="scan attestation directory")
    gate.add_argument("--attestation-key-env", default="")
    gate.add_argument(
        "--approval-attestation", type=Path, help="signed external change approval JSON"
    )
    gate.add_argument("--approval-key-env", default="")
    gate.add_argument("--approval-cosign-bundle", type=Path)
    gate.add_argument("--approval-cosign-verification-key", default="")
    gate.add_argument("--approval-cosign-certificate-identity", default="")
    gate.add_argument("--approval-cosign-certificate-oidc-issuer", default="")
    gate.add_argument("--approval-cosign-key-id", default="")
    gate.add_argument("--vex-attestation", type=Path)
    gate.add_argument("--vex-key-env", default="")
    gate.add_argument("--vex-cosign-bundle", type=Path)
    gate.add_argument("--vex-cosign-verification-key", default="")
    gate.add_argument("--vex-cosign-certificate-identity", default="")
    gate.add_argument("--vex-cosign-certificate-oidc-issuer", default="")
    gate.add_argument("--vex-cosign-key-id", default="")
    gate.add_argument("--expected-commit", default="")
    gate.add_argument("--output", type=Path, default=Path("build/evidence"))
    gate.add_argument("--signing-key-env", default="")
    gate.add_argument("--signing-key-id", default="local-hmac")
    gate.add_argument("--cosign-signing-key", default="")
    gate.add_argument("--force", action="store_true")
    gate.set_defaults(handler=handlers["gate"])

    verify = commands.add_parser("verify", help="verify evidence file hashes and audit chain")
    verify.add_argument("--evidence", type=Path, required=True)
    verify.add_argument("--signing-key-env", default="")
    verify.add_argument("--cosign-verification-key", default="")
    verify.add_argument("--cosign-certificate-identity", default="")
    verify.add_argument("--cosign-certificate-oidc-issuer", default="")
    verify.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="verify hashes only; never use for release or deployment evidence",
    )
    verify.set_defaults(handler=handlers["verify"])

    demo = commands.add_parser("demo", help="run a reproducible pass or fail portfolio scenario")
    demo.add_argument("--scenario", choices=["pass", "fail"], default="pass")
    demo.add_argument("--fixtures", type=Path, default=Path("examples/scenarios"))
    demo.add_argument("--policy", type=Path, default=Path("policies/financial-baseline.toml"))
    demo.add_argument("--output", type=Path, default=Path("build/demo-evidence"))
    demo.add_argument("--signing-key-env", default="")
    demo.add_argument("--signing-key-id", default="local-hmac")
    demo.add_argument("--force", action="store_true")
    demo.set_defaults(handler=handlers["demo"])

    deployment = commands.add_parser(
        "deploy", help="deploy an immutable image after evidence verification"
    )
    deployment.add_argument("--cluster", required=True, help="approved kubectl context")
    deployment.add_argument("--namespace", required=True)
    deployment.add_argument("--deployment", required=True)
    deployment.add_argument("--container", required=True)
    deployment.add_argument("--image", required=True)
    deployment.add_argument("--expected-policy-id", required=True)
    deployment.add_argument("--expected-policy-version", required=True)
    deployment.add_argument("--expected-policy-sha256", required=True)
    deployment.add_argument("--evidence", type=Path, required=True)
    deployment.add_argument("--output", type=Path, default=Path("build/deployment-result.json"))
    deployment.add_argument("--timeout", type=int, default=300)
    deployment.add_argument("--smoke-test-attempts", type=int, default=3)
    deployment.add_argument("--smoke-test-timeout", type=float, default=5.0)
    deployment.add_argument("--smoke-test-interval", type=float, default=2.0)
    deployment.add_argument("--allowed-health-host", action="append", default=[])
    deployment.add_argument("--signing-key-env", default="")
    deployment.add_argument("--cosign-verification-key", default="")
    deployment.add_argument("--cosign-certificate-identity", default="")
    deployment.add_argument("--cosign-certificate-oidc-issuer", default="")
    deployment_signature = deployment.add_mutually_exclusive_group()
    deployment_signature.add_argument(
        "--require-signature",
        dest="require_signature",
        action="store_true",
        default=True,
        help="require a verified evidence signature (default)",
    )
    deployment_signature.add_argument(
        "--allow-unsigned",
        dest="require_signature",
        action="store_false",
        help="allow unsigned evidence for local dry-run demonstrations only",
    )
    deployment.add_argument("--result-cosign-signing-key", default="")
    deployment.add_argument("--result-cosign-bundle", type=Path)
    deployment.add_argument(
        "--force-result",
        action="store_true",
        help="explicitly replace an existing deployment result and signature",
    )
    deployment.add_argument("--dry-run", action="store_true")
    deployment.set_defaults(handler=handlers["deploy"])

    subject = commands.add_parser(
        "subject", help="create an immutable source, artifact, and deployment subject"
    )
    subject.add_argument("--service", required=True)
    subject.add_argument("--repository", required=True)
    subject.add_argument("--commit", required=True)
    subject.add_argument("--image", required=True)
    subject.add_argument("--sbom", type=Path, required=True)
    subject.add_argument("--environment", required=True)
    subject.add_argument("--cluster", required=True)
    subject.add_argument("--namespace", required=True)
    subject.add_argument("--deployment", required=True)
    subject.add_argument("--container", required=True)
    subject.add_argument("--healthcheck-url", required=True)
    subject.add_argument("--builder-id", required=True)
    subject.add_argument("--built-at", default="")
    subject.add_argument("--output", type=Path, required=True)
    subject.set_defaults(handler=handlers["subject"])

    attest = commands.add_parser(
        "attest-report", help="bind a scanner execution to an immutable report"
    )
    attest.add_argument("--report", type=Path, required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.add_argument("--scanner", required=True)
    attest.add_argument("--category", required=True)
    attest.add_argument("--scanner-version", required=True)
    attest.add_argument("--scanner-uri", required=True)
    attest.add_argument("--source-commit", required=True)
    attest.add_argument("--image-digest", default="")
    attest.add_argument("--ruleset", type=Path, required=True)
    attest.add_argument("--database", type=Path)
    attest.add_argument("--command", required=True)
    attest.add_argument("--ci-job-id", required=True)
    attest.add_argument("--runner-id", required=True)
    attest.add_argument("--exit-code", type=int, required=True)
    completion = attest.add_mutually_exclusive_group(required=True)
    completion.add_argument("--complete", dest="complete", action="store_true")
    completion.add_argument("--incomplete", dest="complete", action="store_false")
    attest.add_argument("--target-uri", default="")
    attest.add_argument("--started-at", required=True)
    attest.add_argument("--finished-at", required=True)
    attest.add_argument("--signing-key-env", default="")
    attest.add_argument("--key-id", default="")
    attest.set_defaults(handler=handlers["attest_report"])

    approval = commands.add_parser(
        "attest-approval",
        help="create an ITSM adapter approval envelope for a release subject",
    )
    approval.add_argument("--change", type=Path, required=True)
    approval.add_argument("--subject", type=Path, required=True)
    approval.add_argument("--issuer", required=True)
    approval.add_argument("--source-uri", required=True)
    approval.add_argument("--event-id", required=True)
    approval.add_argument("--issued-at", default="")
    approval.add_argument("--output", type=Path, required=True)
    approval.add_argument("--signing-key-env", default="")
    approval.add_argument("--cosign-signing-key", default="")
    approval.add_argument("--cosign-bundle", type=Path)
    approval.add_argument("--key-id", required=True)
    approval.add_argument("--force", action="store_true")
    approval.set_defaults(handler=handlers["attest_approval"])

    vex = commands.add_parser(
        "attest-vex",
        help="create signed security review evidence for VEX statements",
    )
    vex.add_argument("--subject", type=Path, required=True)
    vex.add_argument("--statements", type=Path, required=True)
    vex.add_argument("--issuer", required=True)
    vex.add_argument("--source-uri", required=True)
    vex.add_argument("--event-id", required=True)
    vex.add_argument("--approver", required=True)
    vex.add_argument("--issued-at", required=True)
    vex.add_argument("--expires-at", required=True)
    vex.add_argument("--output", type=Path, required=True)
    vex.add_argument("--signing-key-env", default="")
    vex.add_argument("--cosign-signing-key", default="")
    vex.add_argument("--cosign-bundle", type=Path)
    vex.add_argument("--key-id", required=True)
    vex.add_argument("--force", action="store_true")
    vex.set_defaults(handler=handlers["attest_vex"])

    image_validation = commands.add_parser(
        "validate-images", help="fail unless every container image is digest-pinned"
    )
    image_validation.add_argument("images", nargs="+")
    image_validation.set_defaults(handler=handlers["validate_images"])

    export = commands.add_parser(
        "export", help="render a decision for GitLab, SARIF, or Prometheus consumers"
    )
    export.add_argument("--decision", type=Path, required=True)
    export.add_argument(
        "--format",
        choices=["gitlab-code-quality", "sarif", "prometheus"],
        required=True,
    )
    export.add_argument("--output", type=Path, required=True)
    export.set_defaults(handler=handlers["export"])

    comparison = commands.add_parser(
        "compare", help="compare baseline and candidate policy decisions"
    )
    comparison.add_argument("--baseline", type=Path, required=True)
    comparison.add_argument("--candidate", type=Path, required=True)
    comparison.add_argument("--output", type=Path)
    comparison.set_defaults(handler=handlers["compare"])
    return parser
