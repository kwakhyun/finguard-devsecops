"""Exercise the real CLI, Cosign, and Kubernetes in an isolated kind cluster.

Security reports and approvals are fixtures. Kubernetes mutations, container image
transfers, HTTP probes, OS signals, and cryptographic signatures are real.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from finguard.change import ChangeRequest
from finguard.release import validate_image_reference

NODE_IMAGE = (
    "kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"
)
REGISTRY_IMAGES = {
    "x86_64": "registry@sha256:7518da9b12dd746278282a729dee2e65eabdeb449db4d0b28d46ef6e90308f58",
    "arm64": "registry@sha256:bc68ba48dae0e0423bb885c8d07d20c3210febbe996d38d54d32c574fda690ae",
    "aarch64": "registry@sha256:bc68ba48dae0e0423bb885c8d07d20c3210febbe996d38d54d32c574fda690ae",
}
PROJECT = Path(__file__).resolve().parents[1]


def run(*command: str, input: str | None = None, timeout: int = 300) -> str:
    result = subprocess.run(  # noqa: S603 - explicit argv, test-owned resources only
        command, input=input, text=True, capture_output=True, timeout=timeout, check=False
    )
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed ({result.returncode}): {result.stderr[-3000:]}")
    return result.stdout.strip()


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def make_evidence(directory: Path, image: str, context: str, health: str, key: Path) -> Path:
    directory.mkdir()
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    fixture = (PROJECT / "examples/scenarios/pass/change.toml").read_text()
    replacements = {
        "image": json.dumps(image),
        "cluster": json.dumps(context),
        "healthcheck_url": json.dumps(health),
        "window_start": (now - dt.timedelta(minutes=5)).isoformat(),
        "window_end": (now + dt.timedelta(hours=1)).isoformat(),
        "built_at": (now - dt.timedelta(minutes=3)).isoformat(),
        "approved_at": (now - dt.timedelta(minutes=2)).isoformat(),
    }
    for field, value in replacements.items():
        fixture = re.sub(rf"^{field} = .*$", f"{field} = {value}", fixture, flags=re.MULTILINE)
    change = directory / "change.toml"
    change.write_text(fixture)
    subject = ChangeRequest.load(change).release_subject
    assert subject is not None
    subject_path = directory / "subject.json"
    subject_path.write_text(json.dumps(subject.to_dict()))
    evidence = directory / "evidence"
    run(
        sys.executable,
        "-m",
        "finguard",
        "gate",
        "--policy",
        str(PROJECT / "policies/financial-baseline.toml"),
        "--reports",
        str(PROJECT / "examples/scenarios/pass/reports"),
        "--change",
        str(change),
        "--subject",
        str(subject_path),
        "--output",
        str(evidence),
        "--cosign-signing-key",
        str(key),
    )
    return evidence


def exercise(output: Path, temporary: Path, registry_image: str) -> dict[str, object]:
    name = f"finguard-e2e-{os.getpid()}"
    context = f"kind-{name}"
    registry = f"{name}-registry"
    kubeconfig = temporary / "kubeconfig"
    os.environ["KUBECONFIG"] = str(kubeconfig)
    os.environ["COSIGN_PASSWORD"] = ""
    registry_port, health_port = available_port(), available_port()
    config = temporary / "kind.yaml"
    config.write_text(
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n"
        "- role: control-plane\n  extraPortMappings:\n"
        f"  - containerPort: 30080\n    hostPort: {health_port}\n"
        "    listenAddress: 127.0.0.1\n"
    )
    # Local test keys need no public transparency service. This wrapper still uses
    # real Cosign public-key verification; it is never installed in production CI.
    real_cosign = shutil.which("cosign")
    assert real_cosign
    wrappers = temporary / "bin"
    wrappers.mkdir()
    wrapper = wrappers / "cosign"
    wrapper.write_text(
        f"#!{sys.executable}\nimport os, sys\n"
        f"binary = {real_cosign!r}\nargs = sys.argv[1:]\n"
        "if args[0] == 'sign-blob':\n"
        "    args.extend(['--use-signing-config=false', '--tlog-upload=false'])\n"
        "if args[0] == 'verify-blob': args.append('--insecure-ignore-tlog=true')\n"
        "os.execv(binary, [binary, *args])\n"
    )
    wrapper.chmod(0o755)
    os.environ["PATH"] = f"{wrappers}{os.pathsep}{os.environ['PATH']}"
    key_prefix = temporary / "audit"
    run("cosign", "generate-key-pair", "--output-key-prefix", str(key_prefix))
    key, public_key = key_prefix.with_suffix(".key"), key_prefix.with_suffix(".pub")
    shutil.copyfile(public_key, output / "audit.pub")
    kubectl = ["kubectl", "--context", context, "--namespace", "credit-prod"]
    started_cluster = False
    started_registry = False
    cases: list[dict[str, object]] = []
    try:
        print("Creating isolated registry and Kubernetes cluster", flush=True)
        run(
            "docker",
            "run",
            "--detach",
            "--name",
            registry,
            "--publish",
            f"127.0.0.1:{registry_port}:5000",
            registry_image,
        )
        started_registry = True
        started_cluster = True
        run(
            "kind",
            "create",
            "cluster",
            "--name",
            name,
            "--image",
            NODE_IMAGE,
            "--config",
            str(config),
            "--kubeconfig",
            str(kubeconfig),
            "--wait",
            "180s",
            timeout=600,
        )
        run("docker", "network", "connect", "kind", registry)
        for node in run("kind", "get", "nodes", "--name", name).splitlines():
            hosts = f"/etc/containerd/certs.d/localhost:{registry_port}"
            run("docker", "exec", node, "mkdir", "-p", hosts)
            run(
                "docker",
                "exec",
                "-i",
                node,
                "cp",
                "/dev/stdin",
                f"{hosts}/hosts.toml",
                input=f'[host."http://{registry}:5000"]\n',
            )
        images = []
        for version in ("previous", "candidate"):
            tag = f"localhost:{registry_port}/sample:{version}"
            print(f"Building and pushing {version} image", flush=True)
            run(
                "docker",
                "build",
                "--label",
                f"finguard.test.version={version}",
                "--tag",
                tag,
                str(PROJECT),
                timeout=600,
            )
            run("docker", "push", tag)
            image = json.loads(run("docker", "image", "inspect", tag))[0]["RepoDigests"][0]
            validate_image_reference(image)
            images.append(image)
        previous, candidate = images
        assert previous != candidate
        run("kubectl", "--context", context, "create", "namespace", "credit-prod")
        annotations = {
            "finguard.io/change-id": "CB-PREVIOUS",
            "finguard.io/evidence-sha256": "old",
            "finguard.io/release-subject-sha256": "old-subject",
        }
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "customer-credit-api", "annotations": annotations},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "sample"}},
                "template": {
                    "metadata": {"labels": {"app": "sample"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "api",
                                "image": previous,
                                "ports": [{"containerPort": 8080}],
                                "readinessProbe": {
                                    "httpGet": {"path": "/health", "port": 8080},
                                    "periodSeconds": 1,
                                },
                            }
                        ]
                    },
                },
            },
        }
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "sample"},
            "spec": {
                "type": "NodePort",
                "selector": {"app": "sample"},
                "ports": [{"port": 8080, "targetPort": 8080, "nodePort": 30080}],
            },
        }
        run(
            *kubectl,
            "apply",
            "-f",
            "-",
            input=json.dumps({"apiVersion": "v1", "kind": "List", "items": [deployment, service]}),
        )
        for case in ("success", "smoke-failure", "signer-failure", "sigterm"):
            print(f"Checking {case}", flush=True)
            run(*kubectl, "set", "image", "deployment/customer-credit-api", f"api={previous}")
            run(
                *kubectl,
                "annotate",
                "deployment/customer-credit-api",
                "--overwrite",
                *(f"{k}={v}" for k, v in annotations.items()),
            )
            run(*kubectl, "rollout", "status", "deployment/customer-credit-api", "--timeout=120s")
            path = "/health" if case in {"success", "signer-failure"} else "/missing"
            health = f"http://127.0.0.1:{health_port}{path}"
            directory = output / case
            evidence = make_evidence(directory, candidate, context, health, key)
            result = directory / "deployment.json"
            policy = PROJECT / "policies/financial-baseline.toml"
            command = [
                sys.executable,
                "-m",
                "finguard",
                "deploy",
                "--cluster",
                context,
                "--namespace",
                "credit-prod",
                "--deployment",
                "customer-credit-api",
                "--container",
                "api",
                "--image",
                candidate,
                "--expected-policy-id",
                "FIN-SW-DEVSECOPS-BASELINE",
                "--expected-policy-version",
                "5.1.1",
                "--expected-policy-sha256",
                hashlib.sha256(policy.read_bytes()).hexdigest(),
                "--evidence",
                str(evidence),
                "--output",
                str(result),
                "--cosign-verification-key",
                str(public_key),
                "--require-signature",
                "--result-cosign-signing-key",
                str(temporary / "missing.key") if case == "signer-failure" else str(key),
                "--allowed-health-host",
                "127.0.0.1",
                "--timeout",
                "120",
                "--smoke-test-attempts",
                "10" if case == "sigterm" else "2",
                "--smoke-test-interval",
                "2",
            ]
            with (directory / "cli.log").open("w") as log:
                process = subprocess.Popen(command, stdout=log, stderr=log)  # noqa: S603
                try:
                    if case == "sigterm":
                        deadline = time.monotonic() + 120
                        while time.monotonic() < deadline:
                            if process.poll() is not None:
                                raise RuntimeError("deployment exited before signal injection")
                            state = json.loads(
                                run(*kubectl, "get", "deployment/customer-credit-api", "-o", "json")
                            )
                            if (
                                state["spec"]["template"]["spec"]["containers"][0]["image"]
                                == candidate
                            ):
                                # A second CLI must fail without acquiring this output path.
                                second = subprocess.run(  # noqa: S603 - invoke the same validated CLI
                                    command, capture_output=True, text=True, timeout=30, check=False
                                )  # noqa: S603
                                assert second.returncode == 3 and "reserved" in second.stderr
                                process.send_signal(signal.SIGTERM)
                                break
                            time.sleep(0.2)
                        else:
                            raise RuntimeError("image mutation not observed")
                    code = process.wait(timeout=300)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=300)
            expected_code = 0 if case == "success" else 143 if case == "sigterm" else 3
            assert code == expected_code, f"{case}: exit {code}, inspect {directory / 'cli.log'}"
            state = json.loads(run(*kubectl, "get", "deployment/customer-credit-api", "-o", "json"))
            actual_image = state["spec"]["template"]["spec"]["containers"][0]["image"]
            assert actual_image == (candidate if case == "success" else previous)
            if case != "success":
                assert all(
                    state["metadata"]["annotations"].get(k) == v for k, v in annotations.items()
                )
            if case == "signer-failure":
                assert not result.exists()
                record = json.loads(Path(f"{result}.recovery.json").read_text())
            else:
                run(
                    "cosign",
                    "verify-blob",
                    "--key",
                    str(public_key),
                    "--bundle",
                    f"{result}.sigstore.json",
                    str(result),
                )
                record = json.loads(result.read_text())
                # Verify that real cryptography rejects a changed result.
                altered = directory / "tampered.json"
                altered.write_text(result.read_text() + " ")
                rejected = subprocess.run(  # noqa: S603 - test result and public key
                    [  # noqa: S607 - isolated test PATH
                        "cosign",
                        "verify-blob",
                        "--key",
                        str(public_key),
                        "--bundle",
                        f"{result}.sigstore.json",
                        str(altered),
                    ],
                    capture_output=True,
                    check=False,
                    timeout=120,
                )
                assert rejected.returncode != 0
            if case != "success":
                assert record["rollback_status"] == "succeeded"
            cases.append(
                {
                    "case": case,
                    "exit_code": code,
                    "status": record["status"],
                    "image": actual_image,
                    "verified": True,
                }
            )
        return {
            "completed_at": dt.datetime.now(dt.UTC).isoformat(),
            "cases": cases,
            "node_image": NODE_IMAGE,
            "registry_image": registry_image,
            "images": images,
            "kind_version": run("kind", "version"),
            "cosign_version": run("cosign", "version", "--json"),
            "scope": "real deployment and crypto; fixture security reports and approvals",
        }
    finally:
        cleanup_resources(
            name,
            registry,
            output,
            started_cluster=started_cluster,
            started_registry=started_registry,
            primary_error=sys.exception(),
        )


def cleanup_resources(
    name: str,
    registry: str,
    output: Path,
    *,
    started_cluster: bool,
    started_registry: bool,
    primary_error: BaseException | None = None,
) -> None:
    errors: list[Exception] = []
    commands: list[tuple[tuple[str, ...], int]] = []
    if started_cluster:
        commands.extend(
            [
                (("kind", "export", "logs", "--name", name, str(output / "cluster-logs")), 300),
                (("kind", "delete", "cluster", "--name", name), 180),
            ]
        )
    if started_registry:
        commands.append((("docker", "rm", "--force", registry), 300))
    for command, timeout in commands:
        try:
            run(*command, timeout=timeout)
        except Exception as exc:
            errors.append(exc)
            print(f"Cleanup failed ({' '.join(command)}): {exc}", file=sys.stderr)
    if errors:
        if primary_error is not None:
            for error in errors:
                primary_error.add_note(f"Cleanup also failed: {error}")
        else:
            raise ExceptionGroup("integration resource cleanup failed", errors)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT / "build/integration-release")
    parser.add_argument(
        "--registry-image",
        default=os.environ.get(
            "FINGUARD_TEST_REGISTRY_IMAGE", REGISTRY_IMAGES.get(platform.machine())
        ),
    )
    args = parser.parse_args()
    if not args.registry_image:
        parser.error("--registry-image requires an immutable registry image")
    validate_image_reference(args.registry_image)
    for tool in ("docker", "kind", "kubectl", "cosign"):
        if not shutil.which(tool):
            parser.error(f"{tool} must be on PATH")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="finguard-integration-") as temporary:
        summary = exercise(output, Path(temporary), args.registry_image)
    (output / "integration-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"All release integration scenarios passed: {output}")


if __name__ == "__main__":
    main()
