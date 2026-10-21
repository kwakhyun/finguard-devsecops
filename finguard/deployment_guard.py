"""Deployment-scoped ownership and conditional Kubernetes mutations.

The lock is stored on the Deployment, so all CI systems and context aliases
addressing that object share it. Locks never expire automatically: a stopped
owner must be investigated before an operator clears its annotation.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .errors import DeploymentError
from .jsonio import strict_json_loads

DEPLOYMENT_LOCK_ANNOTATION = "finguard.io/deployment-lock"
AUDIT_ANNOTATIONS = (
    "finguard.io/change-id",
    "finguard.io/evidence-sha256",
    "finguard.io/release-subject-sha256",
)
Runner = Callable[..., subprocess.CompletedProcess[str]]
_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-fA-F]{64}$")


class DeploymentConflict(DeploymentError):
    """Another actor changed the object; overwriting it would be unsafe."""


@dataclass(frozen=True)
class DeploymentState:
    uid: str
    resource_version: str
    annotations: dict[str, str]
    template: dict[str, Any]
    container_index: int

    @property
    def image(self) -> str:
        return str(self.template["spec"]["containers"][self.container_index]["image"])


def parse_deployment_state(payload: str, *, container: str) -> DeploymentState:
    try:
        value = strict_json_loads(payload)
    except ValueError as exc:
        raise DeploymentError("kubectl returned invalid deployment JSON") from exc
    if not isinstance(value, dict):
        raise DeploymentError("kubectl deployment response must be an object")
    metadata, spec = value.get("metadata"), value.get("spec")
    if not isinstance(metadata, dict) or not isinstance(spec, dict):
        raise DeploymentError("kubectl deployment response is missing metadata or spec")
    uid, resource_version = metadata.get("uid"), metadata.get("resourceVersion")
    if (
        not isinstance(uid, str)
        or not uid
        or not isinstance(resource_version, str)
        or not resource_version
    ):
        raise DeploymentError("deployment identity and resourceVersion are required")
    annotations = metadata.get("annotations")
    if annotations is None:
        annotations = {}
    if not isinstance(annotations, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in annotations.items()
    ):
        raise DeploymentError("deployment annotations are invalid")
    template = spec.get("template")
    if not isinstance(template, dict) or not isinstance(template.get("spec"), dict):
        raise DeploymentError("deployment pod template is invalid")
    containers = template["spec"].get("containers")
    if not isinstance(containers, list) or not all(isinstance(item, dict) for item in containers):
        raise DeploymentError("deployment containers are invalid")
    matches = [index for index, item in enumerate(containers) if item.get("name") == container]
    if len(matches) != 1:
        raise DeploymentError("target container was not found exactly once in the deployment")
    image = containers[matches[0]].get("image")
    if not isinstance(image, str) or not _IMAGE.fullmatch(image):
        raise DeploymentError("current deployment image is not immutable; refusing mutation")
    return DeploymentState(uid, resource_version, annotations, template, matches[0])


class DeploymentGuard:
    """Use optimistic concurrency only to acquire ownership, then guard owned fields.

    Status updates and ordinary controller resourceVersion changes do not break
    image mutation or recovery. A changed UID, template, or owner does.
    """

    def __init__(
        self, base: list[str], *, deployment: str, container: str, runner: Runner, timeout: int
    ) -> None:
        self.base = base
        self.target = f"deployment/{deployment}"
        self.container = container
        self.runner = runner
        self.timeout = timeout
        self.token = uuid.uuid4().hex
        self.uid = ""
        self.attempted = False
        self.original: DeploymentState | None = None
        self.expected_template: dict[str, Any] | None = None
        self.expected_annotations: dict[str, str | None] = {}

    def _run(self, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        return self.runner(
            [*self.base, *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )

    def _read(self) -> DeploymentState:
        return parse_deployment_state(
            self._run(["get", self.target, "-o", "json"]).stdout, container=self.container
        )

    def _patch(self, operations: list[dict[str, Any]]) -> None:
        self._run(["patch", self.target, "--type=json", "-p", json.dumps(operations)])

    def acquire(self) -> DeploymentState:
        for _ in range(5):
            state = self._read()
            owner = state.annotations.get(DEPLOYMENT_LOCK_ANNOTATION)
            if owner == self.token and state.uid == self.uid:
                self.original = state
                return state
            if owner is not None:
                raise DeploymentError(
                    "deployment target is locked; inspect recovery before removing "
                    + DEPLOYMENT_LOCK_ANNOTATION
                )
            self.uid = state.uid
            self.attempted = True
            operations: list[dict[str, Any]] = [
                {"op": "test", "path": "/metadata/uid", "value": state.uid},
                {
                    "op": "test",
                    "path": "/metadata/resourceVersion",
                    "value": state.resource_version,
                },
                {
                    "op": "add",
                    "path": "/metadata/annotations",
                    "value": {
                        **state.annotations,
                        DEPLOYMENT_LOCK_ANNOTATION: self.token,
                    },
                },
            ]
            try:
                self._patch(operations)
            except subprocess.CalledProcessError:
                # Retry a controller update or a lost response; the next read
                # must show either no owner or this exact owner before proceeding.
                continue
            acquired = self._read()
            if (
                acquired.uid != self.uid
                or acquired.annotations.get(DEPLOYMENT_LOCK_ANNOTATION) != self.token
            ):
                raise DeploymentConflict("deployment ownership changed during lock acquisition")
            self.original = acquired
            return acquired
        raise DeploymentError("cannot acquire deployment target lock after concurrent updates")

    def _ownership_tests(self) -> list[dict[str, Any]]:
        return [
            {"op": "test", "path": "/metadata/uid", "value": self.uid},
            {
                "op": "test",
                "path": _annotation_path(DEPLOYMENT_LOCK_ANNOTATION),
                "value": self.token,
            },
        ]

    def apply(self, image: str, annotations: dict[str, str]) -> None:
        assert self.original is not None
        self.expected_template = copy.deepcopy(self.original.template)
        self.expected_template["spec"]["containers"][self.original.container_index]["image"] = image
        self.expected_annotations = dict(annotations)
        last_error: subprocess.CalledProcessError | None = None
        for _ in range(5):
            state = self._read_owned()
            if state.template != self.original.template or any(
                state.annotations.get(key) != self.original.annotations.get(key)
                for key in AUDIT_ANNOTATIONS
            ):
                if (
                    last_error is not None
                    and state.template == self.expected_template
                    and all(
                        state.annotations.get(key) == value
                        for key, value in self.expected_annotations.items()
                    )
                ):
                    # The API applied our patch but its response was lost. Let
                    # the caller perform the same guarded recovery as any failure.
                    raise last_error
                raise DeploymentConflict(
                    "deployment changed before mutation; refusing to overwrite it"
                )
            try:
                self._patch(
                    [
                        *self._ownership_tests(),
                        {"op": "test", "path": "/spec/template", "value": self.original.template},
                        # Testing the map also detects an audit key newly added by
                        # another actor, which a test on an absent key cannot express.
                        {"op": "test", "path": "/metadata/annotations", "value": state.annotations},
                        {
                            "op": "replace",
                            "path": (
                                f"/spec/template/spec/containers/{self.original.container_index}/image"
                            ),
                            "value": image,
                        },
                        *(
                            {"op": "add", "path": _annotation_path(key), "value": value}
                            for key, value in annotations.items()
                        ),
                    ]
                )
                return
            except subprocess.CalledProcessError as exc:
                # An unrelated controller annotation may have changed. Re-read
                # and retry only while the original template/audit are unchanged.
                last_error = exc
        assert last_error is not None
        raise last_error

    def verify(self) -> None:
        state = self._read_owned()
        if state.template != self.expected_template or any(
            state.annotations.get(key) != value for key, value in self.expected_annotations.items()
        ):
            raise DeploymentConflict(
                "deployment changed outside this execution; refusing to overwrite it"
            )

    def _read_owned(self) -> DeploymentState:
        state = self._read()
        if state.uid != self.uid or state.annotations.get(DEPLOYMENT_LOCK_ANNOTATION) != self.token:
            raise DeploymentConflict("deployment ownership changed; refusing to overwrite it")
        return state

    def restore(self) -> bool:
        assert self.original is not None
        state = self._read_owned()
        if state.template == self.original.template and all(
            state.annotations.get(key) == self.original.annotations.get(key)
            for key in AUDIT_ANNOTATIONS
        ):
            return False  # The failed mutation never reached the API server.
        self.verify()
        operations = [
            *self._ownership_tests(),
            {"op": "test", "path": "/spec/template", "value": self.expected_template},
            *(
                {"op": "test", "path": _annotation_path(key), "value": value}
                for key, value in self.expected_annotations.items()
            ),
            {
                "op": "replace",
                "path": (f"/spec/template/spec/containers/{self.original.container_index}/image"),
                "value": self.original.image,
            },
        ]
        for key in AUDIT_ANNOTATIONS:
            if key in self.original.annotations:
                operations.append(
                    {
                        "op": "add",
                        "path": _annotation_path(key),
                        "value": self.original.annotations[key],
                    }
                )
            else:
                operations.append({"op": "remove", "path": _annotation_path(key)})
        try:
            self._patch(operations)
        except subprocess.CalledProcessError as exc:
            raise DeploymentConflict("conditional deployment rollback was rejected") from exc
        self.expected_template = self.original.template
        self.expected_annotations = {
            key: self.original.annotations.get(key) for key in AUDIT_ANNOTATIONS
        }
        return True

    def release(self, *, suppress_errors: bool) -> None:
        if not self.attempted:
            return
        try:
            state = self._read()
            if (
                state.uid != self.uid
                or state.annotations.get(DEPLOYMENT_LOCK_ANNOTATION) != self.token
            ):
                return  # Never clear another execution's lock.
            self._patch(
                [
                    *self._ownership_tests(),
                    {"op": "remove", "path": _annotation_path(DEPLOYMENT_LOCK_ANNOTATION)},
                ]
            )
        except (subprocess.SubprocessError, OSError, DeploymentError) as exc:
            if not suppress_errors:
                raise DeploymentError(
                    "deployment result recorded but target lock release failed; inspect recovery"
                ) from exc


def _annotation_path(key: str) -> str:
    return "/metadata/annotations/" + key.replace("~", "~0").replace("/", "~1")
