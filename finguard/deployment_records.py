"""Exclusive result reservations, recovery journals, and staged signed publication."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from contextlib import ExitStack
from pathlib import Path
from types import TracebackType
from typing import Any

from .errors import ConfigurationError, DeploymentError
from .safeio import assert_no_symlink_components, atomic_write_text
from .signing import Runner, cosign_sign_blob


class DeploymentRecords:
    """Reserve all paths before mutation; publish the JSON last as completion marker.

    Two independent files cannot be renamed atomically together. Both are prepared
    before publication, and consumers must verify the pair. A crash may leave an
    orphan signature; the recovery journal and stale reservation are retained.
    """

    def __init__(
        self,
        output: Path,
        *,
        signing_key: str,
        bundle: Path | None,
        runner: Runner | None,
        force: bool,
    ) -> None:
        self.output = output.expanduser().absolute()
        self.bundle = (
            (bundle or Path(f"{output}.sigstore.json")).expanduser().absolute()
            if signing_key
            else None
        )
        self.journal = Path(f"{self.output}.recovery.json")
        self.signing_key = signing_key
        self.runner = runner
        self.force = force
        self.locks: list[Path] = []

    def __enter__(self) -> DeploymentRecords:
        paths = [self.output, self.journal]
        if self.bundle is not None:
            paths.append(self.bundle)
        if len({path.resolve() for path in paths}) != len(paths):
            raise ConfigurationError("deployment result, recovery, and signature paths must differ")
        try:
            for path in sorted(paths):
                assert_no_symlink_components(path, context="deployment audit")
                path.parent.mkdir(parents=True, exist_ok=True)
                lock = path.with_name(f".{path.name}.finguard-lock")
                try:
                    lock.mkdir(mode=0o700)
                except FileExistsError as exc:
                    raise ConfigurationError(
                        f"deployment audit path is reserved; inspect recovery before retry: {path}"
                    ) from exc
                self.locks.append(lock)
                atomic_write_text(
                    lock / "owner.json",
                    json.dumps({"pid": os.getpid(), "output": str(self.output)}) + "\n",
                    context="deployment reservation",
                )
                if path.exists() and (not self.force or not path.is_file()):
                    raise ConfigurationError(f"deployment audit path already exists: {path}")
            return self
        except BaseException:
            self._release()
            raise

    def checkpoint(self, record: dict[str, Any]) -> None:
        """Local recovery information, never represented as a signed final result."""
        try:
            atomic_write_text(
                self.journal,
                _json({**record, "record_kind": "unsigned-recovery-journal"}),
                context="deployment recovery journal",
            )
        except ConfigurationError as exc:
            raise DeploymentError(str(exc)) from exc

    def persist(self, record: dict[str, Any]) -> None:
        with ExitStack() as stack:
            staging = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(prefix=".finguard-result-", dir=self.output.parent)
                )
            )
            staged_output = staging / "result.json"
            atomic_write_text(staged_output, _json(record), context="staged deployment result")
            staged_bundle: Path | None = None
            if self.bundle is not None:
                signature_staging = Path(
                    stack.enter_context(
                        tempfile.TemporaryDirectory(
                            prefix=".finguard-signature-", dir=self.bundle.parent
                        )
                    )
                )
                staged_bundle = signature_staging / "signature.json"
                cosign_sign_blob(
                    staged_output,
                    staged_bundle,
                    key=self.signing_key,
                    runner=self.runner or subprocess.run,
                )
            published_bundle = False
            published_output = False
            try:
                # Recheck after signing, which may take long enough for unrelated
                # writers to create a result despite our cooperative reservation.
                for path in (self.output, self.bundle):
                    if path is not None:
                        assert_no_symlink_components(path, context="deployment result publish")
                        if path.exists() and not self.force:
                            raise DeploymentError(f"deployment result already exists: {path}")
                if staged_bundle is not None and self.bundle is not None:
                    self._publish(staged_bundle, self.bundle)
                    published_bundle = True
                self._publish(staged_output, self.output)
                published_output = True
            except (OSError, ConfigurationError) as exc:
                raise DeploymentError("cannot publish deployment result") from exc
            finally:
                # On failure, remove only our newly linked signature, never a
                # preexisting or concurrently replaced file owned by someone else.
                if (
                    published_bundle
                    and not self.force
                    and staged_bundle is not None
                    and self.bundle is not None
                    and not published_output
                    and self.bundle.exists()
                    and self.bundle.samefile(staged_bundle)
                ):
                    self.bundle.unlink()

    def _publish(self, source: Path, target: Path) -> None:
        if self.force:
            os.replace(source, target)
        else:
            # link() fails atomically if any writer won the destination path.
            os.link(source, target)

    def _release(self) -> None:
        for lock in reversed(self.locks):
            (lock / "owner.json").unlink(missing_ok=True)
            lock.rmdir()
        self.locks.clear()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._release()


def _json(record: dict[str, Any]) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
