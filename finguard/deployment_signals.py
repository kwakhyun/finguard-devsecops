"""Bounded, recoverable interruption of a deployment in the main thread."""

from __future__ import annotations

import signal
import threading
from types import FrameType, TracebackType
from typing import Any


class DeploymentInterrupted(KeyboardInterrupt):
    """Preserve the signal's conventional exit code after recovery."""

    def __init__(self, signum: int) -> None:
        self.signum = signum
        super().__init__(f"deployment interrupted by {signal.Signals(signum).name}")


class DeploymentSignals:
    """Catch the first stop request; let bounded recovery finish on repeated signals."""

    def __init__(self) -> None:
        self.recovering = False
        self.previous: dict[int, Any] = {}

    def __enter__(self) -> DeploymentSignals:
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGINT, signal.SIGTERM):
                self.previous[signum] = signal.getsignal(signum)
                signal.signal(signum, self._handle)
        return self

    def _handle(self, signum: int, frame: FrameType | None) -> None:
        if not self.recovering:
            self.recovering = True
            raise DeploymentInterrupted(signum)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        for signum, previous in self.previous.items():
            signal.signal(signum, previous)
