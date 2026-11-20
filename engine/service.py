"""Provider-side launch observation and gateway-side attachment."""

from __future__ import annotations

import math
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Event
from typing import TYPE_CHECKING, Protocol

from engine.adapter import (
    Canary,
    Cursor,
    Engine,
    EngineUnavailable,
    StartupEvidence,
    Window,
)
from engine.launch import LaunchConfig, LaunchError, StartedEngine, start
from engine.process_log import ProcessLog
from engine.transport import EngineClient

if TYPE_CHECKING:
    from operations.role_metrics import EngineMetrics


class Observation(Protocol):
    def startup(self) -> tuple[StartupEvidence, tuple[Canary, ...]]: ...
    def begin(self) -> Cursor: ...
    def finish(self, start: Cursor) -> Window: ...


@dataclass(frozen=True)
class EngineObservation:
    _started: StartedEngine
    _log: ProcessLog

    def startup(self) -> tuple[StartupEvidence, tuple[Canary, ...]]:
        self._log.begin()  # Require live, complete coverage for this instance.
        return self._started.startup.evidence(), self._started.canaries

    def begin(self) -> Cursor:
        return self._log.begin()

    def finish(self, start: Cursor) -> Window:
        return self._log.finish(start)


def _intervals(*values: float) -> None:
    if any(not math.isfinite(v) or v <= 0 for v in values):
        raise ValueError("invalid engine supervision interval")


@contextmanager
def observe_engine(
    config: LaunchConfig,
    *,
    startup_timeout: float,
    health_poll_seconds: float,
    checkpoint_timeout: float,
    max_log_line_bytes: int,
) -> Iterator[EngineObservation]:
    """Launch under the provider identity and observe both live F21 loader markers."""
    _intervals(startup_timeout, health_poll_seconds, checkpoint_timeout)
    started = start(config)
    try:
        marks = Event()

        def observe(line: bytes) -> None:
            if marks.is_set():
                return
            started.startup.observe(line)
            try:
                started.startup.evidence()
            except LaunchError:
                return
            marks.set()

        log = ProcessLog(
            started.process,
            started.instance,
            observe,
            max_line_bytes=max_log_line_bytes,
            checkpoint_timeout=checkpoint_timeout,
        )
        try:
            deadline = time.monotonic() + startup_timeout
            while not marks.is_set():
                left = deadline - time.monotonic()
                if left <= 0 or started.process.poll() is not None:
                    raise EngineUnavailable(
                        "serving process failed its startup deadline"
                    )
                marks.wait(min(left, health_poll_seconds))
            observation = EngineObservation(started, log)
            observation.startup()
            yield observation
        finally:
            log.close()
    finally:
        started.close()


def attach_engine(
    client: EngineClient,
    observation: Observation,
    *,
    startup_timeout: float,
    health_poll_seconds: float,
    metrics: EngineMetrics | None = None,
) -> Engine:
    """Run the gateway's mTLS health check and three measured token canaries."""
    _intervals(startup_timeout, health_poll_seconds)
    if metrics is not None:
        metrics.attaching()
    deadline = time.monotonic() + startup_timeout
    while (left := deadline - time.monotonic()) > 0:
        if client.healthy(min(left, health_poll_seconds)):
            try:
                evidence, canaries = observation.startup()
            except EngineUnavailable:
                pass
            else:
                engine = Engine(
                    client.generate,
                    observation.begin,
                    observation.finish,
                    metrics=metrics,
                )
                engine.start(evidence, canaries)
                return engine
        time.sleep(min(max(0, deadline - time.monotonic()), health_poll_seconds))
    raise EngineUnavailable("gateway could not attach to a healthy observed engine")
