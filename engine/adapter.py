"""Serialized engine execution and integrity gates from RFC-0001."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import CancelledError
from dataclasses import dataclass, replace
from threading import Lock
from typing import TypeVar

_COMMITMENT = "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46"  # F4
_END = frozenset({200001, 200007, 200008})  # F37


class EngineIntegrityError(RuntimeError):
    """The request failed its integrity window or output policy."""


class EngineUnavailable(RuntimeError):
    """The adapter cannot dispatch a warranted request."""


@dataclass(frozen=True)
class EngineResult:
    tokens: tuple[int, ...]
    integrity_window_closed: bool


@dataclass(frozen=True)
class Cursor:
    """An ordered position in one particular engine process's observed log."""

    instance: str
    position: int


@dataclass(frozen=True)
class Window:
    """The trusted reader acknowledges coverage through a post-completion barrier."""

    start: Cursor
    end: Cursor
    covered: bool
    integrity_error: bool


@dataclass(frozen=True)
class StartupEvidence:
    """Host measurements bound to the fresh process and its log source."""

    instance: str
    commitment_id: str
    launch_verified: bool
    float64_exact: bool
    reference_files_verified: bool
    weight_tensors_verified: bool


@dataclass(frozen=True)
class Canary:
    prompt: tuple[int, ...]
    max_tokens: int
    expected: tuple[int, ...]


@dataclass(frozen=True)
class GateStatus:
    commitment_verified: bool = False
    launch_verified: bool = False
    float64_exact: bool = False
    reference_files_verified: bool = False
    weight_tensors_verified: bool = False
    canaries_verified: bool = False

    @property
    def host_passed(self) -> bool:
        return all(
            (
                self.commitment_verified,
                self.launch_verified,
                self.float64_exact,
                self.reference_files_verified,
                self.weight_tensors_verified,
            )
        )


def _valid_ids(tokens: tuple[int, ...]) -> bool:
    return (
        isinstance(tokens, tuple)
        and bool(tokens)
        and all(type(token) is int and 0 <= token < 202048 for token in tokens)
    )


def _valid_prompt(prompt: tuple[int, ...], budget: int) -> bool:
    return (
        _valid_ids(prompt)
        and type(budget) is int
        and 1 <= budget <= min(256, 1024 - len(prompt))
    )


def _complete(reply: tuple[int, ...], budget: int) -> bool:
    return (
        _valid_ids(reply)
        and len(reply) <= budget
        and _END.isdisjoint(reply[:-1])
        and (len(reply) == budget or reply[-1] in _END)
    )


def _cursor(value: Cursor, instance: str | None, minimum: int) -> bool:
    return (
        isinstance(value, Cursor)
        and value.instance == instance
        and type(value.position) is int
        and value.position >= minimum
    )


def _closed(window: Window, start: Cursor) -> bool:
    return (
        isinstance(window, Window)
        and _cursor(window.start, start.instance, start.position)
        and window.start == start
        and _cursor(window.end, start.instance, start.position)
        and window.covered is True
        and window.integrity_error is False
    )


_T = TypeVar("_T")


def _host(call: Callable[[], _T], failure: type[RuntimeError], message: str) -> _T:
    try:
        return call()
    except CancelledError:
        raise
    except EngineIntegrityError:
        raise EngineIntegrityError("Engine integrity failure") from None
    except Exception:  # noqa: BLE001 -- host/transport diagnostics may contain private inputs.
        raise failure(message) from None


class Engine:
    """Own the sole execution slot for a supervised engine and its trusted readers."""

    def __init__(
        self,
        generate_tokens: Callable[[tuple[int, ...], int], tuple[int, ...]],
        begin_window: Callable[[], Cursor],
        finish_window: Callable[[Cursor], Window],
    ) -> None:
        self._generate_tokens = generate_tokens
        self._begin_window = begin_window
        self._finish_window = finish_window
        self._slot = Lock()
        self._gates = GateStatus()
        self._quarantined = False
        self._instance: str | None = None
        self._used_instances: set[str] = set()
        self._last_position = 0
        self._interrupted: Cursor | None = None

    @property
    def gates(self) -> GateStatus:
        return self._gates

    @property
    def ready(self) -> bool:
        return (
            self._gates.host_passed
            and self._gates.canaries_verified
            and not self._quarantined
        )

    @property
    def quarantined(self) -> bool:
        return self._quarantined

    def start(self, evidence: StartupEvidence, canaries: tuple[Canary, ...]) -> None:
        """Run host-attested gates and three exact canaries before any client work."""
        with self._slot:
            self._gates = GateStatus()
            if (
                not isinstance(evidence, StartupEvidence)
                or not isinstance(evidence.instance, str)
                or not evidence.instance
                or evidence.instance in self._used_instances
            ):
                raise EngineUnavailable("Fresh engine instance required")
            self._gates = GateStatus(
                commitment_verified=evidence.commitment_id == _COMMITMENT,
                launch_verified=evidence.launch_verified is True,
                float64_exact=evidence.float64_exact is True,
                reference_files_verified=evidence.reference_files_verified is True,
                weight_tensors_verified=evidence.weight_tensors_verified is True,
            )
            if not self._gates.host_passed:
                raise EngineUnavailable("Engine startup evidence incomplete")
            if (
                not isinstance(canaries, tuple)
                or len(canaries) != 3
                or not all(
                    isinstance(c, Canary)
                    and _valid_prompt(c.prompt, c.max_tokens)
                    and _complete(c.expected, c.max_tokens)
                    for c in canaries
                )
                or len({c.prompt for c in canaries}) != 3
            ):
                raise EngineUnavailable("Invalid startup canaries")
            self._instance = evidence.instance
            self._used_instances.add(evidence.instance)
            self._last_position = 0
            self._quarantined = False
            success = False
            try:
                for c in canaries:
                    if self._dispatch(c.prompt, c.max_tokens).tokens != c.expected:
                        raise EngineUnavailable("Canary token mismatch")
                self._gates = replace(self._gates, canaries_verified=True)
                success = True
            except EngineIntegrityError:
                raise EngineUnavailable("Canary integrity window failed") from None
            finally:
                if not success:
                    self._quarantined = True

    def generate(self, prompt: tuple[int, ...], max_tokens: int) -> EngineResult:
        if not _valid_prompt(prompt, max_tokens):
            raise ValueError("Invalid prompt or token budget")
        with self._slot:
            if not self.ready:
                raise EngineUnavailable("Engine gates are closed")
            return self._dispatch(prompt, max_tokens)

    def _dispatch(self, prompt: tuple[int, ...], budget: int) -> EngineResult:
        """Called with the slot held, including during startup canaries."""
        self._interrupted = None
        success = False
        try:
            start = _host(
                self._begin_window, EngineIntegrityError, "Engine log start unavailable"
            )
            if not _cursor(start, self._instance, self._last_position):
                raise EngineIntegrityError("Invalid engine log start")
            self._interrupted = start
            tokens = _host(
                lambda: self._generate_tokens(prompt, budget),
                EngineUnavailable,
                "Engine transport failed",
            )
            window = _host(
                lambda: self._finish_window(start),
                EngineIntegrityError,
                "Engine log checkpoint unavailable",
            )
            if (
                isinstance(window, Window)
                and window.start == start
                and _cursor(window.end, start.instance, start.position)
            ):
                self._last_position = window.end.position
            if not _closed(window, start):
                raise EngineIntegrityError("Engine log integrity window failed")
            if not _complete(tokens, budget):
                raise EngineIntegrityError("Incomplete or invalid engine reply")
            success = True
            self._interrupted = None
            return EngineResult(tokens=tokens, integrity_window_closed=True)
        finally:
            if not success:
                self._quarantined = True

    def reconcile(self, drain_and_checkpoint: Callable[[Cursor], Window]) -> None:
        """The supervisor must drain dispatch and confirm clean coverage of the entire window."""
        with self._slot:
            if self.ready:
                return
            start = self._interrupted
            if (
                not self._gates.canaries_verified
                or not self._quarantined
                or start is None
            ):
                raise EngineUnavailable("Fresh engine startup required")
            window = _host(
                lambda: drain_and_checkpoint(start),
                EngineUnavailable,
                "Engine reconciliation failed",
            )
            if not _closed(window, start) or window.end.position < self._last_position:
                raise EngineUnavailable("Engine reconciliation needs complete coverage")
            self._last_position = window.end.position
            self._interrupted = None
            self._quarantined = False
