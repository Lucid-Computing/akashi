"""Private readouts from the engine, authenticated quicknet and signed audit history."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Literal

from auditor.beacon import round_is_open, verify_round
from auditor.verdict_signing import verify_signed
from engine.adapter import EngineIntegrityError, EngineUnavailable

Mode = Literal["live", "soak"]
BeaconRead = Callable[[], tuple[Mapping[str, object], Mapping[str, object]] | None]


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _labels(service: str, mode: Mode) -> str:
    if type(mode) is not str or mode not in ("live", "soak"):
        raise ValueError("Unknown monitoring mode")
    return f'service="{service}",mode="{mode}"'


def _gauge(name: str, labels: str, value: float) -> str:
    return f"# TYPE {name} gauge\n{name}{{{labels}}} {value}\n"


class EngineMetrics:
    """One registry for the gateway's observed engine, reused across reattachment."""

    def __init__(self, *, mode: Mode) -> None:
        self._labels = _labels("engine", mode)
        self._lock = Lock()
        self._passed: bool | None = None
        self._initialized = False
        self._requests = self._unwarranted = 0

    def attaching(self) -> None:
        with self._lock:
            self._passed = None

    @contextmanager
    def startup(self) -> Iterator[None]:
        self.attaching()
        try:
            yield
        except EngineUnavailable:
            with self._lock:
                self._passed = False
            raise
        else:
            with self._lock:
                self._passed = self._initialized = True

    def startup_passed(self) -> bool:
        with self._lock:
            return self._passed is True

    @contextmanager
    def dispatch(self) -> Iterator[None]:
        integrity_failure = False
        try:
            yield
        except EngineIntegrityError:
            integrity_failure = True
            raise
        finally:
            with self._lock:
                self._requests += 1
                self._unwarranted += int(integrity_failure)

    def prometheus(self) -> str:
        with self._lock:
            passed, initialized = self._passed, self._initialized
            requests, failures = self._requests, self._unwarranted
        labels = self._labels
        text = _gauge("akashi_observation_coverage", labels, int(passed is not None))
        if passed is not None:
            text += _gauge("akashi_engine_startup_gate_failed", labels, int(not passed))
        if initialized:
            text += f"# TYPE akashi_engine_requests_total counter\nakashi_engine_requests_total{{{labels}}} {requests}\n"
            # The real stream reader gives us one integrity bit, without a verified fault subtype.
            text += f'# TYPE akashi_unwarranted_total counter\nakashi_unwarranted_total{{{labels},outcome="engine_error",reason="engine_error"}} {failures}\n'
        return text


class BeaconMetrics:
    """Check the sampler's latest public round using the same pinned chain as selection."""

    def __init__(
        self,
        *,
        mode: Mode,
        enabled: Callable[[], bool | None],
        latest: BeaconRead,
        clock: Callable[[], datetime] = _utc,
    ) -> None:
        self._labels = _labels("sampler", mode)
        self._enabled, self._latest, self._clock = enabled, latest, clock

    def _observe(self) -> tuple[bool | None, float | None]:
        enabled = None
        try:
            configured = self._enabled()
            if type(configured) is not bool:
                return None, None
            if not configured:
                return False, None
            enabled = True
            observation = self._latest()
            if observation is None:
                return enabled, None
            info, beacon = dict(observation[0]), dict(observation[1])
            number, now = beacon.get("round"), self._clock()
            if type(number) is not int or not round_is_open(number, now):
                return enabled, None
            verify_round(number, info, beacon)
            # These exact metadata fields were authenticated by verify_round (F36).
            genesis, period = info["genesis_time"], info["period"]
            assert isinstance(genesis, int) and isinstance(period, int)
            return enabled, now.timestamp() - (genesis + (number - 1) * period)
        except Exception:  # noqa: BLE001 -- suppress reader, clock, and signature diagnostics.
            return enabled, None

    def ready(self) -> bool:
        _, lag = self._observe()
        return lag is not None and lag <= 60  # BeaconLagHigh, specs/observability.md.

    def prometheus(self) -> str:
        enabled, lag = self._observe()
        labels = self._labels
        available = lag is not None
        text = _gauge("akashi_observation_coverage", labels, int(available))
        state = (
            "available" if available else "disabled" if enabled is False else "unknown"
        )
        text += "# TYPE akashi_sampling_coverage gauge\n"
        for label in ("available", "disabled", "unknown"):
            text += f'akashi_sampling_coverage{{{labels},state="{label}"}} {int(state == label)}\n'
        if enabled is True:
            text += _gauge("akashi_beacon_available", labels, int(available))
        if lag is not None:
            text += _gauge("akashi_beacon_lag_seconds", labels, lag)
        return text


class SignedVerdictMetrics:
    """Count unique signed verdicts in the five-minute alert window of a trusted read model."""

    def __init__(
        self,
        *,
        mode: Mode,
        recent: Callable[[int], list[dict[str, object]]],
        lookup_key: Callable[[str, str], bytes],
        clock: Callable[[], datetime] = _utc,
    ) -> None:
        self._labels = _labels("auditor", mode)
        self._recent, self._lookup, self._clock = recent, lookup_key, clock

    def _deviations(self) -> int | None:
        try:
            rows = self._recent(1)
            now = self._clock()
            if not isinstance(rows, list) or now.utcoffset() is None:
                return None
            seen: set[str] = set()
            count = 0
            for row in rows:
                doc = verify_signed(row, self._lookup)
                subject = doc["challenge_id"]
                at = doc["verified_at"]
                assert isinstance(subject, str) and isinstance(at, str)
                stamp = datetime.fromisoformat(at[:-1] + "+00:00")
                if subject in seen or stamp > now:
                    return None
                seen.add(subject)
                if stamp > now - timedelta(minutes=5) and doc["outcome"] == "DEVIATES":
                    count += 1
            return count
        except Exception:  # noqa: BLE001 -- unavailable history or invalid signature is missing coverage.
            return None

    def ready(self) -> bool:
        return self._deviations() is not None

    def prometheus(self) -> str:
        count = self._deviations()
        labels = self._labels
        text = _gauge("akashi_observation_coverage", labels, int(count is not None))
        if count is not None:
            text += _gauge("akashi_signed_deviations_last_5m", labels, count)
        return text
