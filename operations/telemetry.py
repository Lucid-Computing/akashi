"""Private RFC-0009 event logging, trace context and Prometheus metrics."""

import json
import math
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from sys import float_info
from threading import Lock
from time import monotonic
from uuid import uuid4

# Labels are finite deployment vocabulary. No caller-provided message, identifier or tag is serialized.
_EVENTS = {
    ("gateway", "request"): (
        "akashi_requests_total",
        {"served", "rejected", "unavailable", "unwarranted"},
    ),
    ("engine", "gate"): ("akashi_gates_total", {"passed", "failed"}),
    ("engine", "unwarranted"): (
        "akashi_unwarranted_total",
        {"range_failure", "forced_token", "engine_error"},
    ),
    ("log", "append"): ("akashi_appends_total", {"success", "failure"}),
    ("sampler", "beacon"): ("akashi_beacon_total", {"available", "unavailable"}),
    ("sampler", "selection"): (
        "akashi_selections_total",
        {"pending", "selected", "unselected", "gap", "disabled"},
    ),
    ("prover", "proof"): (
        "akashi_proofs_total",
        {"success", "rejected", "timeout", "unavailable"},
    ),
    ("auditor", "verdict"): (
        "akashi_verdicts_total",
        {"CONFORMS", "DEVIATES", "INCOMPLETE", "EXCUSED_RANGE", "UNAVAILABLE"},
    ),
}
_PHASES = {
    "gateway": {"wait", "canonical_render", "receipt_generate", "response_encode"},
    "engine": {"prefill", "decode"},
    "log": {"append", "merge"},
    "sampler": {"selection"},
    "prover": {"prove"},
    "auditor": {"verify"},
}
_REASONS = {
    "unsupported_parameter",
    "unsupported_content",
    "context_too_long",
    "queue_full",
    "auth_failed",
    "body_limit",
    "range_failure",
    "forced_token",
    "engine_error",
    "engine_unavailable",
    "incomplete_reply",
    "invalid_promise",
    "append_failure",
    "beacon_unavailable",
    "escrow_expired",
    "deadline",
    "tool_failure",
    "float64_check",
    "tensor_verification",
    "canary",
    "timeout",
}
_ERRORS = {
    "unavailable",
    "unwarranted",
    "failed",
    "failure",
    "range_failure",
    "forced_token",
    "engine_error",
    "timeout",
    "gap",
    "DEVIATES",
    "INCOMPLETE",
    "UNAVAILABLE",
}
_STAGE_SERIES = {
    ("engine", "prefill"): "akashi_engine_seconds",
    ("engine", "decode"): "akashi_engine_seconds",
    ("gateway", "receipt_generate"): "akashi_receipt_generation_seconds",
    ("prover", "prove"): "akashi_prove_seconds",
    ("auditor", "verify"): "akashi_verify_seconds",
}
_REQUEST_STATUS = {
    "served": 200,
    "rejected": 400,
    "unwarranted": 502,
    "unavailable": 503,
}
_REJECT_STATUS = {
    "queue_full": 429,
    "auth_failed": 401,
    "body_limit": 413,
    "append_failure": 500,
    "invalid_promise": 500,
}
_TYPES = {name: "counter" for name, _ in _EVENTS.values()}
_TYPES.update(dict.fromkeys(_STAGE_SERIES.values(), "summary"))
_TYPES.update(
    akashi_selected_total="counter",
    akashi_engine_startup_gate_failed="gauge",
    akashi_promise_to_sth_seconds="gauge",
    akashi_escrow_gaps_total="counter",
    akashi_stage_seconds="summary",
    akashi_queue_depth="gauge",
)
_correlation: ContextVar[str | None] = ContextVar(
    "akashi_internal_correlation", default=None
)


def _labels(service: str, mode: str) -> str:
    if (
        type(service) is not str
        or service not in _PHASES
        or type(mode) is not str
        or mode not in ("live", "soak")
    ):
        raise ValueError("unknown telemetry service or mode")
    return f'service="{service}",mode="{mode}"'


@dataclass(frozen=True, slots=True)
class Event:
    service: str
    name: str
    outcome: str
    mode: str = "live"
    reason: str | None = None
    divisor: int | None = None


class Telemetry:
    def __init__(self, sink: Callable[[str], None]) -> None:
        self._sink = sink
        self._lock = Lock()
        self._samples: dict[str, dict[str, int | float]] = {
            family: {} for family in _TYPES
        }

    @contextmanager
    def trace(self) -> Iterator[str]:
        """Start an internal trace or propagate the trace active in this execution context."""
        current = _correlation.get()
        if current is not None:
            yield current
            return
        trace_id = str(uuid4())
        reset = _correlation.set(trace_id)
        try:
            yield trace_id
        finally:
            _correlation.reset(reset)

    def _log(
        self, service: str, event: str, mode: str, outcome: str, **fields: object
    ) -> None:
        severity = (
            "ERROR"
            if outcome in _ERRORS
            else "WARN"
            if outcome in ("rejected", "disabled")
            else "INFO"
        )
        record: dict[str, object] = {
            "schema_version": 1,
            "timestamp": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "severity": severity,
            "service": service,
            "event": event,
            "mode": mode,
            "outcome": outcome,
            **fields,
        }
        trace_id = _correlation.get()
        if trace_id is not None:
            record["correlation_id"] = trace_id
        self._sink(json.dumps(record, allow_nan=False, separators=(",", ":")))

    def _add(self, family: str, sample: str, value: float) -> None:
        values = self._samples[family]
        total = values.get(sample, 0) + value
        if not total <= float_info.max:
            raise ValueError("metric would exceed the finite sample range")
        values[sample] = total

    def emit(self, event: Event) -> None:
        """Validate before writing either metrics or structured output."""
        if type(event) is not Event:
            raise TypeError("expected a typed telemetry event")
        labels = _labels(event.service, event.mode)
        rule = (
            _EVENTS.get((event.service, event.name))
            if type(event.name) is str
            else None
        )
        if (
            rule is None
            or type(event.outcome) is not str
            or event.outcome not in rule[1]
        ):
            raise ValueError("unknown telemetry event or outcome")
        if event.reason is not None and (
            type(event.reason) is not str or event.reason not in _REASONS
        ):
            raise ValueError("unknown telemetry reason")
        if event.divisor is not None and (
            event.name != "selection"
            or type(event.divisor) is not int
            or event.divisor not in (1, 20, 1000)
        ):
            raise ValueError("invalid selection divisor")
        family = rule[0]
        outcome = event.outcome
        dimensions = f'{labels},outcome="{outcome}"'
        if event.name == "request":
            status = _REQUEST_STATUS[outcome]
            if outcome == "rejected" and event.reason is not None:
                status = _REJECT_STATUS.get(event.reason, status)
            dimensions += f',status="{status}"'
        elif event.name == "verdict":
            dimensions += f',result="{outcome}"'
        elif event.name == "unwarranted":
            dimensions += f',reason="{outcome}"'
        with self._lock:
            self._add(family, f"{family}{{{dimensions}}}", 1)
            if event.name == "gate":
                name = "akashi_engine_startup_gate_failed"
                self._samples[name][f"{name}{{{labels}}}"] = int(outcome == "failed")
            elif event.name == "selection":
                if outcome == "gap":
                    self._add(
                        "akashi_escrow_gaps_total", f"akashi_escrow_gaps_total{{{labels}}}", 1
                    )
                elif outcome == "selected":
                    divisor = event.divisor or (20 if event.mode == "live" else 1)
                    self._add(
                        "akashi_selected_total",
                        f'akashi_selected_total{{{labels},N="{divisor}"}}',
                        1,
                    )
        detail: dict[str, object] = {}
        if event.reason is not None:
            detail["reason"] = event.reason
        if event.divisor is not None:
            detail["divisor"] = event.divisor
        self._log(event.service, event.name, event.mode, outcome, **detail)

    def set_depth(self, service: str, depth: int, *, mode: str = "live") -> None:
        labels = _labels(service, mode)
        if type(depth) is not int or not 0 <= depth <= float_info.max:
            raise ValueError("expected a nonnegative finite queue depth")
        with self._lock:
            self._samples["akashi_queue_depth"][f"akashi_queue_depth{{{labels}}}"] = depth

    @contextmanager
    def stage(self, service: str, phase: str, *, mode: str = "live") -> Iterator[None]:
        labels = _labels(service, mode)
        if type(phase) is not str or phase not in _PHASES[service]:
            raise ValueError("unknown telemetry phase")
        self._log(service, "stage_start", mode, "started", phase=phase)
        start = monotonic()
        outcome = "failure"
        try:
            yield
            outcome = "success"
        finally:
            duration = monotonic() - start
            if not math.isfinite(duration) or duration < 0:
                raise ValueError("invalid monotonic duration")
            suffix = f'{{{labels},phase="{phase}",outcome="{outcome}"}}'
            families = ["akashi_stage_seconds"]
            named = _STAGE_SERIES.get((service, phase))
            if named is not None:
                families.append(named)
            with self._lock:
                for family in families:
                    self._add(family, family + "_sum" + suffix, duration)
                    self._add(family, family + "_count" + suffix, 1)
                if service == "log" and phase == "merge" and outcome == "success":
                    name = "akashi_promise_to_sth_seconds"
                    self._samples[name][f"{name}{{{labels}}}"] = duration
            self._log(
                service,
                "stage_end",
                mode,
                outcome,
                phase=phase,
                duration_seconds=duration,
            )

    def prometheus(self) -> str:
        """Export only observed samples, preserving absence before a component reports."""
        lines = []
        with self._lock:
            for family, metric_type in _TYPES.items():
                lines.append(f"# TYPE {family} {metric_type}")
                lines.extend(
                    f"{name} {value}"
                    for name, value in sorted(self._samples[family].items())
                )
        return "\n".join(lines) + "\n"
