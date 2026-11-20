"""Private telemetry contracts from docs/spec/05-observability.md and RFC-0009."""

import asyncio
import json
import re
import unittest
from concurrent.futures import ThreadPoolExecutor
from typing import Any, cast
from unittest.mock import patch
from uuid import UUID

from operations.telemetry import Event, Telemetry


def samples(text: str) -> dict[tuple[str, frozenset[tuple[str, str]]], float]:
    """Read the numeric samples produced by the private Prometheus exporter."""
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        metric, number = line.rsplit(" ", 1)
        name, _, labels = metric.partition("{")
        key = (name, frozenset(re.findall(r'(\w+)="([^"]*)"', labels)))
        if key in result:
            raise AssertionError(f"duplicate series for {key}")
        result[key] = float(number)
    return result


class TelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logs: list[str] = []
        self.tel = Telemetry(self.logs.append)

    def metric(self, name: str, **labels: str) -> float:
        matching = [
            value
            for (family, series_labels), value in samples(self.tel.prometheus()).items()
            if family == name and labels.items() <= series_labels
        ]
        self.assertEqual(len(matching), 1, (name, labels))
        return matching[0]

    def test_only_allowlisted_event_fields_are_serialized(self) -> None:
        self.tel.emit(
            Event(service="gateway", name="request", outcome="served", mode="live")
        )
        event = json.loads(self.logs[0])
        self.assertEqual(
            set(event),
            {
                "schema_version",
                "timestamp",
                "severity",
                "service",
                "event",
                "mode",
                "outcome",
            },
        )
        self.assertEqual(
            (
                event["schema_version"],
                event["severity"],
                event["event"],
                event["outcome"],
            ),
            (1, "INFO", "request", "served"),
        )
        self.assertRegex(
            event["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
        )
        previous = (tuple(self.logs), self.tel.prometheus())
        base: dict[str, Any] = {
            "service": "gateway",
            "name": "request",
            "outcome": "served",
            "mode": "live",
        }
        for field in (
            "prompt",
            "reply",
            "token_ids",
            "salt",
            "challenge_token",
            "pickup_secret",
            "api_key",
            "proof",
            "correlation_id",
            "service",
            "name",
            "outcome",
            "reason",
            "mode",
        ):
            marker = f"private-{field}-canary"
            with self.subTest(field=field):
                with self.assertRaises((TypeError, ValueError)):
                    self.tel.emit(Event(**(base | {field: marker})))
                self.assertNotIn(marker, "".join(self.logs) + self.tel.prometheus())
                self.assertEqual((tuple(self.logs), self.tel.prometheus()), previous)

    def test_counters_distinguish_coverage_and_tool_outcomes(self) -> None:
        categories = (
            (
                "gateway",
                "request",
                "vig_requests_total",
                ("served", "unwarranted", "unavailable", "rejected"),
            ),
            ("engine", "gate", "vig_gates_total", ("passed", "failed")),
            (
                "engine",
                "unwarranted",
                "vig_unwarranted_total",
                ("range_failure", "forced_token", "engine_error"),
            ),
            ("log", "append", "vig_appends_total", ("success", "failure")),
            ("sampler", "beacon", "vig_beacon_total", ("available", "unavailable")),
            (
                "sampler",
                "selection",
                "vig_selections_total",
                ("pending", "unselected", "disabled", "gap", "selected"),
            ),
            (
                "prover",
                "proof",
                "vig_proofs_total",
                ("success", "rejected", "timeout", "unavailable"),
            ),
            (
                "auditor",
                "verdict",
                "vig_verdicts_total",
                ("CONFORMS", "DEVIATES", "INCOMPLETE", "EXCUSED_RANGE", "UNAVAILABLE"),
            ),
        )
        for service, name, metric, outcomes in categories:
            for outcome in outcomes:
                self.tel.emit(
                    Event(service=service, name=name, outcome=outcome, mode="live")
                )
                self.assertEqual(
                    self.metric(metric, service=service, mode="live", outcome=outcome),
                    1,
                )
        self.assertEqual(
            self.metric("vig_escrow_gaps_total", service="sampler", mode="live"), 1
        )

    def test_documented_gate_and_deviation_alert_selectors(self) -> None:
        for state, expected in (("failed", 1), ("passed", 0)):
            self.tel.emit(
                Event(service="engine", name="gate", outcome=state, mode="live")
            )
            self.assertEqual(self.metric("vig_engine_startup_gate_failed"), expected)
        for verdict in ("DEVIATES", "CONFORMS", "DEVIATES"):
            self.tel.emit(
                Event(service="auditor", name="verdict", outcome=verdict, mode="live")
            )
        self.assertEqual(self.metric("vig_verdicts_total", result="DEVIATES"), 2)
        self.tel.emit(
            Event(
                service="gateway",
                name="request",
                outcome="rejected",
                reason="queue_full",
                mode="live",
            )
        )
        self.assertEqual(self.metric("vig_requests_total", status="429"), 1)
        self.tel.emit(
            Event(
                service="engine",
                name="unwarranted",
                outcome="range_failure",
                mode="live",
            )
        )
        self.assertEqual(
            self.metric("vig_unwarranted_total", reason="range_failure"), 1
        )

    def test_selection_divisor_labels_are_bounded(self) -> None:
        self.tel.emit(
            Event(
                service="sampler",
                name="selection",
                outcome="selected",
                mode="live",
                divisor=1000,
            )
        )
        self.assertEqual(self.metric("vig_selected_total", N="1000"), 1)
        with self.assertRaises(ValueError):
            self.tel.emit(
                Event(
                    service="sampler",
                    name="selection",
                    outcome="selected",
                    mode="live",
                    divisor=999,
                )
            )
        self.assertNotIn('N="999"', self.tel.prometheus())

    def test_trace_isolation_and_cleanup(self) -> None:
        async def task() -> str:
            with self.tel.trace() as correlation:
                await asyncio.sleep(0)
                self.tel.emit(
                    Event(
                        service="gateway", name="request", outcome="served", mode="live"
                    )
                )
                await asyncio.sleep(0)
                with self.tel.stage("engine", "decode", mode="live"):
                    await asyncio.sleep(0)
                return correlation

        async def run() -> list[str]:
            return list(await asyncio.gather(task(), task()))

        ids = asyncio.run(run())
        self.assertNotEqual(ids[0], ids[1])
        events = [json.loads(s) for s in self.logs]
        for identifier in ids:
            self.assertEqual(str(UUID(identifier)), identifier)
            self.assertEqual(
                [e["event"] for e in events if e["correlation_id"] == identifier],
                ["request", "stage_start", "stage_end"],
            )
            self.assertNotIn(identifier, self.tel.prometheus())
        with self.assertRaisesRegex(RuntimeError, "expected"), self.tel.trace():
            raise RuntimeError("expected")
        self.tel.emit(
            Event(service="log", name="append", outcome="success", mode="live")
        )
        self.assertNotIn("correlation_id", json.loads(self.logs[-1]))

    def test_stage_timing_and_failure_redaction(self) -> None:
        with patch(
            "operations.telemetry.monotonic", side_effect=[15.0, 15.125, 20.0, 20.75]
        ):
            with self.tel.stage("engine", "decode", mode="live"):
                pass
            with (
                self.assertRaisesRegex(RuntimeError, "private-proof-canary"),
                self.tel.stage("engine", "decode", mode="live"),
            ):
                raise RuntimeError("private-proof-canary")
        ends = [e for e in map(json.loads, self.logs) if e["event"] == "stage_end"]
        self.assertEqual(
            [(e["phase"], e["outcome"], e["duration_seconds"]) for e in ends],
            [("decode", "success", 0.125), ("decode", "failure", 0.75)],
        )
        self.assertNotIn(
            "private-proof-canary", "".join(self.logs) + self.tel.prometheus()
        )
        for outcome, total in (("success", 0.125), ("failure", 0.75)):
            labels = {
                "service": "engine",
                "mode": "live",
                "phase": "decode",
                "outcome": outcome,
            }
            self.assertEqual(self.metric("vig_stage_seconds_count", **labels), 1)
            self.assertEqual(self.metric("vig_stage_seconds_sum", **labels), total)

    def test_depth_is_a_bounded_gauge(self) -> None:
        for depth in (3, 1, 0):
            self.tel.set_depth("gateway", depth, mode="live")
            self.assertEqual(
                self.metric("vig_queue_depth", service="gateway", mode="live"), depth
            )
        for invalid in (-1, True, float("nan")):
            with (
                self.subTest(depth=invalid),
                self.assertRaises((TypeError, ValueError)),
            ):
                self.tel.set_depth("gateway", cast(int, invalid), mode="live")
        for service, mode in (
            ("private-id-canary", "live"),
            ("gateway", "private-mode-canary"),
        ):
            with (
                self.subTest(service=service),
                self.assertRaises((TypeError, ValueError)),
            ):
                self.tel.set_depth(service, 1, mode=mode)
        self.assertNotIn("canary", self.tel.prometheus())

    def test_concurrent_updates_preserve_counts(self) -> None:
        def record(_: int) -> None:
            for _ in range(10):
                self.tel.emit(
                    Event(
                        service="gateway", name="request", outcome="served", mode="live"
                    )
                )

        with ThreadPoolExecutor(max_workers=4) as workers:
            list(workers.map(record, range(12)))
        self.assertEqual(len(self.logs), 120)
        self.assertEqual(
            self.metric(
                "vig_requests_total", service="gateway", mode="live", outcome="served"
            ),
            120,
        )
