import json
import unittest
from unittest.mock import Mock

from operations.health import HealthApp
from operations.telemetry import Event, Telemetry


class HealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gates = Mock(return_value=True)
        self.engine = Mock(return_value=True)
        self.log = Mock(return_value=True)
        self.beacon = Mock(return_value=True)
        self.registry = Telemetry(lambda _: None)
        self.metrics = Mock(wraps=self.registry.prometheus)
        self.app = HealthApp(
            startup=self.gates,
            engine=self.engine,
            log=self.log,
            beacon=self.beacon,
            metrics=self.metrics,
        )

    def get(self, path: str, method: str = "GET") -> tuple[str, dict[str, str], bytes]:
        response = Mock()
        body = b"".join(
            self.app({"REQUEST_METHOD": method, "PATH_INFO": path}, response)
        )
        status, headers = response.call_args.args
        self.assertEqual(dict(headers)["Content-Length"], str(len(body)))
        return status, dict(headers), body

    def test_live_does_not_require_any_dependency(self) -> None:
        self.gates.side_effect = RuntimeError("private-canary")
        status, _, body = self.get("/health/live")
        self.assertEqual(status, "200 OK")
        health = json.loads(body)
        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["checks"], {})
        self.assertGreaterEqual(health["uptime_seconds"], 0)
        for probe in (self.gates, self.engine, self.log, self.beacon, self.metrics):
            probe.assert_not_called()

    def test_startup_gate_also_controls_readiness(self) -> None:
        self.gates.return_value = False
        status, _, body = self.get("/health/startup")
        self.assertEqual(status, "503 Service Unavailable")
        self.assertEqual(json.loads(body)["checks"], {"startup": "fail"})
        self.engine.assert_not_called()
        self.assertEqual(self.get("/health/ready")[0], "503 Service Unavailable")
        self.gates.return_value = True
        self.assertEqual(self.get("/health/startup")[0], "200 OK")

    def test_readiness_tracks_loss_and_recovery_without_leaking_diagnostics(
        self,
    ) -> None:
        self.assertEqual(self.get("/health/ready")[0], "200 OK")
        for name, probe in (
            ("engine", self.engine),
            ("log", self.log),
            ("beacon", self.beacon),
        ):
            with self.subTest(name=name):
                probe.side_effect = RuntimeError("private-canary")
                status, _, body = self.get("/health/ready")
                self.assertEqual(status, "503 Service Unavailable")
                self.assertEqual(json.loads(body)["checks"][name], "fail")
                self.assertNotIn(b"private-canary", body)
                probe.side_effect = None
                self.assertEqual(self.get("/health/ready")[0], "200 OK")
        self.gates.return_value = "private-canary"
        self.assertEqual(self.get("/health/ready")[0], "503 Service Unavailable")

    def test_private_metrics_and_route_dispatch(self) -> None:
        self.registry.emit(
            Event(service="sampler", name="selection", outcome="gap", mode="live")
        )
        status, headers, body = self.get("/metrics")
        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers["Content-Type"], "text/plain; version=0.0.4; charset=utf-8"
        )
        self.assertEqual(body, self.registry.prometheus().encode())
        self.assertIn(b"akashi_escrow_gaps_total{", body)
        self.assertEqual(self.get("/health/unknown")[0], "404 Not Found")
        self.assertEqual(self.get("/health/ready", "POST")[0], "405 Method Not Allowed")
        self.gates.assert_not_called()

    def test_metrics_failure_is_redacted(self) -> None:
        self.metrics.side_effect = RuntimeError("private-canary")
        status, headers, body = self.get("/metrics")
        self.assertEqual(status, "503 Service Unavailable")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(body, b'{"status":"unhealthy"}')
        self.metrics.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.get("/metrics")
