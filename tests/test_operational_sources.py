"""Exercise the normal private readouts with public fixtures and a controlled clock."""

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta
from unittest import TestCase
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from engine.adapter import Engine, EngineIntegrityError, EngineUnavailable, Window
from engine.service import attach_engine
from operations.health import HealthApp
from operations.role_metrics import BeaconMetrics, EngineMetrics, SignedVerdictMetrics
from tests.test_beacon import FIRST, GENESIS, INFO
from tests.test_engine_adapter import CANARIES, EVIDENCE, Host


def _get(app: HealthApp, path: str) -> tuple[str, str]:
    start = Mock()
    body = b"".join(app({"REQUEST_METHOD": "GET", "PATH_INFO": path}, start))
    return start.call_args.args[0], body.decode()


def _app(metrics: Callable[[], str], ready: Callable[[], bool]) -> HealthApp:
    return HealthApp(startup=ready, engine=ready, log=ready, metrics=metrics)


def _engine_scrapes() -> list[str]:
    registry = EngineMetrics(mode="live")
    host = Host()
    host.engine = Engine(host.send, host.begin, host.finish, metrics=registry)
    app = HealthApp(
        startup=registry.startup_passed,
        engine=lambda: host.engine.ready,
        log=lambda: True,
        metrics=registry.prometheus,
    )
    host.start()
    host.engine.generate((1,), 1)
    _, healthy = _get(app, "/metrics")
    host.finish.side_effect = lambda start: Window(start, start, True, True)
    try:
        host.engine.generate((1,), 1)
    except EngineIntegrityError:
        pass
    else:
        raise AssertionError("Engine fixture accepted an unclean request window")
    try:
        host.engine.start(
            replace(EVIDENCE, instance="new", float64_exact=False), CANARIES
        )
    except EngineUnavailable:
        pass
    else:
        raise AssertionError("Engine fixture opened with a failed startup gate")
    _, fault = _get(app, "/metrics")
    host.instance = "recovered"
    host.finish.side_effect = host.clean
    host.start()
    host.engine.generate((1,), 1)
    _, recovered = _get(app, "/metrics")
    return [healthy, fault, recovered]


def _sampler_scrapes() -> list[str]:
    latest = Mock(return_value=(INFO, FIRST))
    probe = BeaconMetrics(
        mode="live", enabled=lambda: True, latest=latest, clock=lambda: GENESIS
    )
    app = _app(probe.prometheus, probe.ready)
    _, healthy = _get(app, "/metrics")
    latest.return_value = None
    _, fault = _get(app, "/metrics")
    latest.return_value = (INFO, FIRST)
    _, recovered = _get(app, "/metrics")
    return [healthy, fault, recovered]


def _signed_deviation(stamp: datetime, key: Ed25519PrivateKey) -> dict[str, object]:
    from auditor.verdict_signing import sign_verdict

    return sign_verdict(
        {
            "version": "vig-verdict/1",
            "challenge_id": "12345678-1234-4123-8123-123456789abc",
            "transcript_commitment": "12" * 32,
            "outcome": "DEVIATES",
            "reason": "first_divergence",
            "verified_at": stamp.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "auditor_key_id": "fixture",
            "proof_sha256": "23" * 32,
            "statement_sha256": "34" * 32,
        },
        key,
    )


def _auditor_scrapes() -> list[str]:
    signer = Ed25519PrivateKey.generate()
    rows: list[dict[str, object]] = []
    clock = Mock(return_value=GENESIS)
    probe = SignedVerdictMetrics(
        mode="live",
        recent=lambda hours: rows,
        lookup_key=lambda role, kid: signer.public_key().public_bytes_raw(),
        clock=clock,
    )
    app = _app(probe.prometheus, probe.ready)
    _, healthy = _get(app, "/metrics")
    rows.append(_signed_deviation(GENESIS, signer))
    _, fault = _get(app, "/metrics")
    clock.return_value = GENESIS + timedelta(minutes=5)
    _, recovered = _get(app, "/metrics")
    return [healthy, fault, recovered]


def role_drill_scrapes() -> dict[str, list[str]]:
    """Healthy, fault, recovered /metrics responses for the three fixed CPU incident drills."""
    return {
        "engine": _engine_scrapes(),
        "auditor": _auditor_scrapes(),
        "sampler": _sampler_scrapes(),
    }


class OperationalSourceTests(TestCase):
    def test_private_metrics_three_role_drill_and_recovery(self) -> None:
        scrapes = role_drill_scrapes()
        for role, sample, values in (
            (
                "engine",
                'vig_engine_startup_gate_failed{service="engine",mode="live"}',
                (0, 1, 0),
            ),
            (
                "engine",
                'vig_engine_requests_total{service="engine",mode="live"}',
                (1, 2, 3),
            ),
            (
                "engine",
                'vig_unwarranted_total{service="engine",mode="live",outcome="engine_error",reason="engine_error"}',
                (0, 1, 1),
            ),
            (
                "auditor",
                'vig_signed_deviations_last_5m{service="auditor",mode="live"}',
                (0, 1, 0),
            ),
            (
                "sampler",
                'vig_beacon_available{service="sampler",mode="live"}',
                (1, 0, 1),
            ),
        ):
            with self.subTest(sample=sample):
                for body, value in zip(scrapes[role], values, strict=True):
                    self.assertIn(f"{sample} {value}", body.splitlines())
                    self.assertNotIn("challenge_id", body)
                    self.assertNotIn("signature", body)
        _, outage, _ = scrapes["sampler"]
        self.assertNotIn("vig_beacon_lag_seconds", outage)

    def test_disabled_unknown_and_invalid_beacon_lag_and_readiness(self) -> None:
        enabled, latest, now = Mock(), Mock(), Mock()
        probe = BeaconMetrics(mode="soak", enabled=enabled, latest=latest, clock=now)
        app = _app(probe.prometheus, probe.ready)
        for value, state in ((False, "disabled"), (None, "unknown")):
            enabled.return_value = value
            self.assertIn(f'state="{state}"}} 1', probe.prometheus())
            self.assertNotIn("vig_beacon_available", probe.prometheus())
            self.assertEqual(_get(app, "/health/ready")[0], "503 Service Unavailable")
        latest.assert_not_called()
        enabled.return_value = True
        for now_at, info, record in (
            (GENESIS - timedelta(seconds=1), INFO, FIRST),
            (GENESIS, INFO | {"schemeID": "unknown"}, FIRST),
            (GENESIS, INFO, FIRST | {"signature": "00" * 48}),
        ):
            now.return_value = now_at
            latest.return_value = (info, record)
            self.assertFalse(probe.ready())
            self.assertIn('state="unknown"} 1', probe.prometheus())
            self.assertNotIn("vig_beacon_lag_seconds", probe.prometheus())
        latest.return_value = (INFO, FIRST)
        now.return_value = GENESIS + timedelta(seconds=60)
        self.assertTrue(probe.ready())
        now.return_value += timedelta(seconds=1)
        self.assertFalse(probe.ready())
        self.assertIn('mode="soak"} 61.0', probe.prometheus())

    def test_engine_startup_and_request_population(self) -> None:
        host, registry = Host(), EngineMetrics(mode="soak")
        client, observation = Mock(), Mock()
        client.healthy.return_value = True
        client.generate.side_effect = host.send
        observation.startup.return_value = (EVIDENCE, CANARIES)
        observation.begin.side_effect, observation.finish.side_effect = (
            host.begin,
            host.finish,
        )
        self.assertNotIn("startup_gate_failed", registry.prometheus())
        engine = attach_engine(
            client,
            observation,
            metrics=registry,
            startup_timeout=1.0,
            health_poll_seconds=0.1,
        )
        with self.assertRaises(ValueError):
            engine.generate((), 1)
        self.assertIn(
            'vig_engine_requests_total{service="engine",mode="soak"} 0',
            registry.prometheus(),
        )
        client.generate.side_effect = EngineUnavailable("private-diagnostic")
        with self.assertRaises(EngineUnavailable):
            engine.generate((1,), 1)
        with self.assertRaises(EngineUnavailable):
            engine.generate((1,), 1)
        registry.attaching()
        text = registry.prometheus()
        self.assertIn('vig_engine_requests_total{service="engine",mode="soak"} 1', text)
        self.assertIn('reason="engine_error"} 0', text)
        self.assertNotIn("vig_engine_startup_gate_failed", text)
        self.assertNotIn("private-diagnostic", text)

    def test_wrong_auditor_key_repeated_document_and_future_time_are_unknown(
        self,
    ) -> None:
        signer, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        signed = _signed_deviation(GENESIS, signer)
        reader = Mock(return_value=[signed])
        keys = Mock(return_value=other.public_key().public_bytes_raw())
        probe = SignedVerdictMetrics(
            mode="live", recent=reader, lookup_key=keys, clock=lambda: GENESIS
        )
        self.assertFalse(probe.ready())
        self.assertNotIn("vig_signed_deviations", probe.prometheus())
        keys.return_value = signer.public_key().public_bytes_raw()
        self.assertTrue(probe.ready())
        keys.assert_called_with("auditor", "fixture")
        for rows in (
            [signed, signed],
            [signed | {"reason": "private-diagnostic"}],
            [_signed_deviation(GENESIS + timedelta(seconds=1), signer)],
        ):
            reader.return_value = rows
            self.assertFalse(probe.ready())
            text = probe.prometheus()
            self.assertNotIn("vig_signed_deviations", text)
            self.assertIn(
                'vig_observation_coverage{service="auditor",mode="live"} 0', text
            )
            self.assertNotIn("private-diagnostic", text)
        reader.side_effect = OSError("private-diagnostic")
        self.assertFalse(probe.ready())
        self.assertNotIn("vig_signed_deviations", probe.prometheus())
        reader.side_effect = None
        reader.return_value = []
        self.assertTrue(probe.ready())
        self.assertIn(
            'vig_signed_deviations_last_5m{service="auditor",mode="live"} 0',
            probe.prometheus(),
        )
