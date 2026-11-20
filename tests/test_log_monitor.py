"""Independent observation of the actual signed log and held public promise evidence."""

import json
import shutil
import ssl
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock
from urllib.parse import urlsplit
from wsgiref.simple_server import WSGIRequestHandler, make_server

from log.http import LogApp
from log.monitor import LogMonitor
from log.reader import LogReader
from log.receipt import leaf_hash
from log.store import MerkleLog
from tests.test_engine_proxy import make_certificates
from tests.test_log_store import KEY, KEY_ID, LOG_ID, preimage


class Quiet(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


class MonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.start = self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.log = self.make_log("log")
        self.monitor = self.reopen()
        self.private_salt = "91" * 32

    def reopen(self) -> LogMonitor:
        keys = {("log", KEY_ID): KEY.public_key().public_bytes_raw()}
        return LogMonitor(
            self.root / "independent.db",
            log_id=LOG_ID,
            lookup_key=lambda r, k: keys[r, k],
            clock=lambda: self.now,
        )

    def make_log(self, name: str) -> MerkleLog:
        return MerkleLog(
            self.root / name,
            log_id=LOG_ID,
            log_key_id=KEY_ID,
            signing_key=KEY,
            checkpoint_seconds=1,
            leaf_hash=leaf_hash,
            clock=lambda: self.now,
        )

    def issue(self, log: MerkleLog, index: int = 0) -> dict[str, object]:
        leaf = {
            **preimage(index),
            "served_at": self.now.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
        }
        promise = log.append(leaf)
        promise.pop("leaf_index")
        return {**promise, "salt": self.private_salt}

    def read(self, route: str) -> object:
        url = urlsplit(route)
        start = Mock()
        data = b"".join(
            LogApp(self.log, gateway_identity="gateway")(
                {
                    "PATH_INFO": "/log/v1/" + url.path,
                    "QUERY_STRING": url.query,
                    "REQUEST_METHOD": "GET",
                },
                start,
            )
        )
        if start.call_args.args[0] != "200 OK":
            raise OSError("Log response unavailable")
        return json.loads(data)

    def test_verified_growth_and_coverage_persist_after_restart(self) -> None:
        self.monitor.observe(self.read)
        for i in range(4):
            promise = self.issue(self.log, i)
            self.monitor.hold(promise)
            self.now += timedelta(seconds=9)
            self.monitor.observe(self.read)
            self.assertEqual(
                self.monitor.verified_leaf(i)["leaf_hash"], promise["leaf_hash"]
            )
        self.assertEqual(self.reopen().incidents(), [])
        self.assertEqual(self.reopen().checkpoint(), self.log.head())
        self.assertNotIn(
            self.private_salt.encode(), (self.root / "independent.db").read_bytes()
        )

    def test_omission_requires_signed_post_deadline_history(self) -> None:
        fork = self.make_log("other")
        receipt = self.issue(fork)
        self.monitor.hold(receipt)
        self.now += timedelta(seconds=10)
        self.monitor.observe(self.read)
        self.assertEqual(self.monitor.incidents(), [])
        self.now += timedelta(milliseconds=1)
        self.monitor.observe(self.read)
        self.assertEqual(
            [a["kind"] for a in self.monitor.incidents()], ["overdue_checkpoint"]
        )
        self.log.checkpoint()
        self.monitor.observe(self.read)
        self.monitor.observe(self.read)
        evidence = self.reopen().incidents()
        self.assertEqual(
            [a["kind"] for a in evidence], ["overdue_checkpoint", "omitted_promise"]
        )
        self.assertEqual(evidence[-1]["promise"]["promise_sig"], receipt["promise_sig"])
        self.assertEqual(
            evidence[-1]["checkpoint"]["signature"], self.log.head()["signature"]
        )
        self.assertNotIn(self.private_salt, json.dumps(evidence))

    def test_independent_conflicting_signed_root_persists_both_witnesses(self) -> None:
        self.issue(self.log, 0)
        self.monitor.observe(self.read)
        alternate = self.make_log("fork")
        self.issue(alternate, 1)
        self.monitor.observe(self.read, head=alternate.head())
        (alert,) = self.reopen().incidents()
        self.assertEqual(alert["kind"], "conflicting_history")
        self.assertEqual(alert["previous"], self.log.head())
        self.assertEqual(alert["observed"], alternate.head())
        self.assertEqual(self.monitor.checkpoint(), self.log.head())

    def test_inconsistent_growth_or_changed_public_fields_cannot_advance_the_tip(
        self,
    ) -> None:
        self.issue(self.log)
        self.monitor.observe(self.read)
        saved = self.monitor.checkpoint()
        self.issue(self.log, 1)

        def bad_bounds(route: str) -> object:
            if route.startswith("consistency?"):
                return {"from": True, "to": 2, "consistency_path": []}
            return self.read(route)

        self.monitor.observe(bad_bounds)
        self.assertEqual(self.monitor.checkpoint(), saved)
        self.assertEqual(self.monitor.incidents()[-1]["kind"], "unverified_consistency")

        def polluted(route: str) -> object:
            if route == "receipts/1":
                return {**self.log.receipt(1), "private": "private-value-canary"}
            return self.read(route)

        self.monitor.observe(polluted)
        self.assertEqual(self.monitor.checkpoint(), saved)
        with self.assertRaises(KeyError):
            self.monitor.verified_leaf(1)
        self.assertNotIn(
            b"private-value-canary", (self.root / "independent.db").read_bytes()
        )
        self.monitor.observe(self.read)
        self.assertEqual(self.monitor.checkpoint(), self.log.head())

    def test_unreachable_log_reports_a_gap_and_retries_alert_delivery(self) -> None:
        self.monitor.hold(self.issue(self.make_log("held")))
        self.now += timedelta(seconds=11)
        stop = threading.Event()
        read = Mock(side_effect=OSError("private diagnostic"))
        with self.assertRaises(OSError):
            self.monitor.run(
                read, stop, interval=0.01, emit=Mock(side_effect=OSError())
            )
        alerts = []

        def emit(report: dict[str, Any]) -> None:
            alerts.append(report)
            stop.set()

        self.reopen().run(read, stop, interval=0.01, emit=emit)
        self.assertEqual([a["kind"] for a in alerts], ["observation_unavailable"])
        self.assertNotIn("private diagnostic", json.dumps(alerts))

    @unittest.skipUnless(shutil.which("openssl"), "requires OpenSSL for test-only TLS")
    def test_pinned_https_reader_observes_actual_log(self) -> None:
        make_certificates(self.root, cast(str, shutil.which("openssl")))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(self.root / "proxy.pem", self.root / "proxy.key")
        with make_server(
            "127.0.0.1",
            0,
            cast(Any, LogApp(self.log, gateway_identity="gateway")),
            handler_class=Quiet,
        ) as http:
            http.socket = tls.wrap_socket(http.socket, server_side=True)
            thread = threading.Thread(
                target=http.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
            )
            thread.start()
            try:
                read = LogReader(
                    f"https://127.0.0.1:{http.server_port}/log/v1/",
                    timeout=2,
                    max_response_bytes=65536,
                    context=ssl.create_default_context(
                        cafile=str(self.root / "ca.pem")
                    ),
                )
                self.monitor.hold(self.issue(self.log))
                self.monitor.observe(read)
                self.assertEqual(self.monitor.verified_leaf(0), self.log.receipt(0))
            finally:
                http.shutdown()
                thread.join()
