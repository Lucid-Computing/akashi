"""Exercise log routes using a real signing key and a temporary durable store."""

import hashlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from log.http import LogApp, run_checkpoints
from log.store import MerkleLog


class LogHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.clock = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.log = MerkleLog(
            Path(temp.name, "log.sqlite"),
            log_id="bb" * 32,
            log_key_id="key-1",
            signing_key=Ed25519PrivateKey.generate(),
            leaf_hash=lambda fields: hashlib.sha256(
                json.dumps(fields, sort_keys=True).encode()
            ).hexdigest(),
            clock=lambda: self.clock,
        )
        self.app = LogApp(self.log, gateway_identity="authenticated-gateway")
        self.leaf = {
            "log_id": "bb" * 32,
            "log_key_id": "key-1",
            "endpoint_id": "fixture",
            "request_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "served_at": "2026-01-01T00:00:00.000Z",
            "beacon_round": 22,
            "sampling_mode": "live",
            "commitment_id": "11" * 32,
            "render_profile": "22" * 32,
            "params_digest": "33" * 32,
            "transcript_commitment": "44" * 32,
        }

    def request(
        self, path: str, method: str = "GET", **options: object
    ) -> tuple[str, bytes]:
        path, _, query = path.partition("?")
        env = {
            "PATH_INFO": path,
            "REQUEST_METHOD": method,
            "QUERY_STRING": query,
            **options,
        }
        start = Mock()
        body = b"".join(self.app(env, start))
        status, headers = start.call_args.args
        self.assertEqual(int(dict(headers)["Content-Length"]), len(body))
        return str(status), body

    def post(self, body: bytes, **env: object) -> tuple[str, bytes]:
        fields = {
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
            "REMOTE_USER": "authenticated-gateway",
            **env,
        }
        return self.request("/log/v1/promise", "POST", **fields)

    def test_public_reads_keep_explicit_historical_sizes(self) -> None:
        first = self.post(json.dumps(self.leaf).encode())
        self.assertEqual(first[0], "200 OK")
        self.assertEqual(json.loads(first[1])["leaf_index"], 0)
        self.assertEqual(first, self.post(json.dumps(self.leaf).encode()))
        first_head = self.request("/log/v1/sth")
        other = {**self.leaf, "request_id": "f47ac10b-58cc-4372-a567-0e02b2c3d480"}
        self.assertEqual(self.post(json.dumps(other).encode())[0], "200 OK")
        for path, expected in (
            ("sth?size=1", json.loads(first_head[1])),
            ("sth?size=1&log_key_id=key-1", json.loads(first_head[1])),
            ("proof/0?size=1", {"leaf_index": 0, "tree_size": 1, "audit_path": []}),
            (
                "consistency?from=1&to=2",
                {
                    "from": 1,
                    "to": 2,
                    "consistency_path": [p.hex() for p in self.log.consistency(1, 2)],
                },
            ),
        ):
            status, body = self.request("/log/v1/" + path)
            self.assertEqual(status, "200 OK")
            self.assertEqual(json.loads(body), expected)
        status, body = self.request("/log/v1/receipts/range?start=0&end=2")
        self.assertEqual(status, "200 OK")
        records = json.loads(body)
        self.assertEqual([r["leaf_index"] for r in records], [0, 1])
        self.assertEqual(records[0], json.loads(self.request("/log/v1/receipts/0")[1]))
        self.assertNotIn("promise_sig", records[0])
        self.assertNotIn("salt", records[0])

    def test_unauthorized_and_invalid_writes_leave_no_leaf(self) -> None:
        for body, env, code in (
            (
                b"",
                {"REMOTE_USER": None, "HTTP_REMOTE_USER": "authenticated-gateway"},
                401,
            ),
            (b"", {"CONTENT_LENGTH": str(256 * 1024 + 1)}, 413),
            (b'{"log_id":"one","log_id":"two"}', {}, 400),
            (json.dumps({**self.leaf, "salt": "private-canary"}).encode(), {}, 400),
            (b"private-canary", {"CONTENT_LENGTH": "999"}, 400),
        ):
            with self.subTest(code=code):
                status, response = self.post(body, **env)
                self.assertTrue(status.startswith(str(code)))
                self.assertEqual(response, b"")
        self.assertEqual(self.log.head()["tree_size"], 0)
        self.post(json.dumps(self.leaf).encode())
        conflict = {**self.leaf, "sampling_mode": "soak"}
        self.assertEqual(self.post(json.dumps(conflict).encode())[0], "409 Conflict")

    def test_read_errors(self) -> None:
        for path, method, code in (
            ("sth", "POST", 405),
            ("promise", "GET", 405),
            ("absent", "GET", 404),
            ("receipts/0", "GET", 404),
            ("proof/1?size=2&size=2", "GET", 400),
            ("consistency?from=-1&to=2", "GET", 400),
            ("receipts/range?start=0&end=10001", "GET", 400),
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    self.request("/log/v1/" + path, method)[0].startswith(str(code))
                )

    def test_supervised_cadence_stops_and_persists_idle_head(self) -> None:
        stop = Mock(spec=Event)
        stop.is_set.return_value = False
        prior = self.log.head()

        def advance(delay: float) -> bool:
            self.clock += timedelta(seconds=delay)
            return self.clock > datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(
                seconds=60
            )

        stop.wait.side_effect = advance
        run_checkpoints(self.log, stop)
        updated = self.log.head()
        self.assertEqual(updated["tree_size"], prior["tree_size"])
        self.assertGreater(str(updated["timestamp"]), str(prior["timestamp"]))
        self.assertNotEqual(updated["signature"], prior["signature"])
