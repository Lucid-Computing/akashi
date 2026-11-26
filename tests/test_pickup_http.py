"""Exercise private lookup, no-store and rate controls against actual HTTP requests."""

from __future__ import annotations

import contextlib
import io
import json
import socket
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread
from wsgiref.simple_server import WSGIServer

from pickup.crypto import open as open_envelope
from pickup.crypto import seal
from pickup.http import PerIPLimit, PickupApp, make_pickup_server
from pickup.store import PickupStore

_BASE = "/receipts/v1/pickup/"
_PRIVATE = "fixture-holder-private-text"


def _get(
    server: WSGIServer,
    path: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        conn.request(method, path, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


class PickupHttpTests(unittest.TestCase):
    def _server(self, app: PickupApp) -> WSGIServer:
        server = make_pickup_server(app, port=0)
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join)
        self.addCleanup(server.shutdown)
        return server

    def test_live_envelope_and_indistinguishable_misses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 11, 20, tzinfo=timezone.utc)
            store = PickupStore(Path(tmp).resolve() / "pickup.db", clock=lambda: now)
            app = PickupApp(
                store, limiter=PerIPLimit(requests=32, period_seconds=60, max_peers=2)
            )
            bundle = {
                "version": "akashi/1",
                "receipt": {"fixture": _PRIVATE},
                "prompt_token_ids": [1],
                "reply_token_ids": [2],
            }
            chat = [{"role": "user", "content": _PRIVATE}]
            secret = bytes(range(32))
            identifier, envelope = seal(bundle, chat, 1, "reply", secret)
            binding = "1a" * 32
            expiry = now + timedelta(days=7)
            capture = io.StringIO()
            with contextlib.redirect_stderr(capture):
                server = self._server(app)
                misses = [_get(server, _BASE + identifier)]
                store.reserve(identifier, binding, expiry)
                misses.append(_get(server, _BASE + identifier))
                store.publish(identifier, binding, envelope, expiry)
                code, headers, body = _get(server, _BASE + identifier)
                self.assertEqual((code, headers["Cache-Control"]), (200, "no-store"))
                self.assertEqual(headers["Content-Type"], "application/json")
                self.assertNotIn(_PRIVATE.encode(), body)
                decoded = json.loads(body)
                self.assertEqual(decoded, envelope)
                self.assertEqual(
                    open_envelope(decoded, secret, chat, 1, "reply"), bundle
                )
                for method in ("POST", "HEAD", "DELETE"):
                    code, headers, body = _get(server, _BASE + identifier, method)
                    self.assertEqual((code, headers["Allow"], body), (405, "GET", b""))
                    self.assertEqual(headers["Cache-Control"], "no-store")
                for path in (
                    _BASE,
                    _BASE[:-1],
                    _BASE + identifier.upper(),
                    _BASE + identifier + "/more",
                    _BASE + identifier + "?extra=yes",
                    _BASE + "%" + format(ord(identifier[0]), "02x") + identifier[1:],
                ):
                    misses.append(_get(server, path))
                now = expiry
                misses.append(_get(server, _BASE + identifier))
                for code, headers, body in misses:
                    self.assertEqual(
                        (code, headers["Cache-Control"], body), (404, "no-store", b"")
                    )
                self.assertEqual(
                    {
                        tuple(sorted((k, v) for k, v in headers.items() if k != "Date"))
                        for _, headers, _ in misses
                    },
                    {
                        tuple(
                            sorted(
                                (k, v) for k, v in misses[0][1].items() if k != "Date"
                            )
                        )
                    },
                )
                # A parser-level error must not reflect the request line or log it.
                with socket.create_connection(
                    ("127.0.0.1", server.server_port), timeout=5
                ) as sock:
                    sock.sendall(f"GET {_BASE}{identifier} HTTP/7.bad\r\n\r\n".encode())
                    self.assertNotIn(identifier.encode(), sock.makefile("rb").read())
            self.assertEqual(capture.getvalue(), "")

    def test_forwarding_headers_cannot_bypass_actual_peer_limit(self) -> None:
        class Miss:
            def get(self, identifier: str) -> None:
                return None

        server = self._server(
            PickupApp(
                Miss(), limiter=PerIPLimit(requests=1, period_seconds=20, max_peers=4)
            )
        )
        for i, expected in enumerate([404, 429, 429]):
            code, headers, body = _get(
                server,
                _BASE + "1" * 64,
                headers={
                    "X-Forwarded-For": f"192.0.2.{i}",
                    "Forwarded": f"for=192.0.2.{i}",
                },
            )
            self.assertEqual(
                (code, headers["Cache-Control"], body), (expected, "no-store", b"")
            )
            if code == 429:
                self.assertEqual(headers["Retry-After"], "20")

    def test_source_failures_do_not_leak(self) -> None:
        class Broken:
            def get(self, identifier: str) -> dict[str, str]:
                if identifier[0] == "1":
                    raise RuntimeError(_PRIVATE + identifier)
                if identifier[0] == "2":
                    return {
                        "version": "akashi-pickup/1",
                        "nonce": "aa" * 24,
                        "ciphertext": "bb" * 16,
                        "user": _PRIVATE,
                    }
                return {"version": "akashi-pickup/1", "nonce": ".", "ciphertext": _PRIVATE}

        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            server = self._server(
                PickupApp(
                    Broken(),
                    limiter=PerIPLimit(requests=8, period_seconds=1, max_peers=2),
                )
            )
            for c in "123":
                code, headers, body = _get(server, _BASE + c * 64)
                self.assertEqual(
                    (code, headers["Cache-Control"], body), (503, "no-store", b"")
                )
        self.assertEqual(capture.getvalue(), "")

    def test_bounded_rolling_limit_and_concurrent_admission(self) -> None:
        now = 0.0
        limit = PerIPLimit(requests=2, period_seconds=4, max_peers=2, clock=lambda: now)
        self.assertTrue(limit("192.0.2.1"))
        now = 1.0
        self.assertTrue(limit("192.0.2.1"))
        self.assertTrue(limit("192.0.2.2"))
        self.assertFalse(limit("192.0.2.3"))
        now = 3.999
        self.assertFalse(limit("192.0.2.1"))
        now = 4.0
        self.assertTrue(limit("192.0.2.1"))
        self.assertFalse(limit("192.0.2.3"))
        now = 5.0
        with ThreadPoolExecutor(max_workers=8) as executor:
            self.assertEqual(sum(executor.map(limit, ["192.0.2.3"] * 32)), 2)

    def test_limit_configuration_and_peer_aliases(self) -> None:
        for args in (
            (0, 1, 1),
            (1, 0, 1),
            (1, float("nan"), 4),
            (1, 2, 0),
            (True, 1, 1),
        ):
            with self.assertRaises(ValueError):
                PerIPLimit(requests=args[0], period_seconds=args[1], max_peers=args[2])

        class Miss:
            def get(self, identifier: str) -> None:
                return None

        app = PickupApp(
            Miss(), limiter=PerIPLimit(requests=1, period_seconds=60, max_peers=3)
        )
        statuses: list[str] = []
        for peer in (
            None,
            "not a peer",
            "::ffff:127.0.0.1",
            "127.0.0.1",
            "0:0:0:0:0:0:0:1",
            "::1",
        ):
            app(
                {
                    "PATH_INFO": _BASE + "a" * 64,
                    "REQUEST_METHOD": "GET",
                    "REMOTE_ADDR": peer,
                },
                lambda status, _headers: statuses.append(status),
            )
        self.assertEqual(
            [status.split()[0] for status in statuses],
            ["429", "429", "404", "429", "404", "429"],
        )


if __name__ == "__main__":
    unittest.main()
