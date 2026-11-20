"""Mode R HTTP forwarding and transport controls on loopback."""

import json
import threading
import unittest
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from unittest.mock import Mock

from gateway.discovery import DiscoveryApp, ServiceConfig
from gateway.http import ServingApp
from router.mock import MockRouter, Mode, _events, origin
from tests.m1_flow import _loopback
from tests.test_discovery import CONFIG, MODEL


@contextmanager
def serve(server: HTTPServer) -> Iterator[int]:
    with server:
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            thread.join()


def call(
    port: int, path: str, body: bytes | None, headers: dict[str, str] | None = None
) -> tuple[int, dict[str, str], bytes]:
    with closing(HTTPConnection("127.0.0.1", port, timeout=3)) as conn:
        conn.request("GET" if body is None else "POST", path, body, headers or {})
        with conn.getresponse() as response:
            return (
                response.status,
                {k.lower(): v for k, v in response.getheaders()},
                response.read(),
            )


def handler(
    callback: Callable[[bytes, str | None], tuple[int, str, bytes]],
) -> type[BaseHTTPRequestHandler]:
    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            status, media, data = callback(body, self.headers.get("Authorization"))
            self.send_response(status)
            self.send_header("x-vig-receipt", "synthetic")
            self.send_header("Retry-After", "2")
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: object) -> None:
            pass

    return Upstream


class MockRouterTests(unittest.TestCase):
    def test_feed_uses_descriptor_model_and_admission_budget(self) -> None:
        cap = 17
        app = DiscoveryApp(ServiceConfig(**(CONFIG | {"max_tokens_cap": cap})))
        start = Mock()
        data = json.loads(
            b"".join(
                app({"PATH_INFO": "/router/models", "REQUEST_METHOD": "GET"}, start)
            )
        )
        feed = data["models"][0]
        self.assertEqual(
            (
                feed["id"],
                feed["max_context_length"],
                feed["max_completion_tokens"],
                feed["max_length"],
            ),
            (MODEL, 1024, cap, cap),
        )
        self.assertEqual(feed["quantization"], "int4")
        self.assertEqual(
            feed["constraints"], {"temperature": [0], "top_p": [1], "n": [1]}
        )
        self.assertTrue(
            {"temperature", "max_tokens", "seed"}.issubset(feed["supported_parameters"])
        )
        self.assertNotIn("secret", str(data))

    def test_live_feed_advertises_stream_only_when_enabled(self) -> None:
        serving = Mock(config=ServiceConfig(**CONFIG))
        for heartbeat in (None, 0.1):
            app = ServingApp(
                serving,
                request_timeout=1,
                retry_after_seconds=1,
                stream_heartbeat_seconds=heartbeat,
            )
            with (
                _loopback(app) as upstream,
                serve(
                    MockRouter(f"http://127.0.0.1:{upstream}", 0, "opaque", 2)
                ) as router,
            ):
                status, _, body = call(router, "/router/models", None)
                self.assertEqual(status, 200)
                feed = json.loads(body)["models"][0]
                self.assertEqual(feed["id"], MODEL)
                self.assertEqual(
                    "stream" in feed["supported_parameters"], heartbeat is not None
                )

    def test_opaque_and_transparent_modes_forward_original_chat_octets(self) -> None:
        body = b'{ "messages": [{"role":"user","content":"test"}], "user":"fixture", "max_tokens":2 }'
        response = b'{"choices":[{"message":{"content":"text"}}],"verification":{"receipt":"synthetic"}}'
        capture = Mock(return_value=(200, "application/json", response))
        modes: tuple[Mode, ...] = ("opaque", "transparent")
        with serve(ThreadingHTTPServer(("127.0.0.1", 0), handler(capture))) as upstream:
            for mode in modes:
                with serve(
                    MockRouter(f"http://127.0.0.1:{upstream}", 0, mode, 3)
                ) as port:
                    status, headers, raw = call(
                        port,
                        "/v1/chat/completions",
                        body,
                        {"Authorization": "Bearer local-test"},
                    )
                capture.assert_called_with(body, "Bearer local-test")
                self.assertEqual(status, 200)
                self.assertEqual(
                    json.loads(raw)["choices"], json.loads(response)["choices"]
                )
                self.assertEqual("x-vig-receipt" in headers, mode == "transparent")
                self.assertEqual(
                    "verification" in json.loads(raw), mode == "transparent"
                )

    def test_opaque_sse_strips_only_evidence_and_keeps_final_boundary(self) -> None:
        data = (
            b': heartbeat\r\n\r\ndata: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
            b'event: message\ndata: {"choices":[],\ndata: "verification":{"status":"ok"}}\n\n'
            b"data: [DONE]\n\n"
        )
        fixture = Mock(return_value=(200, "text/event-stream", data))
        with serve(ThreadingHTTPServer(("127.0.0.1", 0), handler(fixture))) as upstream:
            for mode in ("transparent", "opaque"):
                proxy = MockRouter(f"http://127.0.0.1:{upstream}", 0, mode, 3)
                with serve(proxy) as port:
                    status, headers, result = call(
                        port, "/v1/chat/completions", b'{"stream":true}'
                    )
                self.assertEqual(
                    (status, headers["content-type"]), (200, "text/event-stream")
                )
                if mode == "transparent":
                    self.assertEqual(result, data)
                else:
                    self.assertIn(b": heartbeat", result)
                    self.assertIn(b'"content":"hello"', result)
                    self.assertNotIn(b"verification", result)
                    self.assertTrue(
                        result.endswith(b'data: {"choices":[]}\n\ndata: [DONE]\n\n')
                    )
        self.assertEqual(list(_events([b"data: [DONE]\n"], False)), [])

    def test_disallowed_method_routes_and_error_status(self) -> None:
        fixture = Mock(
            return_value=(429, "application/json", b'{"error":{"code":"queue_full"}}')
        )
        with (
            serve(ThreadingHTTPServer(("127.0.0.1", 0), handler(fixture))) as upstream,
            serve(MockRouter(f"http://127.0.0.1:{upstream}", 0, "opaque", 3)) as port,
        ):
            status, h, raw = call(port, "/v1/chat/completions", b"{}")
            self.assertEqual(
                (status, h["retry-after"], json.loads(raw)["error"]["code"]),
                (429, "2", "queue_full"),
            )
            self.assertEqual(
                call(port, "/v1/chat/completions?url=ignored", b"{}")[0], 404
            )
            self.assertEqual(
                call(port, "/v1/chat/completions", b"x" * (256 * 1024 + 1))[0], 413
            )
            fixture.assert_called_once()
        for bad in (
            "https://name:secret@example.com",
            "http://example.com",
            "http://127.0.0.1/another",
            "https://example.com?next=elsewhere",
        ):
            with self.assertRaises(ValueError):
                origin(bad)
