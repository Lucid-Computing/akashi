"""Exercise admission, terminal evidence and disconnects through the gateway entry point."""

import io
import json
import os
import tempfile
import threading
import unittest
from collections.abc import Iterable
from http.client import HTTPConnection
from pathlib import Path
from typing import Any
from unittest.mock import Mock

from engine.mock import EngineResult
from gateway.http import ServingApp
from gateway.renderer import ChatRenderer
from gateway.stream_reader import IncompleteStream, terminal_evidence
from gateway.streaming import StreamDelivery
from log.receipt import verify_promise
from tests import test_serving as fixture
from tests.m1_flow import _loopback
from tools.gate_m1 import FIXTURES, _assets


class StreamHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixture.ServingTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.app = ServingApp(
            self.fixture.serving,
            request_timeout=5,
            retry_after_seconds=2,
            stream_heartbeat_seconds=0.01,
        )
        self.body = {
            **self.fixture.body,
            "stream": True,
            "stream_options": {"include_usage": True},
        }

    def handle(
        self, data: object, *, authorization: str = "Bearer fixture"
    ) -> tuple[str, dict[str, str], Iterable[bytes]]:
        raw = json.dumps(data).encode()
        response = Mock()
        stream = self.app(
            {
                "PATH_INFO": "/v1/completions",
                "REQUEST_METHOD": "POST",
                "wsgi.input": io.BytesIO(raw),
                "CONTENT_LENGTH": str(len(raw)),
                "HTTP_AUTHORIZATION": authorization,
            },
            response,
        )
        return response.call_args.args[0], dict(response.call_args.args[1]), stream

    def test_real_http_verification_is_terminal_and_has_signed_promise(self) -> None:
        with _loopback(self.app) as port:
            conn = HTTPConnection("127.0.0.1", port, timeout=4)
            try:
                conn.request(
                    "POST",
                    "/v1/completions",
                    json.dumps(self.body),
                    {
                        "Authorization": "Bearer fixture",
                        "Content-Type": "application/json",
                    },
                )
                with conn.getresponse() as reply:
                    self.assertEqual(
                        (reply.status, reply.getheader("content-type")),
                        (200, "text/event-stream"),
                    )
                    self.assertIsNone(reply.getheader("x-vig-receipt"))
                    raw = reply.read()
            finally:
                conn.close()
        self.assertTrue(raw.startswith(b":"))
        frames = [
            line.removeprefix(b"data: ")
            for line in raw.splitlines()
            if line.startswith(b"data: ")
        ]
        self.assertEqual(frames[-1], b"[DONE]")
        chunks = [json.loads(frame) for frame in frames[:-1]]
        self.assertFalse(any("verification" in item for item in chunks[:-1]))
        self.assertIn("usage", chunks[-1])
        result = terminal_evidence(raw.splitlines(keepends=True))
        receipt = result["receipt"]
        verify_promise(
            receipt,
            log_id=self.fixture.config.log_id,
            log_key_id=self.fixture.config.log_key_id,
            public_key=self.fixture.public,
        )
        self.assertEqual(self.fixture.log.receipt(0)["leaf_hash"], receipt["leaf_hash"])

    @unittest.skipUnless(
        os.environ.get("VIG_RENDER_ASSETS")
        or os.environ.get("VIG_REQUIRE_STREAM_ASSETS"),
        "requires pinned renderer assets",
    )
    def test_real_pinned_decoder_buffers_split_utf8_in_chat_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = json.loads(
                (FIXTURES / "render-goldens/manifest.json").read_bytes()
            )
            renderer = ChatRenderer(_assets(Path(tmp), manifest))
        ids = (5796, 116, 136)  # The pinned tokenizer's three fragments of U+1FABF.
        self.assertEqual(renderer.decode(ids), "🪿")
        self.assertNotEqual("".join(renderer.decode((i,)) for i in ids), "🪿")
        self.fixture.serving.renderer = renderer
        self.fixture.serving.engine = Mock(
            generate=Mock(return_value=EngineResult(ids, True))
        )
        body = {
            "model": self.fixture.config.model,
            "messages": [{"role": "user", "content": "bird"}],
            "max_tokens": len(ids),
            "stream": True,
        }
        with _loopback(self.app) as port:
            conn = HTTPConnection("127.0.0.1", port, timeout=4)
            try:
                conn.request(
                    "POST",
                    "/v1/chat/completions",
                    json.dumps(body),
                    {"Authorization": "Bearer fixture"},
                )
                with conn.getresponse() as reply:
                    wire = reply.read()
            finally:
                conn.close()
        frames = [
            json.loads(line[6:])
            for line in wire.splitlines()
            if line.startswith(b"data: {")
        ]
        self.assertEqual(frames[0]["choices"][0]["delta"]["content"], "🪿")
        self.assertNotIn("verification", frames[0])
        self.assertEqual(
            terminal_evidence(wire.splitlines(keepends=True))["reply_token_ids"],
            list(ids),
        )

    def test_policy_errors_remain_http_errors_before_sse(self) -> None:
        for data, token, expected in (
            (self.body, "", 401),
            (self.body | {"top_p": 0.4}, "Bearer fixture", 400),
        ):
            status, headers, stream = self.handle(data, authorization=token)
            self.assertTrue(status.startswith(str(expected)))
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertNotIn(b"verification", b"".join(stream))
        self.assertEqual(self.fixture.log.head()["tree_size"], 0)

    def test_close_after_first_heartbeat_cannot_publish_a_receipt(self) -> None:
        entered, finish, returned = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        generate = self.fixture.serving.engine.generate

        def slow(prompt: tuple[int, ...], budget: int) -> Any:
            entered.set()
            try:
                self.assertTrue(finish.wait(timeout=3))
                return generate(prompt, budget)
            finally:
                returned.set()

        self.fixture.serving.engine = Mock(generate=slow)
        status, _, stream = self.handle(self.body)
        self.assertEqual(status, "200 OK")
        iterator = iter(stream)
        self.assertTrue(next(iterator).startswith(b":"))
        self.assertTrue(entered.wait(timeout=1))
        assert isinstance(stream, StreamDelivery)
        stream.close()
        finish.set()
        self.assertTrue(returned.wait(timeout=1))
        self.assertEqual(list(iterator), [])
        # A normal next request can acquire the slot only after the cancelled worker exits.
        _, _, next_result = self.handle(self.body | {"stream": False})
        self.assertIn("verification", json.loads(b"".join(next_result)))
        self.assertEqual(self.fixture.log.head()["tree_size"], 1)

    def test_consumer_rejects_partial_unwarranted_and_duplicate_termination(
        self,
    ) -> None:
        evidence = b'data: {"verification":{"version":"vig/1","receipt":{}}}\n\n'
        done = b"data: [DONE]\n\n"
        for content in (
            done,
            evidence,
            evidence + done[:-1],
            done + evidence,
            evidence + evidence + done,
            evidence + done + done,
            b'data: {"verification":{"status":"unwarranted"}}\n\n' + done,
            b'data: {"verification":42}\n\n' + done,
            b"data: {\n\n",
        ):
            with self.subTest(content=content), self.assertRaises(IncompleteStream):
                terminal_evidence(content.splitlines(keepends=True))
