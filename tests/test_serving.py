"""Direct HTTP delivery, bounded FIFO and cancellation at the commit boundary."""

import base64
import io
import json
import os
import tempfile
import threading
import time
import unittest
from collections.abc import Mapping
from concurrent.futures import CancelledError
from datetime import datetime, timezone
from http.client import HTTPConnection
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock
from wsgiref.simple_server import WSGIRequestHandler, make_server

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from engine.mock import EngineResult, MockEngine
from escrow.store import EscrowStore
from gateway.commit_delivery import DeliveryCommitter
from gateway.discovery import ServiceConfig
from gateway.http import ServingApp
from gateway.policy import PolicyError
from gateway.renderer import ChatRenderer
from gateway.serving import AdmissionQueue, Engine, RequestControl, Serving
from log.receipt import leaf_hash, verify_promise
from log.store import MerkleLog
from tests.test_discovery import CONFIG, MODEL


class Quiet(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


class ServingTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes_raw()
        self.config = ServiceConfig(**{**CONFIG, "log_public_key": self.public.hex()})
        now = datetime.now(timezone.utc)
        self.store = EscrowStore(
            root / "escrow",
            wrapping_key=os.urandom(32),
            auditor_public_key=bytes(PrivateKey.generate().public_key),
            clock=lambda: now,
        )
        self.log = MerkleLog(
            root / "merkle",
            log_id=self.config.log_id,
            log_key_id=self.config.log_key_id,
            signing_key=self.private,
            leaf_hash=leaf_hash,
            clock=lambda: now,
        )
        self.append = Mock(side_effect=self.log.append)
        self.committer = DeliveryCommitter(
            self.config,
            endpoint_id="test-endpoint",
            sampling_mode="live",
            stage=self.store.stage,
            append=self.append,
            clock=lambda: now,
        )
        self.renderer = Mock(spec=ChatRenderer)
        self.serving = Serving(
            self.config,
            self.renderer,
            MockEngine(),
            self.committer,
            lambda token: token == "fixture",
        )
        self.app = ServingApp(self.serving, request_timeout=5, retry_after_seconds=2)
        self.body = {"model": MODEL, "prompt": [17, 4], "max_tokens": 2}

    def post(
        self,
        body: object = None,
        *,
        authorization: str = "Bearer fixture",
        control: RequestControl | None = None,
    ) -> tuple[int, dict[str, str], dict[str, Any]]:
        data = json.dumps(self.body if body is None else body).encode()
        start = Mock()
        response = b"".join(
            self.app(
                {
                    "PATH_INFO": "/v1/completions",
                    "REQUEST_METHOD": "POST",
                    "HTTP_AUTHORIZATION": authorization,
                    "CONTENT_LENGTH": str(len(data)),
                    "wsgi.input": io.BytesIO(data),
                    "vig.request_control": control,
                },
                start,
            )
        )
        status, headers = start.call_args.args
        return int(status[:3]), dict(headers), json.loads(response)

    def test_raw_http_header_promise_and_private_state_agree(self) -> None:
        status, headers, result = self.post()
        self.assertEqual(status, 200)
        verify = result["verification"]
        self.assertEqual(verify["prompt_token_ids"], [17, 4])
        self.assertEqual(verify["reply_token_ids"], [22, 23])
        self.assertIsNone(result["choices"][0]["text"])
        self.assertEqual(
            result["usage"],
            {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
        )
        encoded = headers["x-vig-receipt"]
        receipt = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        self.assertEqual(receipt, verify["receipt"])
        verify_promise(
            receipt,
            log_id=self.config.log_id,
            log_key_id=self.config.log_key_id,
            public_key=self.public,
        )
        self.assertEqual(self.store.status(receipt["leaf_hash"]), "pending")
        self.assertEqual(self.log.receipt(0)["leaf_hash"], receipt["leaf_hash"])
        self.assertNotIn("salt", self.log.receipt(0))

    @unittest.skipUnless(
        os.getenv("VIG_RENDER_ASSETS"), "requires pinned renderer assets"
    )
    def test_real_chat_http_with_pinned_renderer(self) -> None:
        assets = Path(os.environ["VIG_RENDER_ASSETS"])
        renderer = ChatRenderer(assets)
        self.serving.renderer = renderer
        with make_server(
            "127.0.0.1", 0, cast(Any, self.app), handler_class=Quiet
        ) as server:
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            try:
                messages = [{"role": "user", "content": "Hello!"}]
                connection.request(
                    "POST",
                    "/v1/chat/completions",
                    json.dumps({"model": MODEL, "messages": messages, "max_tokens": 1}),
                    {"Authorization": "Bearer fixture"},
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                result = json.loads(response.read())
                self.assertEqual(
                    tuple(result["verification"]["prompt_token_ids"]),
                    renderer.render(messages),
                )
                self.assertEqual(
                    result["choices"][0]["message"]["content"],
                    renderer.decode(result["verification"]["reply_token_ids"]),
                )
            finally:
                connection.close()
                thread.join(6)

    def test_engine_and_end_rule_errors_leave_no_receipt(self) -> None:
        for injection, status in (
            (MockEngine("unavailable"), 503),
            (MockEngine("integrity_error"), 502),
            (Mock(generate=Mock(return_value=EngineResult((4,), True))), 502),
            (Mock(generate=Mock(return_value=EngineResult((200008, 4), True))), 502),
            (Mock(generate=Mock(return_value=EngineResult((True, 4), True))), 502),
            (Mock(generate=Mock(return_value=EngineResult((3, 4), False))), 502),
        ):
            with self.subTest(injection=injection):
                self.serving.engine = cast(Engine, injection)
                actual, headers, reply = self.post()
                self.assertEqual(actual, status)
                self.assertNotIn("x-vig-receipt", headers)
                self.assertNotIn("verification", reply)
        self.append.assert_not_called()

    def test_cancel_after_durable_append_response_still_withholds_completion(
        self,
    ) -> None:
        control = RequestControl(self.serving.queue, 5)

        def append(preimage: Mapping[str, object]) -> Mapping[str, object]:
            reply = self.log.append(preimage)
            control.cancel()
            return reply

        self.append.side_effect = append
        status, headers, reply = self.post(control=control)
        self.assertNotEqual(status, 200)
        self.assertNotIn("x-vig-receipt", headers)
        self.assertNotIn("verification", reply)
        self.assertEqual(self.log.head()["tree_size"], 1)

    def test_actual_http_queue_error_advertises_retry_interval(self) -> None:
        controls = [RequestControl(self.serving.queue, 4) for _ in range(4)]
        threads = [
            threading.Thread(target=self.post, kwargs={"control": c}) for c in controls
        ]
        with self.serving.queue.slot(RequestControl(self.serving.queue, 4)):
            try:
                for thread in threads:
                    thread.start()
                until = time.monotonic() + 2
                while self.serving.queue.depth != 4 and time.monotonic() < until:
                    time.sleep(0.001)
                self.assertEqual(self.serving.queue.depth, 4)
                status, headers, body = self.post()
                self.assertEqual(
                    (status, body["error"]["code"], headers["Retry-After"]),
                    (429, "queue_full", "2"),
                )
                self.assertNotIn("x-vig-receipt", headers)
            finally:
                for control in controls:
                    control.cancel()
                for thread in threads:
                    thread.join(2)
        self.append.assert_not_called()
        self.assertEqual(self.post()[0], 200)

    def test_end_token_at_budget_is_stop(self) -> None:
        self.serving.engine = Mock(
            generate=Mock(return_value=EngineResult((200008,), True))
        )
        status, _, body = self.post({**self.body, "max_tokens": 1})
        self.assertEqual((status, body["choices"][0]["finish_reason"]), (200, "stop"))

    def test_append_error_and_wrong_promise_are_receipt_free(self) -> None:
        faults: tuple[OSError, dict[str, object]] = (OSError("private text"), {})
        for fault in faults:
            self.append.side_effect = fault if isinstance(fault, Exception) else None
            self.append.return_value = fault
            status, headers, result = self.post()
            self.assertEqual(status, 500)
            self.assertNotIn("x-vig-receipt", headers)
            self.assertNotIn("verification", result)
            self.assertNotIn("private text", str(result))

    def test_authentication_precedes_body_and_raw_pickup_fails_before_execution(
        self,
    ) -> None:
        stream = Mock()
        start = Mock()
        self.app(
            {
                "PATH_INFO": "/v1/completions",
                "REQUEST_METHOD": "POST",
                "CONTENT_LENGTH": "3",
                "wsgi.input": stream,
            },
            start,
        )
        self.assertTrue(start.call_args.args[0].startswith("401"))
        stream.read.assert_not_called()
        self.assertEqual(
            self.post({**self.body, "user": "vig-pickup/1:" + ("a0" * 32)})[0], 400
        )
        self.append.assert_not_called()


class QueueTests(unittest.TestCase):
    def test_fifo_limit_cancel_and_expiry(self) -> None:
        queue = AdmissionQueue()
        order: list[int] = []
        errors: list[int] = []

        def take(index: int, control: RequestControl) -> None:
            try:
                with queue.slot(control):
                    order.append(index)
            except CancelledError:
                errors.append(index)

        threads = []
        controls = [RequestControl(queue, 5) for _ in range(4)]
        with queue.slot(RequestControl(queue, 5)):
            for n in range(4):
                t = threading.Thread(target=take, args=(n, controls[n]))
                threads.append(t)
                t.start()
                until = time.monotonic() + 2
                while queue.depth != n + 1 and time.monotonic() < until:
                    time.sleep(0.001)
                self.assertEqual(queue.depth, n + 1)
            with (
                self.assertRaises(PolicyError) as ctx,
                queue.slot(RequestControl(queue, 1)),
            ):
                self.fail("saturated queue dispatched")
            self.assertEqual(ctx.exception.status, 429)
            controls[2].cancel()
            threads[2].join(2)
            with (
                self.assertRaises(CancelledError),
                queue.slot(RequestControl(queue, 0.01)),
            ):
                self.fail("expired request dispatched")
        for t in threads:
            t.join(2)
        self.assertEqual(order, [0, 1, 3])
        self.assertEqual(errors, [2])
        self.assertEqual(queue.depth, 0)
