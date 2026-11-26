"""Holder-side checks against the standalone loopback Mode R router."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from log.store import MerkleLog
from pickup.crypto import open as open_pickup
from tests.router_demo import DemoError, _stream, main, run_demo
from tools.gate_m1 import FIXTURES, _assets


class RouterDemoOutputTests(unittest.TestCase):
    def test_opaque_holder_requires_finishing_event_and_done(self) -> None:
        delta = b'data: {"choices":[{"finish_reason":null,"delta":{"content":"fixture"}}]}\n\n'
        finish = b'data: {"choices":[{"finish_reason":"stop","delta":{}}]}\n\n'
        for tail in (finish, b"data: {}\n\ndata: [DONE]\n\n"):
            response = (
                200,
                {"content-type": "text/event-stream"},
                b": keepalive\n\n" + delta + tail,
            )
            with (
                patch("tests.router_demo.call", return_value=response),
                self.assertRaises(DemoError),
            ):
                _stream(0, {"user": "fixture-holder"}, transparent=False)

    def test_failure_report_is_redacted(self) -> None:
        output = io.StringIO()
        with (
            patch(
                "tests.router_demo._assets", side_effect=OSError("private-holder-value")
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(main(), 1)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"schema_version": 1, "mode": "R", "status": "failed"},
        )


@unittest.skipUnless(
    os.getenv("AKASHI_RENDER_ASSETS") or os.getenv("AKASHI_REQUIRE_ROUTER_ASSETS") == "1",
    "requires pinned renderer assets",
)
class RouterHolderTests(unittest.TestCase):
    assets: Path

    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        manifest = json.loads((FIXTURES / "render-goldens/manifest.json").read_bytes())
        cls.assets = _assets(Path(temporary.name), manifest)

    def test_all_four_router_behaviors_over_loopback(self) -> None:
        self.assertEqual(
            run_demo(self.assets),
            {
                "schema_version": 1,
                "status": "passed",
                "engine": "mock",
                "logged": 6,
                "mode": "R",
                "nonneutral_sampling_rejected": True,
                "opaque_pickup_verified": True,
                "pickup_store": "sqlite",
                "direct_receipt_verified": True,
                "transparent_stream_verified": True,
                "opaque_stream_pickup_verified": True,
                "rewritten_messages_unrecoverable": True,
                "transparent_receipt_verified": True,
                "wrong_secret_refused": True,
            },
        )

    def test_holder_recomputes_salted_commitment_after_open(self) -> None:
        def altered(*args: Any, **kwargs: Any) -> dict[str, Any]:
            opened: dict[str, Any] = open_pickup(*args, **kwargs)
            receipt = opened["receipt"]
            receipt["salt"] = "00" * 32 if receipt["salt"] != "00" * 32 else "11" * 32
            return opened

        with (
            patch("tests.router_demo.open_pickup", altered),
            self.assertRaises(DemoError),
        ):
            run_demo(self.assets)

    def test_holder_refuses_an_invalid_log_inclusion_proof(self) -> None:
        with (
            patch.object(MerkleLog, "path", return_value=(bytes(32),)),
            self.assertRaises(ValueError),
        ):
            run_demo(self.assets)
