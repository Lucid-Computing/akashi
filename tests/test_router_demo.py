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
from tests.router_demo import DemoError, main, run_demo
from tools.gate_m1 import FIXTURES, _assets


class RouterDemoOutputTests(unittest.TestCase):
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
    os.getenv("VIG_RENDER_ASSETS") or os.getenv("VIG_REQUIRE_ROUTER_ASSETS") == "1",
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
                "logged": 3,
                "mode": "R",
                "nonneutral_sampling_rejected": True,
                "opaque_pickup_verified": True,
                "pickup_store": "in-memory fixture",
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
