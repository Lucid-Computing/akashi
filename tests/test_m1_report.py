"""A failed M1 gate replaces stale evidence and withholds private diagnostics."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.gate_m1 import gate


class GateReports(unittest.TestCase):
    def test_bad_local_asset_fails_closed_and_supersedes_old_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tokenizer.json").write_text("private-test-marker")
            output = root / "old.json"
            output.write_text('{"status":"passed"}')
            with patch.dict(os.environ, {"VIG_RENDER_ASSETS": str(root)}):
                self.assertFalse(gate(output))
            text = output.read_text()
            report = json.loads(text)
            self.assertEqual(
                (report["schema_version"], report["status"], report["failed_stage"]),
                (1, "failed", "renderer_assets"),
            )
            self.assertNotIn("private-test-marker", text)
            self.assertNotIn(temp, text)
            self.assertNotIn("mode_d", report)
