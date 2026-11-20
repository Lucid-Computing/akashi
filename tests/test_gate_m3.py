"""Refresh failed milestone evidence through its normal entry point."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.gate_m1 import _write
from tools.gate_m3 import gate


class M3GateTests(unittest.TestCase):
    def test_failed_new_run_replaces_previous_pass_and_keeps_bounded_reports(
        self,
    ) -> None:
        def failed(path: Path, *, suite: str) -> bool:
            _write(path, {"status": "failed", "scope": suite})
            return False

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            _write(out / "m3.json", {"status": "passed", "private-marker": True})
            with patch("redteam.evidence_regressions.gate", side_effect=failed):
                self.assertFalse(gate(out))
            doc = json.loads((out / "m3.json").read_bytes())
            self.assertEqual(doc["status"], "failed")
            self.assertNotIn("private-marker", doc)
            self.assertEqual(
                set(doc["failed_suites"]), {"admission", "evidence", "model"}
            )
            for filename in doc["artifacts"]:
                self.assertEqual(
                    json.loads((out / filename).read_bytes())["status"], "failed"
                )
