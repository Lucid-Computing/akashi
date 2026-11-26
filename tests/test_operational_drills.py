"""Bound public drill output and replace a previous pass if the rule evaluator fails."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.operational_drills import _series, gate


class OperationalDrillTests(unittest.TestCase):
    def test_rejected_unbounded_sample_and_stale_success(self) -> None:
        bad = {
            "engine": ['akashi_secret{service="engine",reason="sensitive/id"} 1', "", ""],
            "sampler": ["", "", ""],
            "auditor": ["", "", ""],
        }
        with self.assertRaises(ValueError):
            _series(bad)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.json"
            path.write_text('{"status":"passed"}')
            with patch(
                "tools.operational_drills._promtool",
                side_effect=OSError("private-marker"),
            ):
                self.assertFalse(gate(path))
            report = json.loads(path.read_bytes())
            self.assertEqual(
                report,
                {
                    "schema_version": 1,
                    "status": "incomplete",
                    "failed_stage": "alert_rules",
                    "reason": "OSError",
                },
            )
            self.assertNotIn("private-marker", path.read_text())
