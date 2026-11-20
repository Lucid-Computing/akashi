import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from operations.retention import main
from pickup.store import PickupStore


class RetentionCommandTests(unittest.TestCase):
    def test_existing_pickup_worker_reports_only_counts_and_restarts(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "role.sqlite"
            past = datetime(2000, 1, 1, tzinfo=timezone.utc)
            store = PickupStore(path, clock=lambda: past)
            store.reserve("ab" * 32, "cd" * 32, past + timedelta(days=7))
            for expected in (1, 0):
                out = io.StringIO()
                with (
                    patch("sys.argv", ["retention", "pickup", str(path)]),
                    redirect_stdout(out),
                ):
                    self.assertEqual(main(), 0)
                self.assertEqual(
                    json.loads(out.getvalue()), {"role": "pickup", "expired": expected}
                )

    def test_error_redacts_store_path_and_does_not_create_it(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private-name"
            err = io.StringIO()
            with (
                patch("sys.argv", ["retention", "auditor", str(path)]),
                redirect_stderr(err),
            ):
                self.assertEqual(main(), 1)
            self.assertNotIn(str(path), err.getvalue())
            self.assertFalse(path.exists())
