import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from operations.engine_logs import EngineLogs
from operations.telemetry import Event


class EngineLogRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "engine-events.sqlite3"
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.logs = EngineLogs(self.path, clock=lambda: self.now)

    def test_exact_deadline_without_cleanup_and_secure_restart_purge(self) -> None:
        self.logs.emit(Event("engine", "unwarranted", "forced_token"))
        self.now += timedelta(microseconds=1)
        self.logs.emit(Event("engine", "gate", "passed"))
        self.now += timedelta(days=7) - timedelta(microseconds=2)
        self.assertEqual(
            [r["outcome"] for r in self.logs.read()], ["forced_token", "passed"]
        )
        self.now += timedelta(microseconds=1)
        self.assertIn(b"forced_token", self.path.read_bytes())
        self.assertEqual([r["outcome"] for r in self.logs.read()], ["passed"])
        self.now -= timedelta(microseconds=1)
        self.assertEqual([r["outcome"] for r in self.logs.read()], ["passed"])
        self.assertNotIn(b"forced_token", self.path.read_bytes())
        self.now += timedelta(microseconds=2)
        restarted = EngineLogs(self.path, clock=lambda: self.now)
        self.assertEqual(restarted.purged_on_open, 1)
        self.assertEqual(restarted.sweep(), 0)
        self.assertEqual(self.logs.read(), [])
        for path in self.path.parent.iterdir():
            self.assertNotIn(b'"outcome":"passed"', path.read_bytes())

    def test_only_content_free_engine_events_and_stages_reach_disk(self) -> None:
        canary = "private-request-contents-765"
        with self.assertRaises(ValueError):
            self.logs.emit(cast(Event, canary))
        for event in (
            Event("gateway", "request", "served"),
            Event("engine", "gate", canary),
            Event("engine", "gate", "failed", reason=canary),
        ):
            with self.assertRaises(ValueError):
                self.logs.emit(event)
        with self.assertRaises(ValueError), self.logs.stage(canary):
            self.fail("invalid phase was admitted")
        with self.assertRaisesRegex(RuntimeError, canary), self.logs.stage("decode"):
            raise RuntimeError(canary)
        rows = self.logs.read()
        self.assertEqual([row["outcome"] for row in rows], ["started", "failure"])
        self.assertNotIn(canary, json.dumps(rows))
        self.assertNotIn(canary.encode(), self.path.read_bytes())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone(), ("delete",))

    def test_open_rejects_shared_directory_symlink_or_shared_database(self) -> None:
        parent = self.path.parent
        os.chmod(parent, 0o755)
        try:
            with self.assertRaises(PermissionError):
                EngineLogs(self.path)
        finally:
            os.chmod(parent, 0o700)
        alias = parent / "link"
        alias.symlink_to(self.path)
        with self.assertRaises(OSError):
            EngineLogs(alias)
        os.chmod(self.path, 0o640)
        with self.assertRaises(PermissionError):
            EngineLogs(self.path)
