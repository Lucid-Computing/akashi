import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from auditor.retention import expire_private
from operations.retention import main
from pickup.store import PickupStore


class RetentionCommandTests(unittest.TestCase):
    def test_existing_proof_store_uses_expiry_index_and_erases_at_deadline(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as folder,
            closing(sqlite3.connect(Path(folder) / "auditor.sqlite")) as db,
        ):
            db.executescript("""
                PRAGMA secure_delete=ON;
                CREATE TABLE audit_jobs(job_id TEXT PRIMARY KEY, completed_us INTEGER);
                CREATE TABLE challenge_work(job_id TEXT, material BLOB, statement_tag BLOB);
                CREATE TABLE challenge_handles(job_id TEXT, capability_hash BLOB, holder_tag BLOB);
                CREATE TABLE audit_evidence(job_id TEXT PRIMARY KEY, proof_digest TEXT,
                    statement_digest TEXT, ciphertext BLOB, expires_us INTEGER NOT NULL);
                INSERT INTO audit_evidence VALUES
                    ('due', 'one', 'a', X'01', 100), ('later', 'two', 'b', X'02', 101),
                    ('retired', 'three', 'c', NULL, 90);
            """)
            statements: list[str] = []
            db.set_trace_callback(statements.append)
            self.assertEqual(expire_private(db, 99), 0)
            update = next(
                s for s in statements if s.startswith("UPDATE audit_evidence")
            )
            plan = [r[3] for r in db.execute("EXPLAIN QUERY PLAN " + update)]
            self.assertTrue(
                any(
                    "SEARCH audit_evidence USING INDEX evidence_live_expiry" in row
                    for row in plan
                ),
                plan,
            )
            self.assertEqual(expire_private(db, 100), 1)
            self.assertEqual(expire_private(db, 100), 0)
            self.assertEqual(
                db.execute(
                    "SELECT job_id, proof_digest, ciphertext FROM audit_evidence ORDER BY job_id"
                ).fetchall(),
                [
                    ("due", "one", None),
                    ("later", "two", b"\x02"),
                    ("retired", "three", None),
                ],
            )

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
