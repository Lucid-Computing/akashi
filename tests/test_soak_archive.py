"""Resume a stopped archive using fixed signed records and read-only service calls."""

from __future__ import annotations

import copy
import errno
import http.client
import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any
from unittest.mock import patch

from log.receipt import leaf_hash
from log.store import MerkleLog
from soak import runner
from soak.deployment import _archive_recoverable
from soak.ledger import Journal
from soak.settings import digest
from tests import test_soak_evidence as signed_fixture
from tests.test_log_store import KEY, KEY_ID, LOG_ID
from tools.gate_m1 import _write

REAL_GET = runner._get


class ArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.journal = Journal(self.root / "journal.db")
        self.attempts, self.evidence = signed_fixture.SoakEvidenceTests().signed(
            self.root
        )
        desc = self.root / "descriptor.json"
        pub = KEY.public_key().public_bytes_raw().hex()
        _write(
            desc,
            {
                "log": {"log_id": LOG_ID, "log_key_id": KEY_ID, "log_public_key": pub},
                "auditor_public_key": pub,
                "auditor_key_id": "fixture",
            },
        )
        self.config = {
            "archive_drain_seconds": 300,
            "state": str(self.root),
            "descriptor": str(desc),
            "response_cap": 30000,
            "network_timeout": 1,
            "poll_seconds": 0.001,
            "log_origin": "log",
            "audit_origin": "audit",
            "audit_socket": "sample",
        }
        binding = {
            "archive_drain_seconds": 300,
            "descriptor_sha256": digest(desc),
            "fixture_sha256": digest(runner.CORPUS),
        }
        self.end = time.monotonic_ns()
        with closing(sqlite3.connect(self.journal.path)) as db, db:
            db.execute(
                "INSERT INTO run VALUES(1,?,'test-boot',0,0,?,0)",
                (json.dumps(binding), self.end),
            )
            db.executemany(
                "INSERT INTO attempts VALUES(?,?,0,1,?)",
                [(seq, shape, json.dumps(hold)) for seq, shape, hold in self.attempts],
            )
        inherited = Path.read_text

        def text(path: Path, *args: Any, **kwargs: Any) -> str:
            if path == Path("/proc/sys/kernel/random/boot_id"):
                return "test-boot"
            return inherited(path, *args, **kwargs)

        for support in (
            patch.object(Path, "read_text", text),
            patch.object(runner, "_get", side_effect=self.get),
            patch.object(runner, "quicknet", side_effect=self.beacon),
        ):
            support.start()
            self.addCleanup(support.stop)
        self.calls: list[str] = []
        self.faults: dict[str, list[BaseException]] = {}

    def route(self, path: str) -> None:
        self.calls.append(path)
        if self.faults.get(path):
            raise self.faults[path].pop(0)

    def beacon(self, path: str, **kw: Any) -> Any:
        self.route(path)
        return (
            self.evidence["chain"]
            if path == "info"
            else self.evidence["leaves"][0]["beacon"]
        )

    def get(self, origin: str, path: str, **kw: Any) -> Any:
        self.route(path)
        if path == "/log/v1/sth":
            return self.evidence["head"]
        if path.startswith("/log/v1/receipts/"):
            return self.evidence["leaves"][int(path.split("/")[-1])]["leaf"]
        if path.startswith("/log/v1/proof/"):
            i = int(path.split("/")[-1].split("?")[0])
            return {
                "leaf_index": i,
                "tree_size": 4,
                "audit_path": self.evidence["leaves"][i]["audit_path"],
            }
        if path.startswith("/audit/v1/selections"):
            i = int(path.split("=")[-1])
            return {
                "log_id": LOG_ID,
                "indexed_size": 4,
                "epochs": [
                    {"first_leaf_index": 0, "sampling_mode": "soak", "divisor": 1}
                ],
                "selections": [r["selection"] for r in self.evidence["leaves"][i:]],
            }
        return next(
            r["sample_verdict"]
            for r in self.evidence["leaves"]
            if path.endswith(r["leaf"]["leaf_hash"])
        )

    def test_real_signed_rows_resume_without_requests_or_clock_updates(self) -> None:
        self.assertTrue(_archive_recoverable(self.journal.path, 300))
        self.faults["info"] = [ConnectionError()]
        self.faults["/log/v1/receipts/2"] = [KeyboardInterrupt()]
        with self.assertRaises(KeyboardInterrupt):
            runner.collect(self.config)
        with closing(sqlite3.connect(self.journal.path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM archive_leaves").fetchone(), (2,)
            )
            (head,) = db.execute("SELECT head FROM archive_pin").fetchone()
            self.assertEqual(json.loads(head), self.evidence["head"])
        self.assertFalse((self.root / "archive.json").exists())
        self.calls.clear()
        self.faults["/log/v1/receipts/2"] = [http.client.IncompleteRead(b"")]
        with (
            patch.object(Journal, "reserve", side_effect=AssertionError),
            patch.object(Journal, "finish", side_effect=AssertionError),
        ):
            runner.collect(self.config, archive_only=True)
        self.assertNotIn("info", self.calls)
        self.assertNotIn("/log/v1/receipts/0", self.calls)
        self.assertEqual(self.calls.count("/log/v1/receipts/2"), 2)
        self.assertEqual(
            json.loads((self.root / "archive.json").read_bytes()), self.evidence
        )
        with closing(sqlite3.connect(self.journal.path)) as db:
            self.assertEqual(
                db.execute("SELECT end_ns FROM run").fetchone(), (self.end,)
            )
        self.calls.clear()
        runner.collect(self.config, archive_only=True)
        self.assertEqual(self.calls, [])

    def test_invalid_signature_fails_before_next_leaf_without_retry(self) -> None:
        r = self.evidence["leaves"][1]
        r["sample_verdict"] = {**r["sample_verdict"], "signature": "00" * 64}
        with self.assertRaises(ValueError):
            runner.archive(self.config, self.journal)
        path = "/internal/sampled/" + r["leaf"]["leaf_hash"]
        self.assertEqual(self.calls.count(path), 1)
        self.assertNotIn("/log/v1/receipts/2", self.calls)
        self.assertFalse((self.root / "archive.json").exists())

    def test_invalid_sth_or_late_tree_cannot_be_published(self) -> None:
        self.faults["info"] = [KeyboardInterrupt()]
        with self.assertRaises(KeyboardInterrupt):
            runner.archive(self.config, self.journal)
        original = copy.deepcopy(self.evidence["head"])
        self.evidence["head"]["signature"] = "00" * 64
        with self.assertRaises(ValueError):
            runner.archive(self.config, self.journal)
        self.evidence["head"] = MerkleLog(
            self.root / "other.db",
            log_id=LOG_ID,
            log_key_id=KEY_ID,
            signing_key=KEY,
            leaf_hash=leaf_hash,
        ).head()
        with self.assertRaisesRegex(ValueError, "tree changed"):
            runner.archive(self.config, self.journal)
        self.assertFalse((self.root / "archive.json").exists())
        self.evidence["head"] = original
        runner.archive(self.config, self.journal)
        self.assertEqual(
            json.loads((self.root / "archive.json").read_bytes())["head"], original
        )

    def test_unfinished_or_expired_drain_never_resends_or_restarts_deadline(
        self,
    ) -> None:
        with closing(sqlite3.connect(self.journal.path)) as db, db:
            db.execute("UPDATE run SET end_ns=NULL")
        self.assertFalse(_archive_recoverable(self.journal.path, 300))
        with self.assertRaisesRegex(ValueError, "completed traffic"):
            runner.collect(self.config, archive_only=True)
        with closing(sqlite3.connect(self.journal.path)) as db, db:
            db.execute("UPDATE run SET end_ns=?", (self.end - 301 * 10**9,))
        self.assertFalse(_archive_recoverable(self.journal.path, 300))
        with self.assertRaises(runner.ArchiveExpired):
            runner.collect(self.config)
        with self.assertRaisesRegex(ValueError, "binding changed"):
            runner.collect(
                {**self.config, "archive_drain_seconds": 9999}, archive_only=True
            )
        self.assertFalse(self.calls)

    def test_transient_http_only_and_absolute_retry_bound(self) -> None:
        for code, exc in [
            (202, ConnectionError),
            (429, ConnectionError),
            (503, ConnectionError),
            (404, ValueError),
            (400, ValueError),
        ]:
            with (
                self.subTest(code=code),
                patch.object(runner, "response", return_value=(code, {})),
                self.assertRaises(exc),
            ):
                REAL_GET("local", "/test", timeout=1, cap=1)
        self.faults["info"] = [PermissionError(errno.EACCES, "denied")]
        with self.assertRaises(PermissionError):
            runner.archive(self.config, self.journal)
        self.assertEqual(self.calls.count("info"), 1)
        with self.assertRaises(runner.ArchiveExpired):
            runner._retry(lambda _: {}, time.monotonic() - 1, self.config)


if __name__ == "__main__":
    unittest.main()
