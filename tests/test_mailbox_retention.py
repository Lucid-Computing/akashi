"""A selected carrier has one durable, retryable destination under RFC-0005."""

import sqlite3
import unittest
from contextlib import closing
from dataclasses import replace
from unittest.mock import Mock

from tests import test_escrow_crypto


class MailboxRetentionTests(unittest.TestCase):
    def test_crash_between_commits_denies_reads_and_confirms_exact_handoff(
        self,
    ) -> None:
        fixture = test_escrow_crypto.AuditorInboxTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        inbox, binding = fixture.inbox(), fixture.binding
        leaf = inbox.accept(fixture.transfer)
        other = fixture.path.parent / "challenge.db"

        def acquire(payload: bytes, digest: bytes) -> str:
            self.assertEqual(payload, fixture.payload)
            with closing(sqlite3.connect(other)) as receiver, receiver:
                receiver.execute(
                    "CREATE TABLE IF NOT EXISTS received(leaf TEXT PRIMARY KEY)"
                )
                receiver.execute("INSERT OR IGNORE INTO received VALUES(?)", (leaf,))
            return "stable-job-id"

        def interrupted(payload: bytes, digest: bytes) -> str:
            acquire(payload, digest)
            raise OSError("lost destination acknowledgment")

        with self.assertRaises(OSError):
            inbox.handoff(binding, interrupted)
        self.assertIsNone(inbox.read(binding))
        self.assertFalse(inbox.purge(leaf))
        recovered = fixture.inbox()
        self.assertEqual(recovered.handoff(binding, acquire), "stable-job-id")
        self.assertEqual(recovered.accept(fixture.transfer), leaf)
        unused = Mock()
        self.assertEqual(fixture.inbox().handoff(binding, unused), "stable-job-id")
        unused.assert_not_called()
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            recovered.handoff(replace(binding, beacon_round=49), unused)
        with closing(sqlite3.connect(other)) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM received").fetchone(), (1,)
            )
        for private in (
            fixture.payload,
            fixture.transfer.ciphertext,
            fixture.transfer.key_slot,
        ):
            self.assertNotIn(private, fixture.path.read_bytes())
