"""The original selected transcript stays in role-private CH custody through its deadline."""

import sqlite3
import unittest
from contextlib import closing
from datetime import timedelta
from unittest.mock import Mock, patch

from escrow.mailbox import AuditorInbox, reconcile_handoffs
from escrow.store import Binding, EscrowStore
from tests import test_audit_jobs


class SelectedRetentionTests(unittest.TestCase):
    def test_read_bound_to_leaf_and_verdict_deadline_without_sweep(self) -> None:
        f = test_audit_jobs.AuditJobTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        originals = [
            b'{"messages":["retention-one"],"salt":"one"}',
            b'{"messages":["retention-two"],"salt":"two"}',
        ]
        leaves = ["12" * 32, "13" * 32]

        def enqueue(i: int, data: bytes) -> str:
            return f.jobs.sample_unavailable(
                leaf_hash=leaves[i],
                transcript="ab" * 32,
                served_at=f.start,
                reason="invalid_material",
                original_transcript=data,
            )

        self.assertEqual(enqueue(0, originals[0]), enqueue(0, originals[0]))
        enqueue(1, originals[1])
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            enqueue(0, originals[1])
        self.assertEqual(f.restart().selected_transcript(leaves[0]), originals[0])
        with closing(sqlite3.connect(f.path)) as db, db:
            rows = dict(db.execute("SELECT leaf,material FROM selected_transcripts"))
            self.assertNotEqual(rows[leaves[0]], rows[leaves[1]])
            db.execute(
                "UPDATE selected_transcripts SET material=? WHERE leaf=?",
                (rows[leaves[0]], leaves[1]),
            )
        with self.assertRaisesRegex(ValueError, "different leaf"):
            f.jobs.selected_transcript(leaves[1])
        for marker in originals:
            self.assertNotIn(marker, f.path.read_bytes())
        f.now += timedelta(days=30) - timedelta(microseconds=1)
        self.assertEqual(f.jobs.selected_transcript(leaves[0]), originals[0])
        deadline = f.now + timedelta(microseconds=1)
        with patch.object(f.jobs, "_clock", side_effect=[f.now, deadline]):
            self.assertIsNone(f.jobs.selected_transcript(leaves[0]))
        f.now = deadline
        self.assertIsNone(f.restart().selected_transcript(leaves[0]))
        enqueue(0, originals[0])
        self.assertIsNone(f.jobs.selected_transcript(leaves[0]))
        self.assertNotIn(rows[leaves[0]], f.path.read_bytes())

    def test_old_completed_obligation_cannot_restore_an_expired_carrier(self) -> None:
        f = test_audit_jobs.AuditJobTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        leaf = "41" * 32
        old = f.jobs.sample_unavailable(
            leaf_hash=leaf,
            transcript="17" * 32,
            served_at=f.start,
            reason="missing_handoff",
        )
        self.assertFalse(f.jobs.has_selected_custody(leaf, old))
        f.now += timedelta(days=31)
        recovered = f.jobs.sample_unavailable(
            leaf_hash=leaf,
            transcript="17" * 32,
            served_at=f.start,
            reason="missing_handoff",
            original_transcript=b"historic carrier after expiry",
        )
        self.assertEqual(old, recovered)
        self.assertTrue(f.jobs.has_selected_custody(leaf, old))
        self.assertIsNone(f.restart().selected_transcript(leaf))

    def test_keyless_sweep_matches_ch_digest_even_after_ch_expiry(self) -> None:
        for shared in (False, True):
            with self.subTest(shared_database=shared):
                self.check_keyless_sweep(shared)

    def check_keyless_sweep(self, shared: bool) -> None:
        f = test_audit_jobs.AuditJobTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        path = f.path if shared else f.root / "inbox.db"
        inbox = AuditorInbox(
            path, auditor_private_key=bytes(f.key), clock=lambda: f.now
        )
        provider = EscrowStore(
            f.root / "escrow.db",
            wrapping_key=b"w" * 32,
            auditor_public_key=bytes(f.key.public_key),
            clock=lambda: f.now,
        )
        binding = Binding("13" * 32, "ab" * 32, "2026-11-20T00:00:00.000Z", 42, "soak")
        provider.stage(binding, b"complete private carrier")
        provider.resolve(binding, selected=True)
        transfer = provider.transfer(binding.leaf_hash)
        assert transfer is not None
        leaf = inbox.accept(transfer)
        hashes: list[bytes] = []

        def lost(data: bytes, digest: bytes) -> str:
            hashes.append(digest)
            f.jobs.sample_unavailable(
                leaf_hash=leaf,
                transcript=binding.transcript_commitment,
                served_at=f.start,
                reason="invalid_material",
                original_transcript=data,
                envelope_digest=digest,
            )
            raise OSError("lost acknowledgment")

        with self.assertRaises(OSError):
            inbox.handoff(binding, lost)
        self.assertIsNone(inbox.read(leaf))
        f.now += timedelta(days=30)
        self.assertIsNone(f.jobs.selected_transcript(leaf))
        with closing(sqlite3.connect(f.path)) as db, db:
            db.execute(
                "UPDATE selected_transcripts SET envelope_digest=?",
                (bytes(32),),
            )
        self.assertEqual(reconcile_handoffs(f.path, path), 0)
        with closing(sqlite3.connect(f.path)) as db, db:
            db.execute(
                "UPDATE selected_transcripts SET envelope_digest=?",
                (hashes[0],),
            )
        self.assertEqual(reconcile_handoffs(f.path, path), 1)
        self.assertEqual(reconcile_handoffs(f.path, path), 0)
        callback = Mock()
        job = inbox.handoff(binding, callback)
        assert job is not None
        self.assertTrue(f.jobs.has_selected_custody(leaf, job))
        callback.assert_not_called()
        self.assertEqual(inbox.accept(transfer), leaf)
        self.assertNotIn(transfer.ciphertext, path.read_bytes())
        self.assertNotIn(transfer.key_slot, path.read_bytes())
