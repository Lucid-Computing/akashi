"""Private spool retirement, disk cleanup and crash/restart boundaries."""

import fcntl
import hmac
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prover.request import build_statement
from prover.submission import COMMITMENT, RetiredSubmission, SpoolError, SubmissionStore
from prover.worker import CandidateProof, ProofWorker, Unavailable


class SpoolRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.state, self.spool = self.root / "state", self.root / "spool"
        self.spool.mkdir(mode=0o700)
        (self.spool / "mark.txt").write_text(
            f"cp-folder 1\nkind spool\ncommitment {COMMITMENT}\n"
        )
        self.now, self.deadline = 10, 20
        self.store = self.reopen()
        self.worker = ProofWorker(
            self.store, max_proof_bytes=100_000, now_ns=lambda: self.now
        )
        self.statement = build_statement([4, 88, 13], [42, 92])
        self.item = self.store.submit(
            "first", self.statement, deadline_ns=self.deadline
        )
        self.name = self.item.request_id
        self.queued = self.spool / "in" / (self.name + ".req")
        self.out = self.spool / "out"
        self.out.mkdir(mode=0o700)
        self.proof = b"private-retention-test-" * 3400
        fields = (
            bytes.fromhex(self.name)
            + struct.pack("<QQ", 4, len(self.proof))
            + bytes(4)
            + self.proof
        )
        for suffix, data in (
            ("proof", self.proof),
            ("tag", hmac.digest(self.item.tag_key, fields, "sha256")),
            ("y", bytes(4)),
        ):
            self.write(self.out / f"{self.name}.{suffix}", data)
        self.assertEqual(
            self.worker.poll("first"),
            CandidateProof(self.statement, bytes(4), self.proof),
        )

    def reopen(self) -> SubmissionStore:
        return SubmissionStore(self.state, self.spool, clock_ns=lambda: self.now)

    @staticmethod
    def write(path: Path, data: bytes) -> None:
        path.write_bytes(data)
        path.chmod(0o600)
        os.utime(path, ns=(12345, 12345))

    def test_deadline_denies_every_read_before_sweep_and_survives_clock_rollback(
        self,
    ) -> None:
        self.now = self.deadline
        self.assertEqual(self.worker.poll("first"), Unavailable("deadline"))
        self.assertTrue(self.queued.exists())
        self.assertEqual(self.store.pending_cleanup(), 1)
        self.now -= 1
        restarted = self.reopen()
        worker = ProofWorker(
            restarted, max_proof_bytes=100_000, now_ns=lambda: self.now
        )
        self.assertEqual(worker.wait("first", poll_seconds=1), Unavailable("deadline"))
        with (
            patch(
                "prover.request.os.urandom",
                side_effect=AssertionError("unexpected submission"),
            ),
            self.assertRaises(RetiredSubmission),
        ):
            restarted.submit(
                "first", build_statement([1], [2]), deadline_ns=self.deadline + 1
            )
        with self.assertRaises(RetiredSubmission):
            restarted.get("first")
        with self.assertRaises(RetiredSubmission):
            restarted.resume("first")
        self.assertEqual(restarted.sweep(), 0)
        self.assertEqual(restarted.pending_cleanup(), 0)
        self.assertFalse(self.queued.exists())
        self.assertFalse(any(self.out.iterdir()))
        database = (self.state / "submissions.sqlite3").read_bytes()
        for secret in (self.proof[:90], self.statement[:20], self.item.tag_key):
            self.assertNotIn(secret, database)
        self.assertFalse(list(self.state.glob("submissions.sqlite3-*")))

    def test_existing_submission_and_snapshot_migrate_without_extending_deadline(
        self,
    ) -> None:
        # The #23 ledger used these same jobs/results tables, without tombstones.
        with self.store.transaction() as db:
            db.execute("DROP TABLE retired")
        self.now = self.deadline - 1
        old = self.reopen()
        ticks = iter((self.now, self.deadline))
        worker = ProofWorker(old, max_proof_bytes=100_000, now_ns=lambda: next(ticks))
        self.assertEqual(worker.poll("first"), Unavailable("deadline"))
        self.assertEqual(old.pending_cleanup(), 1)
        self.assertEqual(old.sweep(), 0)
        self.assertFalse(self.queued.exists())
        with old.transaction() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM results").fetchone()[0], 0
            )

    def test_durable_handoff_wipes_all_named_copies_and_preserves_other_job(
        self,
    ) -> None:
        other = self.store.submit(
            "other", build_statement([7], [8]), deadline_ns=self.deadline + 1
        )
        other_queue = self.queued.with_name(other.request_id + ".req")
        other_proof = self.out / (other.request_id + ".proof")
        self.write(other_proof, b"untouched")
        staged = self.out / ".tmp" / self.name
        staged.parent.mkdir(mode=0o700)
        staged.mkdir(mode=0o700)
        self.write(staged / "proof", self.proof)
        work = self.spool / "work"
        work.mkdir(mode=0o700)
        self.queued.rename(work / self.queued.name)
        self.write(self.state / (self.name + ".pending"), self.statement)
        with (self.out / (self.name + ".proof")).open("rb") as already_open:
            self.assertTrue(self.store.handoff("first"))
            self.assertEqual(already_open.read(), bytes(len(self.proof)))
        self.assertFalse(self.reopen().handoff("first"))
        self.assertEqual(self.worker.poll("first"), Unavailable("handed_off"))
        self.assertEqual(self.store.pending_cleanup(), 0)
        self.assertEqual(list(work.iterdir()), [])
        self.assertFalse(staged.exists())
        self.assertFalse((self.state / (self.name + ".pending")).exists())
        self.assertEqual(other_queue.read_bytes()[:-32], other.statement)
        self.assertEqual(other_proof.read_bytes(), b"untouched")

    def test_process_loss_after_logical_handoff_retries_cleanup_from_tombstone(
        self,
    ) -> None:
        with (
            patch("prover.submission._clean_spool", side_effect=InterruptedError),
            self.assertRaises(InterruptedError),
        ):
            self.store.handoff("first")
        fresh = self.reopen()
        self.assertTrue(self.queued.exists())
        self.assertEqual(fresh.pending_cleanup(), 1)
        self.assertEqual(self.worker.poll("first"), Unavailable("handed_off"))
        self.assertFalse(fresh.handoff("first"))
        self.assertEqual(fresh.pending_cleanup(), 0)
        self.assertFalse(self.queued.exists())

    def test_upstream_live_work_stays_owned_until_release_and_late_response_is_purged(
        self,
    ) -> None:
        work = self.spool / "work"
        work.mkdir(mode=0o700)
        active = work / self.queued.name
        self.queued.rename(active)
        fd = os.open(self.spool, os.O_DIRECTORY | os.O_RDONLY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.now = self.deadline
        self.assertEqual(self.store.sweep(), 1)
        self.assertTrue(active.exists())
        self.assertEqual(self.store.pending_cleanup(), 1)
        self.assertEqual(self.worker.poll("first"), Unavailable("deadline"))
        self.write(self.out / (self.name + ".proof"), b"late proof")
        active.unlink()  # cp_prove finishes releasing its batch
        self.assertEqual(self.store.sweep(), 0)
        self.assertEqual(self.store.pending_cleanup(), 0)
        self.assertFalse(any(self.out.iterdir()))

    def test_link_and_hold_fail_closed_without_losing_cleanup_retry(self) -> None:
        outside = self.root / "unrelated"
        self.write(outside, b"unrelated data")
        proof = self.out / (self.name + ".proof")
        proof.unlink()
        os.link(outside, proof)
        with self.assertRaises(SpoolError):
            self.store.handoff("first")
        self.assertEqual(self.store.pending_cleanup(), 1)
        self.assertEqual(outside.read_bytes(), b"unrelated data")
        proof.unlink()
        proof.symlink_to(outside)
        (self.spool / "hold").touch()
        with self.assertRaises(SpoolError):
            self.store.sweep()
        (self.spool / "hold").unlink()
        self.assertEqual(self.store.sweep(), 0)
        self.assertEqual(self.store.pending_cleanup(), 0)
        self.assertEqual(outside.read_bytes(), b"unrelated data")
        self.assertFalse(proof.is_symlink())


if __name__ == "__main__":
    unittest.main()
