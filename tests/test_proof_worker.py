"""FlashProve's documented publication order, per-request tag, and private worker snapshots."""

import hashlib
import hmac
import os
import tempfile
import time
import unittest
from pathlib import Path

from prover.request import build_statement
from prover.submission import COMMITMENT, SpoolError, SubmissionStore
from prover.worker import CandidateProof, ProofWorker, Unavailable


class WorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.spool, self.state = self.root / "spool", self.root / "state"
        for d in (self.spool, self.state):
            d.mkdir(mode=0o700)
        mark = self.spool / "mark.txt"
        mark.write_text(f"cp-folder 1\nkind spool\ncommitment {COMMITMENT}\n")
        mark.chmod(0o600)
        self.store = SubmissionStore(self.state, self.spool)
        self.statement = build_statement([1, 4], [2])
        self.deadline = time.time_ns() + 60_000_000_000
        self.now = self.deadline - 1
        self.worker = self.new_worker()
        self.item = self.store.submit("job1", self.statement, deadline_ns=self.deadline)
        self.out = self.spool / "out"
        self.out.mkdir(mode=0o700, exist_ok=True)

    def new_worker(self) -> ProofWorker:
        return ProofWorker(self.store, max_proof_bytes=80, now_ns=lambda: self.now)

    def write_part(self, name: str, data: bytes, stamp: int = 123456789) -> Path:
        p = self.out / (self.item.request_id + "." + name)
        p.write_bytes(data)
        p.chmod(0o600)
        os.utime(p, ns=(stamp, stamp))
        return p

    def tag(self, proof: bytes | None) -> bytes:
        request = (self.spool / "in" / (self.item.request_id + ".req")).read_bytes()
        key = hmac.digest(request[-32:], b"p258-spool-tag-1", "sha256")
        request_id = hashlib.sha256(b"p258-spool-req-1" + request).digest()
        fields = (
            bytes(16) + b"failed"
            if proof is None
            else (
                (4).to_bytes(8, "little")
                + len(proof).to_bytes(8, "little")
                + bytes(4)
                + proof
            )
        )
        return hmac.digest(key, request_id + fields, "sha256")

    def test_first_authenticated_response_survives_restart_and_later_spool_changes(
        self,
    ) -> None:
        proof = b"private synthetic bytes"
        self.write_part("y", bytes(4))
        self.write_part("tag", self.tag(proof))
        self.assertIsNone(self.worker.poll("job1"))
        self.write_part("proof", proof)
        result = self.worker.wait("job1", poll_seconds=0.01)
        self.assertEqual(result, CandidateProof(self.statement, bytes(4), proof))
        self.assertNotIn("private", repr(result))
        self.write_part("proof", b"changed")
        self.assertEqual(self.new_worker().poll("job1"), result)
        (self.spool / "hold").touch()
        with self.assertRaises(SpoolError):
            self.worker.poll("job1")

    def test_anonymous_failure_stays_unavailable_across_restart(self) -> None:
        self.write_part("tag", self.tag(None))
        self.assertIsNone(self.worker.poll("job1"))
        p = self.write_part("failed", b"")
        self.assertEqual(self.worker.poll("job1"), Unavailable("spool_failure"))
        p.unlink()
        self.assertEqual(self.new_worker().poll("job1"), Unavailable("spool_failure"))

    def test_missed_absolute_deadline_wins_even_if_a_response_appears_later(
        self,
    ) -> None:
        self.now = self.deadline
        self.assertEqual(
            self.worker.wait("job1", poll_seconds=1), Unavailable("deadline")
        )
        self.write_part("tag", self.tag(None))
        self.write_part("failed", b"")
        self.assertEqual(self.new_worker().poll("job1"), Unavailable("deadline"))

    def test_mismatched_tag_blocks_candidate(self) -> None:
        self.write_part("y", bytes(4))
        self.write_part("proof", b"hello")
        self.write_part("tag", self.tag(b"other"))
        self.assertEqual(self.worker.poll("job1"), Unavailable("invalid_response"))

    def test_conflicting_success_and_failure_markers_block_candidate(self) -> None:
        self.write_part("y", bytes(4))
        self.write_part("proof", b"a")
        self.write_part("tag", self.tag(b"a"))
        self.write_part("failed", b"")
        self.assertEqual(self.worker.poll("job1"), Unavailable("invalid_response"))

    def test_file_permissions_and_timestamps_are_checked(self) -> None:
        self.write_part("failed", b"")
        self.write_part("tag", self.tag(None), stamp=3333333333)
        self.assertEqual(self.worker.poll("job1"), Unavailable("invalid_response"))

    def test_symlink_cannot_supply_a_proof(self) -> None:
        self.write_part("tag", self.tag(b"private"))
        self.write_part("y", bytes(4))
        (self.out / (self.item.request_id + ".proof")).symlink_to(self.root / "state")
        self.assertEqual(self.worker.poll("job1"), Unavailable("invalid_response"))
