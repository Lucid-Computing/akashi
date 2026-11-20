"""Exercise stable private job identity, reader isolation, spool replay and deadlines."""

import importlib
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from importlib.util import find_spec
from pathlib import Path
from typing import Any
from unittest.mock import patch

from nacl.public import PrivateKey

from auditor.jobs import AuditJobs, Claim
from prover.request import build_statement
from prover.scoring import Assessment
from prover.submission import SubmissionStore
from tests.test_proof_submission import MARK


@unittest.skipUnless(
    find_spec("auditor.intake"), "requires the challenge intake database"
)
class AuditJobTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.path = self.root / "audit.db"
        self.key = PrivateKey.generate()
        self.tags = b"t" * 32
        self.start = datetime(2026, 11, 20, tzinfo=timezone.utc)
        self.now = self.start
        self.intake = importlib.import_module("auditor.intake").ChallengeIntake(
            self.path,
            descriptor={},
            assets=None,
            auditor_public_key=bytes(self.key.public_key),
            holder_hmac_key=self.tags,
            clock=lambda: self.now,
        )
        self.jobs = self.restart()
        self.t = "12" * 32
        self.leaf = "fe" * 32

    def restart(self) -> AuditJobs:
        return AuditJobs(
            self.path,
            auditor_private_key=bytes(self.key),
            holder_hmac_key=self.tags,
            clock=lambda: self.now,
        )

    def demand(self, owner: str = "holder") -> dict[str, Any]:
        material = {
            "max_tokens": 2,
            "verification": {
                "prompt_token_ids": [1],
                "reply_token_ids": [3, 4],
                "receipt": {
                    "transcript_commitment": self.t,
                    "served_at": self.start.isoformat(),
                },
            },
        }
        with patch.object(self.intake, "_validate", return_value=(material, False)):
            result: dict[str, Any] = self.intake.submit(owner, material, 0)
            return result

    def sample(self) -> str:
        return self.jobs.enqueue_sample(
            leaf_hash=self.leaf,
            transcript=self.t,
            served_at=self.start,
            prompt=(1,),
            reply=(3, 4),
            budget=2,
        )

    def claim(self) -> Claim:
        value = self.jobs.claim(lease_time=timedelta(seconds=10))
        assert value is not None
        return value

    def test_demand_access_and_lease_fencing_after_restart(self) -> None:
        a, b = self.demand("a"), self.demand("b")
        self.assertIsNone(self.jobs.status(a["challenge_id"], b["capability"]))
        first = self.claim()
        a_state = self.jobs.status(a["challenge_id"], a["capability"])
        assert a_state is not None
        self.assertEqual(a_state["status"], "verifying")
        self.assertIsNone(self.restart().claim(lease_time=timedelta(seconds=5)))
        self.now += timedelta(seconds=11)
        new = self.restart().claim(lease_time=timedelta(seconds=10))
        assert new is not None
        self.assertEqual(first.job_id, new.job_id)
        with self.assertRaises(ValueError):
            self.jobs.complete(first, "UNAVAILABLE", "prover_unavailable")
        with self.assertRaises(ValueError):
            self.jobs.complete(
                replace(new, reply=(9, 9)), "UNAVAILABLE", "prover_unavailable"
            )
        with self.assertRaises(ValueError):
            self.jobs.complete(new, "CONFORMS")
        self.jobs.complete(new, "UNAVAILABLE", "prover_unavailable")
        for handle in (a, b):
            state = self.jobs.status(handle["challenge_id"], handle["capability"])
            assert state is not None
            self.assertEqual(
                (state["status"], state["outcome"], state["reason"]),
                ("completed", "UNAVAILABLE", "prover_unavailable"),
            )
        self.now += timedelta(days=30)
        self.assertIsNone(self.jobs.status(a["challenge_id"], a["capability"]))

    def test_concurrent_claim_and_authorized_spool_retry(self) -> None:
        self.demand()
        with ThreadPoolExecutor(max_workers=5) as pool:
            claims = [
                c
                for c in pool.map(
                    lambda _: self.restart().claim(lease_time=timedelta(seconds=10)),
                    range(5),
                )
                if c
            ]
        self.assertEqual(len(claims), 1)
        first = claims[0]
        spool = self.root / "spool"
        spool.mkdir(mode=0o700)
        for name in ("in", "out", "work"):
            (spool / name).mkdir(mode=0o700)
        (spool / "mark.txt").write_text(MARK)
        store = SubmissionStore(self.root / "spool-state", spool, clock_ns=lambda: 1)
        decision = Assessment("conformance", build_statement(first.prompt, first.reply))
        submitted = self.jobs.dispatch(first, decision, store, deadline_ns=10000)
        self.now += timedelta(seconds=11)
        second = self.claim()
        replay = self.jobs.dispatch(second, decision, store, deadline_ns=20000)
        self.assertEqual(replay, submitted)
        self.assertEqual(len(list((spool / "in").iterdir())), 1)
        with self.assertRaises(ValueError):
            self.jobs.dispatch(
                second,
                Assessment("conformance", build_statement((1,), (4, 3))),
                store,
                deadline_ns=10000,
            )

    def test_sampled_deadline_and_demand_target_are_independent(self) -> None:
        job = self.sample()
        self.assertEqual(self.sample(), job)
        self.now += timedelta(hours=24)
        sample = self.jobs.sample_status(self.leaf)
        assert sample is not None
        self.assertEqual(
            (sample["outcome"], sample["reason"], sample["missed"]),
            ("UNAVAILABLE", "deadline_missed", 1),
        )
        self.now += timedelta(hours=2)
        handle = self.demand()
        self.now += timedelta(minutes=16)
        new = self.claim()
        self.assertEqual(new.job_id, job)
        state = self.jobs.status(handle["challenge_id"], handle["capability"])
        assert state is not None
        self.assertEqual(state["status"], "verifying")
        self.jobs.complete(new, "UNAVAILABLE", "prover_unavailable")
        sample_state = self.jobs.sample_status(self.leaf)
        assert sample_state is not None
        self.assertEqual(sample_state["reason"], "deadline_missed")

    def test_confirmed_gap_is_terminal_and_corrupt_work_does_not_block_queue(
        self,
    ) -> None:
        job = self.jobs.sample_unavailable(
            leaf_hash=self.leaf,
            transcript=self.t,
            served_at=self.start,
            reason="selection_gap",
        )
        self.assertEqual(
            job,
            self.jobs.sample_unavailable(
                leaf_hash=self.leaf,
                transcript=self.t,
                served_at=self.start,
                reason="selection_gap",
            ),
        )
        self.assertIsNone(self.jobs.claim(lease_time=timedelta(seconds=1)))
        state = self.jobs.sample_status(self.leaf)
        assert state is not None
        self.assertEqual((state["reason"], state["missed"]), ("selection_gap", 0))
        bad = self.demand()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE challenge_work SET material=x'00'")
        self.t = "34" * 32
        self.now += timedelta(seconds=1)
        self.demand()
        self.assertEqual(self.claim().transcript, self.t)
        bad_state = self.jobs.status(bad["challenge_id"], bad["capability"])
        assert bad_state is not None
        self.assertEqual(
            bad_state["reason"],
            "invalid_material",
        )
