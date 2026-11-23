"""Exercise the real custody and signed-history stores across a private retention boundary."""

import sqlite3
import unittest
from contextlib import closing
from datetime import timedelta

from auditor.retention import sweep
from auditor.verdicts import VerdictStore
from tests import test_log_store as log_fixture
from tests import test_verdicts as verdict_fixture


class AuditRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.f = verdict_fixture.VerdictStoreTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def test_boundary_lag_restart_and_permanent_signed_history(self) -> None:
        f = self.f
        first = f.handle()
        alias = f.handle("another-holder")
        claim = f.claim()
        f.store.settle(claim, f.candidate)
        signed = f.store.by_commitment(f.t)
        counts = f.store.stats()
        log_path = f.path.parent / "public-log.sqlite"
        log = log_fixture.store_at(log_path)
        stored = log.append(log_fixture.preimage())
        head = log.head()
        with closing(sqlite3.connect(f.path)) as db:
            material = db.execute("SELECT material FROM challenge_work").fetchone()[0]
            proof = db.execute("SELECT ciphertext FROM audit_evidence").fetchone()[0]
            capabilities = [
                r[0]
                for r in db.execute("SELECT capability_hash FROM challenge_handles")
            ]
        for data in [material[32:64], proof[128:160], *capabilities]:
            self.assertTrue(
                data in f.path.read_bytes(),
                "private fixture bytes missing before expiry",
            )
        f.now += timedelta(days=30, microseconds=-1)
        self.assertIsNotNone(
            f.store.private_proof(first["challenge_id"], first["capability"])
        )
        self.assertEqual(sweep(f.path, f.now), 0)
        f.now += timedelta(microseconds=1)
        # No scheduled worker ran; the first authentic private read observes the cutoff.
        self.assertIsNone(
            f.store.private_proof(first["challenge_id"], first["capability"])
        )
        self.assertIsNone(f.jobs.status(alias["challenge_id"], alias["capability"]))
        for data in [material[32:64], proof[128:160], *capabilities]:
            self.assertFalse(
                data in f.path.read_bytes(), "private fixture bytes remain after expiry"
            )
        f.now -= timedelta(days=1)
        restarted = VerdictStore(
            f.jobs, key_id="a1", signer=f.signer, primary=f.primary
        )
        self.assertIsNone(
            restarted.private_proof(first["challenge_id"], first["capability"])
        )
        self.assertEqual(restarted.by_commitment(f.t), signed)
        after = restarted.stats()
        self.assertEqual(
            {k: after[k] for k in counts if k != "last_updated"},
            {k: v for k, v in counts.items() if k != "last_updated"},
        )
        self.assertEqual(sweep(f.path, f.now), 0)
        self.assertEqual(log_fixture.store_at(log_path).head(), head)
        self.assertEqual(
            log_fixture.store_at(log_path).append(log_fixture.preimage()), stored
        )

    def test_outcome_awaiting_signature_can_still_be_published_after_cleanup(
        self,
    ) -> None:
        f = self.f
        h = f.handle()
        f.jobs.complete(f.claim(), "UNAVAILABLE", "prover_unavailable")
        f.now += timedelta(days=30)
        self.assertEqual(sweep(f.path, f.now), 2)
        self.assertIsNone(f.jobs.status(h["challenge_id"], h["capability"]))
        published = f.store.by_commitment(f.t)
        self.assertEqual(
            [(v["challenge_id"], v["outcome"]) for v in published],
            [(h["challenge_id"], "UNAVAILABLE")],
        )
        self.assertEqual(sweep(f.path, f.now), 0)
        with closing(sqlite3.connect(f.path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM challenge_handles").fetchone()[0], 0
            )

    def test_periodic_sweep_keeps_pending_work_and_refuses_wrong_store(self) -> None:
        f = self.f
        h = f.handle()
        f.now += timedelta(days=32)
        self.assertEqual(sweep(f.path, f.now), 0)
        self.assertIsNotNone(f.jobs.status(h["challenge_id"], h["capability"]))
        public = f.path.parent / "public-log.sqlite"
        historical = log_fixture.store_at(public).head()
        public.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "challenge and audit"):
            sweep(public, f.now)
        self.assertEqual(log_fixture.store_at(public).head(), historical)
