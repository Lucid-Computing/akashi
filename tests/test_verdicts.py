"""Signed verdict evidence, per-reader isolation and exact original proof reconstruction."""

import hashlib
import importlib
import json
import sqlite3
import tempfile
import unittest
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from importlib.util import find_spec
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from auditor.verdict_signing import public_verdict, sign_verdict, verify_signed
from auditor.verdicts import VerdictStore, decide
from prover.reference import ReferenceTrace
from prover.request import build_statement
from prover.worker import CandidateProof, Unavailable


class SignedVerdictTests(unittest.TestCase):
    def test_external_preimage_historical_role_and_strict_projection(self) -> None:
        key = Ed25519PrivateKey.generate()
        doc: dict[str, Any] = {
            "version": "vig-verdict/1",
            "auditor_key_id": "old",
            "verified_at": "2026-11-20T00:00:00.123Z",
            "outcome": "UNAVAILABLE",
            "reason": "prover_unavailable",
            "challenge_id": str(uuid.uuid4()),
            "transcript_commitment": "12" * 32,
        }
        public = sign_verdict(doc, key)
        key.public_key().verify(
            bytes.fromhex(str(public["signature"])),
            b"vig/verdict/1" + rfc8785.dumps(doc),
        )
        lookup = Mock(return_value=key.public_key().public_bytes_raw())
        self.assertEqual(verify_signed(public, lookup), public)
        lookup.assert_called_once_with("auditor", "old")
        for fields in (
            {"token": 42},
            {"proof_sha256": "ab" * 32},
            {"reason": "private reason"},
            {"verified_at": "2026-02-31T00:00:00.123Z"},
        ):
            with self.assertRaises(ValueError):
                public_verdict({**public, **fields})
        with self.assertRaises(ValueError):
            verify_signed({**public, "reason": "proof_rejected"}, lookup)

    def test_incomplete_range_and_missing_evidence(self) -> None:
        args: dict[str, Any] = {"primary": Mock(), "secondary": None, "scorer": None}
        self.assertEqual(decide((1,), (2,), 2, None, **args).outcome, "INCOMPLETE")
        self.assertEqual(decide((1,), (2, 3), 2, None, **args).outcome, "UNAVAILABLE")
        scorer = Mock()
        scorer.score.return_value = ReferenceTrace((2, 3, 0), 3, 1)
        actual = decide(
            (1,),
            (2, 3),
            2,
            Unavailable("spool_failure"),
            primary=Mock(),
            secondary=None,
            scorer=scorer,
        )
        self.assertEqual(actual.outcome, "EXCUSED_RANGE")
        self.assertIsNone(actual.artifact)
        self.assertNotIn("position", repr(actual))
        scorer.score.return_value = ReferenceTrace((2,), 1, 1)
        self.assertEqual(
            decide(
                (1,),
                (2, 3),
                2,
                Unavailable("spool_failure"),
                primary=Mock(),
                secondary=None,
                scorer=scorer,
            ).outcome,
            "UNAVAILABLE",
        )


@unittest.skipUnless(
    find_spec("auditor.jobs")
    and find_spec("verifier.proof")
    and find_spec("auditor.intake"),
    "requires integrated intake, jobs and proof verifier",
)
class VerdictStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "audit.db"
        self.now = datetime(2026, 11, 20, tzinfo=timezone.utc)
        key = PrivateKey.generate()
        tags = b"t" * 32
        self.intake = importlib.import_module("auditor.intake").ChallengeIntake(
            self.path,
            descriptor={},
            assets=None,
            auditor_public_key=bytes(key.public_key),
            holder_hmac_key=tags,
            clock=lambda: self.now,
        )
        self.jobs = importlib.import_module("auditor.jobs").AuditJobs(
            self.path,
            auditor_private_key=bytes(key),
            holder_hmac_key=tags,
            clock=lambda: self.now,
        )
        self.primary, self.scorer = Mock(), Mock()
        self.primary.check.return_value = "verified"
        self.signer = Ed25519PrivateKey.generate()
        self.store = VerdictStore(
            self.jobs,
            key_id="a1",
            signer=self.signer,
            primary=self.primary,
            scorer=self.scorer,
        )
        self.t = "ac" * 32
        self.statement = build_statement((1,), (2, 3))
        self.candidate = CandidateProof(self.statement, bytes(4), b"private-proof")

    def handle(self, owner: str = "holder") -> dict[str, Any]:
        material = {
            "max_tokens": 2,
            "verification": {
                "prompt_token_ids": [1],
                "reply_token_ids": [2, 3],
                "receipt": {
                    "transcript_commitment": self.t,
                    "served_at": self.now.isoformat(),
                },
            },
        }
        with patch.object(self.intake, "_validate", return_value=(material, False)):
            result: dict[str, Any] = self.intake.submit(owner, material, 0)
            return result

    def claim(self) -> Any:
        return self.jobs.claim(lease_time=timedelta(minutes=5))

    def test_conformance_private_artifact_and_replayed_reader(self) -> None:
        first = self.handle()
        decision = self.store.settle(self.claim(), self.candidate)
        self.assertEqual(decision.outcome, "CONFORMS")
        self.primary.check.assert_called_once_with(
            self.statement, bytes(4), b"private-proof"
        )
        extra = self.handle("second")
        public = self.store.by_commitment(self.t)
        self.assertEqual(
            {v["challenge_id"] for v in public},
            {first["challenge_id"], extra["challenge_id"]},
        )
        self.assertEqual(self.store.recent(1), public)
        self.assertEqual(self.store.stats()["conform"], 2)
        for v in public:
            self.assertEqual(
                v["proof_sha256"], hashlib.sha256(b"private-proof").hexdigest()
            )
            verify_signed(v, lambda *_: self.signer.public_key().public_bytes_raw())
            self.assertNotIn("proof", v)
            self.assertNotIn("index", v)
        self.assertIsNone(
            self.store.private_proof(first["challenge_id"], extra["capability"])
        )
        self.assertEqual(
            self.store.private_proof(first["challenge_id"], first["capability"]),
            decision.artifact,
        )
        self.assertNotIn(b"private-proof", self.path.read_bytes())
        rotated = VerdictStore(
            self.jobs,
            key_id="a2",
            signer=Ed25519PrivateKey.generate(),
            primary=self.primary,
        )
        self.assertEqual(rotated.by_commitment(self.t), public)
        self.now += timedelta(days=30)
        self.assertIsNone(
            rotated.private_proof(first["challenge_id"], first["capability"])
        )
        self.assertEqual(rotated.by_commitment(self.t), public)

    def test_deviation_requires_reconstructed_corrected_prefix(self) -> None:
        h = self.handle()
        self.scorer.score.return_value = ReferenceTrace((2, 5) + (0,) * 1022)
        candidate = CandidateProof(
            build_statement((1,), (2, 5)), bytes(4), b"private-deviation"
        )
        result = self.store.settle(self.claim(), candidate)
        self.assertEqual(result.outcome, "DEVIATES")
        assert result.artifact
        self.assertEqual(
            (result.artifact["index"], result.artifact["expected"]), (1, 5)
        )
        status = self.store.private_status(h["challenge_id"], h["capability"])
        assert status is not None
        self.assertNotIn('"expected"', json.dumps(status))

    def test_rejected_unrelated_or_disagreeing_evidence_stays_unavailable(self) -> None:
        for i, (outcome, reason) in enumerate(
            (("rejected", "proof_rejected"), ("unavailable", "verifier_unavailable"))
        ):
            self.t = f"{i:064x}"
            self.handle()
            self.primary.check.return_value = outcome
            self.assertEqual(
                self.store.settle(self.claim(), self.candidate).reason, reason
            )
            self.assertEqual(
                self.store.by_commitment(self.t)[0]["outcome"], "UNAVAILABLE"
            )
        self.t = "34" * 32
        h = self.handle()
        secondary = Mock()
        secondary.check.return_value = "rejected"
        self.primary.check.return_value = "verified"
        store = VerdictStore(
            self.jobs,
            key_id="a1",
            signer=self.signer,
            primary=self.primary,
            secondary=secondary,
        )
        self.assertEqual(
            store.settle(self.claim(), self.candidate).reason, "verifier_disagreement"
        )
        self.assertIsNone(store.private_proof(h["challenge_id"], h["capability"]))

    def test_signing_failure_rolls_back_terminal_state_and_private_artifact(
        self,
    ) -> None:
        h = self.handle()
        claim = self.claim()
        with (
            patch(
                "auditor.verdicts.sign_verdict",
                side_effect=ValueError("signer failure"),
            ),
            self.assertRaises(ValueError),
        ):
            self.store.settle(claim, self.candidate)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM audit_evidence").fetchone()[0], 0
            )
        state = self.store.private_status(h["challenge_id"], h["capability"])
        assert state
        self.assertEqual(state["status"], "verifying")
        self.store.settle(claim, self.candidate)
        self.assertEqual(self.store.stats()["pending"], 0)

    def test_incomplete_and_range_get_signed_without_publishing_private_details(
        self,
    ) -> None:
        self.jobs.enqueue_sample(
            leaf_hash="aa" * 32,
            transcript=self.t,
            served_at=self.now,
            prompt=(1,),
            reply=(2,),
            budget=2,
        )
        self.assertEqual(self.store.settle(self.claim(), None).outcome, "INCOMPLETE")
        incomplete = self.store.by_commitment(self.t)[0]
        self.assertEqual(incomplete["reason"], "completion_rule")
        self.t = "56" * 32
        h = self.handle()
        self.scorer.score.return_value = ReferenceTrace((2, 3, 0), 3, 1)
        self.store.settle(self.claim(), Unavailable("spool_failure"))
        signed = self.store.by_commitment(self.t)[0]
        self.assertEqual(
            (signed["outcome"], signed["reason"]), ("EXCUSED_RANGE", "padding_range")
        )
        self.assertNotIn("position", signed)
        self.assertNotIn("proof_sha256", signed)
        self.assertIsNone(self.store.private_proof(h["challenge_id"], h["capability"]))
        with closing(sqlite3.connect(self.path)) as db:
            sealed = db.execute(
                "SELECT ciphertext FROM audit_evidence WHERE proof_digest IS NULL"
            ).fetchone()[0]
        self.assertNotIn(b"position", sealed)
        self.primary.check.assert_not_called()

    def test_private_download_checks_digest_against_signed_verdict(self) -> None:
        h = self.handle()
        self.store.settle(self.claim(), self.candidate)
        artifact = self.store.private_proof(h["challenge_id"], h["capability"])
        assert artifact
        artifact["proof"] = "eA=="
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "UPDATE audit_evidence SET ciphertext=?",
                (self.store._box.encrypt(json.dumps(artifact).encode()),),
            )
        with self.assertRaisesRegex(ValueError, "signed verdict"):
            self.store.private_proof(h["challenge_id"], h["capability"])

    def test_independent_missed_sample_and_later_holder(self) -> None:
        self.jobs.enqueue_sample(
            leaf_hash="ab" * 32,
            transcript=self.t,
            served_at=self.now,
            prompt=(1,),
            reply=(2, 3),
            budget=2,
        )
        self.now += timedelta(days=2)
        pub = self.store.by_commitment(self.t)
        self.assertEqual(pub[0]["reason"], "deadline_missed")
        self.handle()
        self.store.settle(self.claim(), self.candidate)
        self.assertEqual(
            {v["outcome"] for v in self.store.by_commitment(self.t)},
            {"CONFORMS", "UNAVAILABLE"},
        )
