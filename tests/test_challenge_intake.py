"""Atomic holder and transcript quotas, verified private evidence, and lossless restart."""

import hashlib
import json
import sqlite3
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from importlib.util import find_spec
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey, SealedBox

from auditor.beacon import round_for
from auditor.intake import ChallengeIntake, IntakeError
from gateway.discovery import ServiceConfig
from gateway.renderer import RAW_PROFILE_DIGEST
from log.receipt import leaf_hash, params_digest, transcript_commitment
from log.store import MerkleLog
from tests.test_discovery import CONFIG

COMMITMENT = "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46"


class ChallengeIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.key = PrivateKey.generate()
        self.db = self.root / "intake.db"
        self.signer = Ed25519PrivateKey.generate()
        self.config = ServiceConfig(
            **{
                **CONFIG,
                "log_public_key": self.signer.public_key().public_bytes_raw().hex(),
            }
        )
        self.received = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
        self.clock = self.received
        self.ledger = MerkleLog(
            self.root / "log.db",
            log_id=self.config.log_id,
            log_key_id=self.config.log_key_id,
            signing_key=self.signer,
            leaf_hash=leaf_hash,
            clock=lambda: self.received,
        )
        self.intake = self.reopen()

    def reopen(self) -> ChallengeIntake:
        return ChallengeIntake(
            self.db,
            descriptor=self.config.descriptor(),
            assets=None,
            auditor_public_key=bytes(self.key.public_key),
            holder_hmac_key=bytes(self.key),
            clock=lambda: self.clock,
        )

    def make_bundle(self, case: int, reply: tuple[int, ...] = (2, 3)) -> dict[str, Any]:
        prompt = (case + 1, 4)
        salt = f"{case:064x}"
        fields = {
            "log_id": self.config.log_id,
            "log_key_id": self.config.log_key_id,
            "endpoint_id": "test",
            "request_id": str(uuid.uuid4()),
            "commitment_id": COMMITMENT,
            "served_at": self.received.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "render_profile": RAW_PROFILE_DIGEST,
            "beacon_round": round_for(self.received),
            "params_digest": params_digest(2),
            "transcript_commitment": transcript_commitment(
                COMMITMENT, RAW_PROFILE_DIGEST, 2, salt, prompt, reply
            ),
            "sampling_mode": "live",
        }
        receipt = self.ledger.append(fields)
        index = receipt.pop("leaf_index")
        assert isinstance(index, int)
        receipt["salt"] = salt
        head = self.ledger.head()
        size = head["tree_size"]
        assert isinstance(size, int)
        return {
            "verification": {
                "version": "vig/1",
                "receipt": receipt,
                "prompt_token_ids": list(prompt),
                "reply_token_ids": list(reply),
            },
            "input": list(prompt),
            "text": None,
            "max_tokens": 2,
            "history": {
                "sth": head,
                "inclusion": {
                    "leaf_index": index,
                    "tree_size": size,
                    "audit_path": [v.hex() for v in self.ledger.path(index, size)],
                },
            },
        }

    def counts(self) -> tuple[int, int]:
        with closing(sqlite3.connect(self.db)) as db:
            return (
                db.execute("SELECT COUNT(*) FROM challenge_handles").fetchone()[0],
                db.execute("SELECT COUNT(*) FROM challenge_work").fetchone()[0],
            )

    def test_concurrent_quota_and_private_deduplication(self) -> None:
        bundle = self.make_bundle(0)

        def submit(i: int) -> tuple[int, dict[str, object]]:
            try:
                return 202, self.intake.submit(f"holder-{i}", bundle, 0)
            except IntakeError as err:
                self.assertEqual(err.retry_after, 86400)
                return err.status, {}

        with (
            patch.object(self.intake, "_validate", return_value=(bundle, False)),
            ThreadPoolExecutor(max_workers=6) as pool,
        ):
            outcomes = list(pool.map(submit, range(8)))
        admitted = [handle for code, handle in outcomes if code == 202]
        self.assertEqual(len(admitted), 3)
        self.assertEqual(sum(code == 429 for code, _ in outcomes), 5)
        self.assertEqual(len({h["challenge_id"] for h in admitted}), 3)
        self.assertEqual(len({h["capability"] for h in admitted}), 3)
        self.assertEqual(self.counts(), (3, 1))
        with closing(sqlite3.connect(self.db)) as db:
            sealed = db.execute("SELECT material FROM challenge_work").fetchone()[0]
            secret = str(admitted[0]["capability"])
            self.assertEqual(
                db.execute(
                    "SELECT capability_hash FROM challenge_handles WHERE challenge_id=?",
                    (admitted[0]["challenge_id"],),
                ).fetchone()[0],
                hashlib.sha256(secret.encode()).digest(),
            )
            self.assertEqual(json.loads(SealedBox(self.key).decrypt(sealed)), bundle)
        self.assertNotIn(secret.encode(), self.db.read_bytes())
        self.assertNotIn(b"prompt_token_ids", self.db.read_bytes())
        self.assertNotIn(b"holder-", self.db.read_bytes())
        self.clock += timedelta(days=1)
        reopened = self.reopen()
        with patch.object(reopened, "_validate", return_value=(bundle, False)):
            self.assertEqual(
                reopened.submit("holder-next", bundle, 0)["status"], "pending"
            )
        self.assertEqual(self.counts(), (4, 1))

    def test_hourly_limit_is_shared_across_connections_and_rolls_at_boundary(
        self,
    ) -> None:
        for i in range(11):
            item = self.make_bundle(i)
            service = self.reopen()
            with patch.object(service, "_validate", return_value=(item, False)):
                if i < 10:
                    service.submit("holder", item, i)
                else:
                    with self.assertRaises(IntakeError) as ctx:
                        service.submit("holder", item, i)
                    self.assertEqual(
                        (ctx.exception.status, ctx.exception.retry_after), (429, 3600)
                    )
                    self.assertEqual(self.counts(), (10, 10))
                    self.clock += timedelta(hours=1)
                    service.submit("holder", item, i)
        self.assertEqual(self.counts(), (11, 11))

    @unittest.skipUnless(
        find_spec("verifier.holder"), "requires the holder verification component"
    )
    def test_live_receipt_verification_including_independent_windows(self) -> None:
        bundle = self.make_bundle(0)
        self.clock += timedelta(days=3)
        self.intake.submit("holder", bundle, 0)
        bad = {**bundle, "input": [4, 1]}
        for subject, value, index, expected in (
            ("", bundle, 0, 401),
            ("h", bad, 0, 400),
            ("h", bundle, 7, 400),
        ):
            with self.assertRaises(IntakeError) as ctx:
                self.intake.submit(subject, value, index)
            self.assertEqual(ctx.exception.status, expected)
        incomplete = self.make_bundle(1, reply=(2,))
        self.intake.submit("incomplete", incomplete, 1)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM challenge_work WHERE incomplete=1"
                ).fetchone()[0],
                1,
            )
        self.clock = self.received + timedelta(days=30)
        with self.assertRaises(IntakeError) as ctx:
            self.intake.submit("expired", bundle, 0)
        self.assertEqual(ctx.exception.code, "expired")
        self.assertEqual(self.counts(), (2, 2))
