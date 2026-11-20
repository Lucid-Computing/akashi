"""Integration checks for private custody, signed append, pickup, and terminal release."""

import tempfile
import unittest
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from auditor.beacon import round_for
from escrow.store import Binding, EscrowStore
from gateway.commit_delivery import CommitError, DeliveryCommitter
from gateway.discovery import ServiceConfig
from gateway.policy import InferenceRequest
from log.receipt import leaf_hash, transcript_commitment, verify_promise
from log.store import MerkleLog
from pickup.crypto import open as open_pickup

NOW = datetime(2026, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)


class Pickup:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.reservation: tuple[str, str, datetime] | None = None
        self.envelope: dict[str, str] | None = None
        self.fail = False

    def reserve(self, pickup_id: str, leaf_hash: str, expires_at: datetime) -> None:
        self.events.append("reserve")
        identity = pickup_id, leaf_hash, expires_at
        if self.reservation is not None and self.reservation != identity:
            raise ValueError("conflicting reservation")
        self.reservation = identity

    def publish(
        self,
        pickup_id: str,
        leaf_hash: str,
        envelope: dict[str, str],
        expires_at: datetime,
    ) -> None:
        self.events.append("publish")
        if self.reservation != (pickup_id, leaf_hash, expires_at):
            raise ValueError("no matching reservation")
        if self.envelope is None:
            self.envelope = envelope
        if self.fail:
            raise OSError("lost acknowledgement")


def guard() -> None:
    pass


class DeliveryCommitTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.now = NOW
        key = Ed25519PrivateKey.generate()
        self.config = ServiceConfig(
            model="maverick-int",
            owned_by="fixture",
            created=0,
            log_id="aa" * 32,
            log_key_id="log",
            log_public_key=key.public_key().public_bytes_raw().hex(),
            auditor_key_id="auditor",
            auditor_public_key="11" * 32,
            log_url="https://log.example/log/v1/",
            pickup_url="https://pickup.example/receipts/v1/pickup/",
            audit_url="https://audit.example/audit/v1/",
            challenge_url="https://audit.example/audit/v1/challenges",
        )
        self.log = MerkleLog(
            self.root / "log",
            log_id=self.config.log_id,
            log_key_id="log",
            signing_key=key,
            leaf_hash=leaf_hash,
            clock=lambda: self.now,
        )
        self.escrow = EscrowStore(
            self.root / "escrow",
            wrapping_key=b"a" * 32,
            auditor_public_key=bytes(PrivateKey.generate().public_key),
            clock=lambda: self.now,
        )
        self.events: list[str] = []
        self.pickup = Pickup(self.events)
        self.edit: dict[str, object] = {}
        self.cancel = Event()
        self.lose_append = False
        self.open_after_append = False
        self.committer = DeliveryCommitter(
            self.config,
            endpoint_id="test",
            sampling_mode="live",
            stage=self.stage,
            append=self.append,
            pickup=self.pickup,
            clock=lambda: self.now,
        )
        self.chat = InferenceRequest(
            "maverick-int", "chat", (200000, 29), 2, False, False
        )
        self.raw = InferenceRequest(
            "maverick-int", "raw", (200000, 29), 2, False, False
        )

    def stage(self, binding: Binding, material: bytes) -> str:
        self.events.append("escrow")
        return self.escrow.stage(binding, material)

    def append(self, fields: Mapping[str, object]) -> Mapping[str, object]:
        self.events.append("log")
        promise = self.log.append(fields)
        if self.lose_append:
            raise OSError("private diagnostic")
        if self.open_after_append:
            self.now += timedelta(minutes=1)
        self.cancel.set()
        return {**promise, **self.edit}

    def test_chat_handoff_and_authenticated_pickup_use_original_input(self) -> None:
        messages = [{"role": "user", "content": "private canary"}]
        secret = b"b" * 32
        attempt = self.committer.prepare(
            self.chat,
            (3, 4),
            original_chat=messages,
            reply_text="reply",
            holder_secret=secret,
        )
        messages[0]["content"] = "changed by caller"
        self.assertEqual(attempt.served_at, "2026-01-01T12:00:00.123Z")
        self.assertEqual(
            attempt.beacon_round, round_for(NOW.replace(microsecond=123000))
        )
        evidence = self.committer.commit(attempt, guard=guard)
        self.assertEqual(self.events, ["escrow", "reserve", "log", "publish"])
        actual: Any = evidence["receipt"]
        verify_promise(
            actual,
            log_id=self.config.log_id,
            log_key_id="log",
            public_key=bytes.fromhex(self.config.log_public_key),
        )
        self.assertEqual(
            actual["transcript_commitment"],
            transcript_commitment(
                actual["commitment_id"],
                actual["render_profile"],
                2,
                actual["salt"],
                self.chat.prompt,
                (3, 4),
            ),
        )
        self.assertEqual(self.log.receipt(0)["leaf_hash"], actual["leaf_hash"])
        self.assertEqual(self.escrow.status(actual["leaf_hash"]), "pending")
        self.assertNotIn("salt", self.log.receipt(0))
        self.assertNotIn(b"private canary", (self.root / "escrow").read_bytes())
        self.assertEqual(
            self.pickup.reservation,
            (
                evidence["pickup_id"],
                actual["leaf_hash"],
                NOW.replace(microsecond=123000) + timedelta(days=7),
            ),
        )
        self.assertEqual(
            open_pickup(
                self.pickup.envelope,
                secret,
                [{"role": "user", "content": "private canary"}],
                2,
                "reply",
            ),
            evidence,
        )

    def test_lost_append_reuses_original_leaf_and_new_submission_is_fresh(self) -> None:
        attempt = self.committer.prepare(self.raw, (200008,))
        self.lose_append = True
        with self.assertRaises(CommitError) as fail:
            self.committer.commit(attempt, guard=guard)
        self.assertNotIn("private diagnostic", str(fail.exception))
        self.lose_append = False
        recovered = self.committer.commit(attempt, guard=guard)
        self.assertEqual(recovered, self.committer.commit(attempt, guard=guard))
        self.assertEqual(self.log.head()["tree_size"], 1)
        new = self.committer.prepare(self.raw, (200008,))
        other = self.committer.commit(new, guard=guard)
        self.assertNotEqual(attempt.request_id, new.request_id)
        a: Any = recovered["receipt"]
        b: Any = other["receipt"]
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertNotIn("pickup_id", recovered)
        self.assertEqual(self.log.head()["tree_size"], 2)

    def test_lost_pickup_acknowledgement_blocks_until_durable_retry(self) -> None:
        attempt = self.committer.prepare(
            self.chat,
            (1, 2),
            original_chat=[{"role": "user", "content": "x"}],
            reply_text="x",
            holder_secret=b"k" * 32,
        )
        self.pickup.fail = True
        with self.assertRaises(CommitError):
            self.committer.commit(attempt, guard=guard)
        first = self.pickup.envelope
        self.pickup.fail = False
        recovered = self.committer.commit(attempt, guard=guard)
        self.assertIs(first, self.pickup.envelope)
        self.assertEqual(self.log.head()["tree_size"], 1)
        self.assertIn("pickup_id", recovered)

    def test_no_terminal_evidence_on_invalid_signature_conflicting_leaf_or_cancel(
        self,
    ) -> None:
        attempt = self.committer.prepare(self.raw, (1, 2))
        for edit in (
            {"promise_sig": "00" * 64},
            {"beacon_round": 1},
            {"leaf_index": False},
            {"salt": "untrusted"},
        ):
            with self.subTest(edit=list(edit)), self.assertRaises(CommitError):
                self.edit = dict(edit)
                self.committer.commit(attempt, guard=guard)
        self.edit = {}
        self.cancel.clear()

        def cancelled() -> None:
            if self.cancel.is_set():
                raise TimeoutError("deadline")

        with self.assertRaises(TimeoutError):
            self.committer.commit(attempt, guard=cancelled)
        self.assertEqual(self.log.head()["tree_size"], 1)

    def test_open_round_blocks_return_even_after_valid_append(self) -> None:
        attempt = self.committer.prepare(self.raw, (1, 2))
        self.open_after_append = True
        with self.assertRaises(CommitError):
            self.committer.commit(attempt, guard=guard)
        self.assertEqual(self.log.head()["tree_size"], 1)
        self.events.clear()
        with self.assertRaises(CommitError):
            self.committer.commit(attempt, guard=guard)
        self.assertEqual(self.events, [])

    def test_bad_or_unusable_private_state_cannot_be_promised(self) -> None:
        with self.assertRaises(CommitError):
            self.committer.prepare(self.raw, (1,))
        with self.assertRaises(CommitError):
            self.committer.prepare(self.raw, (200008, 2))
        with self.assertRaises(CommitError):
            self.committer.prepare(self.raw, (1, 2), holder_secret=bytes(32))
        committer = DeliveryCommitter(
            self.config,
            endpoint_id="test",
            sampling_mode="live",
            stage=lambda _binding, _data: "gap",
            append=self.append,
            clock=lambda: self.now,
        )
        attempt = committer.prepare(self.raw, (1, 2))
        with self.assertRaises(CommitError):
            committer.commit(attempt, guard=guard)
        self.assertEqual(self.log.head()["tree_size"], 0)
