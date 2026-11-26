"""Ciphertext-only custody, bounded retention and durable idempotence for Mode R."""

import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pickup.crypto import PickupError, lookup_id, seal
from pickup.crypto import open as open_pickup
from pickup.store import PICKUP_LIFETIME, PickupStore


class PickupStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "pickup.db"
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.store = self.reopen()
        self.until = self.now + PICKUP_LIFETIME
        self.chat = [{"role": "user", "content": "private canary pickup message"}]
        self.secret = os.urandom(32)
        self.tag = os.urandom(32).hex()
        self.identity = lookup_id(self.chat, 2, "display", self.secret)
        self.bundle = {
            "version": "akashi/1",
            "receipt": {"test": "private receipt canary"},
            "prompt_token_ids": [10],
            "reply_token_ids": [4, 5],
            "pickup_id": self.identity,
        }
        self.envelope = self.make_envelope()

    def reopen(self) -> PickupStore:
        return PickupStore(self.path, clock=lambda: self.now)

    def make_envelope(self) -> dict[str, str]:
        return seal(self.bundle, self.chat, 2, "display", self.secret)[1]

    def test_first_durable_ciphertext_survives_retry_and_restart(self) -> None:
        self.assertIsNone(self.store.get(self.identity))
        with self.assertRaises(PickupError):
            self.store.publish(self.identity, self.tag, self.envelope, self.until)
        self.store.reserve(self.identity, self.tag, self.until)
        self.assertIsNone(self.reopen().get(self.identity))
        self.store.publish(self.identity, self.tag, self.envelope, self.until)
        fresh = self.reopen()
        fresh.reserve(self.identity, self.tag, self.until)
        other = self.make_envelope()
        self.assertNotEqual(other, self.envelope)
        fresh.publish(self.identity, self.tag, other, self.until)
        result = fresh.get(self.identity)
        self.assertEqual(result, self.envelope)
        self.assertEqual(
            open_pickup(result, self.secret, self.chat, 2, "display"), self.bundle
        )
        stored = self.path.read_bytes()
        for private in (
            self.secret,
            self.secret.hex().encode(),
            b"private receipt canary",
            b"private canary pickup message",
            b"reply_token_ids",
        ):
            self.assertNotIn(private, stored)
        self.assertFalse(self.path.with_name(self.path.name + "-journal").exists())

    def test_concurrent_resealing_keeps_one_complete_envelope(self) -> None:
        self.store.reserve(self.identity, self.tag, self.until)
        variants = [self.make_envelope() for _ in range(8)]

        def publish(envelope: dict[str, str]) -> None:
            self.reopen().publish(self.identity, self.tag, envelope, self.until)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(publish, variants))
        winner = self.store.get(self.identity)
        self.assertIn(winner, variants)
        for tag, exp in (
            ("12" * 32, self.until),
            (self.tag, self.until - timedelta(microseconds=1)),
        ):
            with self.assertRaises(PickupError):
                self.store.reserve(self.identity, tag, exp)
            with self.assertRaises(PickupError):
                self.store.publish(self.identity, tag, self.envelope, exp)
        self.assertEqual(self.store.get(self.identity), winner)

    def test_expiry_removes_reservation_and_payload_at_the_boundary(self) -> None:
        self.store.reserve(self.identity, self.tag, self.until)
        self.store.publish(self.identity, self.tag, self.envelope, self.until)
        self.now = self.until - timedelta(microseconds=1)
        self.assertEqual(self.store.get(self.identity), self.envelope)
        self.now = self.until
        self.assertIsNone(self.store.get(self.identity))
        self.now -= timedelta(days=1)
        for store in (self.store, self.reopen()):
            self.assertIsNone(store.get(self.identity))
            with self.assertRaises(PickupError):
                store.reserve(self.identity, self.tag, self.until)
        stored = self.path.read_bytes()
        self.assertNotIn(bytes.fromhex(self.envelope["ciphertext"]), stored)
        self.assertNotIn(self.identity.encode(), stored)

    def test_sweeper_removes_pending_and_published_rows_without_request(self) -> None:
        pending = "ac" * 32
        self.store.reserve(pending, self.tag, self.until)
        self.store.reserve(self.identity, self.tag, self.until)
        self.store.publish(self.identity, self.tag, self.envelope, self.until)
        self.now = self.until + timedelta(seconds=1)
        self.assertEqual(self.store.sweep(), 2)
        self.assertEqual(self.store.sweep(), 0)
        with self.assertRaises(PickupError):
            self.store.publish(pending, self.tag, self.envelope, self.until)

    def test_untrusted_shape_and_excessive_retention_are_refused(self) -> None:
        for exp in (self.now, self.until + timedelta(microseconds=1)):
            with self.assertRaises(PickupError):
                self.store.reserve(self.identity, self.tag, exp)
        self.store.reserve(self.identity, self.tag, self.until)
        for envelope in (
            self.envelope | {"secret": "internal"},
            self.envelope | {"nonce": "ab"},
            self.envelope | {"version": "other"},
            self.envelope | {"ciphertext": "00"},
        ):
            with self.assertRaises(PickupError):
                self.store.publish(self.identity, self.tag, envelope, self.until)
        self.assertIsNone(self.store.get(self.identity))
        self.assertNotIn(b"internal", self.path.read_bytes())
        os.chmod(self.path, 0o644)
        with self.assertRaises(PermissionError):
            self.reopen()
