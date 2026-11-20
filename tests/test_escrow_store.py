"""On-disk escrow custody, expiry and selected handoff under RFC-0005."""

import hashlib
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event
from typing import Any
from unittest.mock import patch

from nacl.public import PrivateKey

from escrow.crypto import open_record, open_transfer, transfer_record
from escrow.store import Binding, EscrowStore

SERVED = datetime(2026, 1, 1, tzinfo=timezone.utc)
DEADLINE = SERVED + timedelta(minutes=5)
LEAF = "ab" * 32
BINDING = Binding(
    leaf_hash=LEAF,
    transcript_commitment="01" * 32,
    served_at="2026-01-01T00:00:00.000Z",
    beacon_round=20,
    sampling_mode="live",
)
MATERIAL = json.dumps(
    {
        "messages": [{"role": "user", "content": "private prompt -- Canary Hawthorn"}],
        "reply_text": "private answer -- Canary Juniper",
        "prompt_token_ids": [135179, 139131],
        "reply_token_ids": [129519],
        "salt": "private salt -- Canary Hawfinch",
    },
    separators=(",", ":"),
).encode()


class EscrowStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "escrow.sqlite"
        self.now = SERVED
        self.key = bytes(range(32))
        self.auditor = PrivateKey.generate()
        self.store = self.reopen()

    def reopen(self) -> EscrowStore:
        return EscrowStore(
            self.path,
            wrapping_key=self.key,
            auditor_public_key=bytes(self.auditor.public_key),
            clock=lambda: self.now,
        )

    def images(self) -> list[bytes]:
        return [
            file.read_bytes() for file in self.path.parent.iterdir() if file.is_file()
        ]

    def assert_redacted(self, image: bytes) -> None:
        for private in (
            b"Canary Hawthorn",
            b"Canary Juniper",
            b"Canary Hawfinch",
            b"135179",
            b"129519",
            self.key,
            bytes(self.auditor),
            hashlib.sha256(MATERIAL).digest(),
        ):
            self.assertNotIn(private, image)

    def stage(self) -> tuple[bytes, bytes]:
        self.assertEqual(self.store.stage(BINDING, MATERIAL), "pending")
        # Read actual persisted envelope so deletion checks cover SQLite file slack
        # as well as logically live rows and the public API.
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute(
                "SELECT ciphertext, key_slot, identity_tag FROM records WHERE status='pending'"
            ).fetchone()
        self.assertIsNotNone(row)
        ciphertext, slot, self.pending_identity_tag = row
        self.assertEqual(
            open_record(self.key, BINDING.metadata(), ciphertext, slot), MATERIAL
        )
        images = self.images()
        self.assertTrue(any(ciphertext in image for image in images))
        self.assertTrue(any(slot in image for image in images))
        self.assertTrue(any(self.pending_identity_tag in image for image in images))
        for image in images:
            self.assert_redacted(image)
        return ciphertext, slot

    def assert_erased(self, *transient: bytes) -> None:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute(
                "SELECT ciphertext, key_slot, identity_tag FROM records WHERE leaf_hash=?",
                (LEAF,),
            ).fetchone()
        self.assertEqual(row, (None, None, None))
        for image in self.images():
            self.assert_redacted(image)
            for data in (*transient, self.pending_identity_tag):
                self.assertNotIn(data, image)

    def test_pending_replay_restart_and_binding_integrity(self) -> None:
        ciphertext, slot = self.stage()
        reopened = self.reopen()
        self.assertEqual(reopened.stage(BINDING, MATERIAL), "pending")
        self.assertEqual(reopened.binding(LEAF), BINDING)
        self.assertEqual(reopened.next_expiry(), DEADLINE)
        self.assertIsNone(reopened.transfer(LEAF))
        self.assertIsNone(reopened.gap(LEAF))
        changed = (
            replace(BINDING, transcript_commitment="02" * 32),
            replace(BINDING, served_at="2026-01-01T00:01:00.000Z"),
            replace(BINDING, beacon_round=21),
            replace(BINDING, sampling_mode="soak"),
        )
        for binding in changed:
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                reopened.stage(binding, MATERIAL)
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                reopened.resolve(binding, selected=True)
        with self.assertRaises(ValueError):
            reopened.stage(BINDING, b"different private bytes")
        self.assertEqual(reopened.status(LEAF), "pending")
        with self.assertRaises((TypeError, ValueError)):
            invalid: Any = {"signature": "unverified"}
            reopened.resolve(BINDING, selected=invalid)
        self.assertIsNone(reopened.transfer(LEAF))
        self.assertTrue(
            any(slot in image and ciphertext in image for image in self.images())
        )
        public = json.dumps(
            [asdict(reopened.binding(LEAF)), reopened.status(LEAF), reopened.gap(LEAF)]
        )
        self.assert_redacted(public.encode())

    def test_wrong_store_keys_cannot_reopen_existing_custody(self) -> None:
        transient = self.stage()
        for wrapping_key, recipient in (
            (bytes(reversed(self.key)), bytes(self.auditor.public_key)),
            (self.key, bytes(PrivateKey.generate().public_key)),
        ):
            with (
                self.subTest(recipient_changed=wrapping_key == self.key),
                self.assertRaises(ValueError),
            ):
                EscrowStore(
                    self.path,
                    wrapping_key=wrapping_key,
                    auditor_public_key=recipient,
                    clock=lambda: self.now,
                )
        reopened = self.reopen()
        self.assertEqual(reopened.status(LEAF), "pending")
        self.assertEqual(
            open_record(self.key, BINDING.metadata(), *transient), MATERIAL
        )

    def test_unselected_erases_immediately_and_cannot_resurrect(self) -> None:
        transient = self.stage()
        self.now += timedelta(seconds=1)
        self.assertEqual(self.store.resolve(BINDING, selected=False), "unselected")
        self.assert_erased(*transient)
        reopened = self.reopen()
        self.assertEqual(reopened.stage(BINDING, MATERIAL), "unselected")
        with patch(
            "escrow.store.seal_record", side_effect=AssertionError("terminal reseal")
        ):
            self.assertEqual(
                reopened.stage(BINDING, b"altered material after final decision"),
                "unselected",
            )
        with self.assertRaises(ValueError):
            reopened.stage(replace(BINDING, beacon_round=21), MATERIAL)

        self.assertEqual(reopened.resolve(BINDING, selected=True), "unselected")
        self.assertIsNone(reopened.gap(LEAF))
        self.assertIsNone(reopened.transfer(LEAF))
        self.assertIsNone(reopened.next_expiry())
        self.assert_erased(*transient)

    def test_concurrent_selected_transfer_persists_once_through_ack(self) -> None:
        transient = self.stage()
        rendezvous = Barrier(6, timeout=10)

        def select() -> tuple[bytes, bytes]:
            worker = self.reopen()
            rendezvous.wait()
            self.assertEqual(worker.resolve(BINDING, selected=True), "transferring")
            handoff = worker.transfer(LEAF)
            assert handoff is not None
            return handoff.ciphertext, handoff.key_slot

        with ThreadPoolExecutor(max_workers=6) as pool:
            outgoing = [
                future.result() for future in [pool.submit(select) for _ in range(6)]
            ]
        self.assertEqual(len(set(outgoing)), 1)
        self.assert_erased(*transient)
        self.now = DEADLINE - timedelta(seconds=1)
        reopened = self.reopen()
        packet = reopened.transfer(LEAF)
        assert packet is not None
        self.assertEqual((packet.ciphertext, packet.key_slot), outgoing[0])
        self.assertEqual(packet.binding, BINDING)
        self.assertEqual(
            open_transfer(bytes(self.auditor), BINDING.metadata(), *outgoing[0]),
            MATERIAL,
        )
        with self.assertRaises(ValueError):
            open_transfer(
                bytes(PrivateKey.generate()), BINDING.metadata(), *outgoing[0]
            )
        self.assertIsNone(reopened.gap(LEAF))
        reopened.ack_transfer(LEAF)
        reopened.ack_transfer(LEAF)
        self.now = DEADLINE + timedelta(seconds=1)
        after = self.reopen()
        self.assertEqual(after.status(LEAF), "selected")
        self.assertEqual(after.resolve(BINDING, selected=True), "selected")
        self.assertEqual(after.stage(BINDING, MATERIAL), "selected")
        self.assertIsNone(after.transfer(LEAF))
        self.assert_erased(*transient, *outgoing[0])

    def test_receiver_outage_expires_unacknowledged_handoff_at_deadline(self) -> None:
        transient = self.stage()
        self.assertEqual(self.store.resolve(BINDING, selected=True), "transferring")
        reopened = self.reopen()
        packet = reopened.transfer(LEAF)
        assert packet is not None
        with patch(
            "escrow.store.seal_record", side_effect=AssertionError("transfer reseal")
        ):
            self.assertEqual(
                reopened.stage(BINDING, b"already handed off"), "transferring"
            )
        self.assertEqual(reopened.pending_transfers(4), [LEAF])
        self.assertEqual(reopened.next_expiry(), DEADLINE)
        self.assert_erased(*transient)
        self.now = DEADLINE
        self.assertIsNone(reopened.transfer(LEAF))
        with self.assertRaises(ValueError):
            reopened.ack_transfer(LEAF)
        after = self.reopen()
        self.assertEqual(after.status(LEAF), "gap")
        self.assertEqual(after.pending_transfers(4), [])
        self.assertEqual(after.resolve(BINDING, selected=True), "gap")
        self.assertEqual(after.stage(BINDING, MATERIAL), "gap")
        self.assertIsNone(after.transfer(LEAF))
        self.assertEqual(
            after.gap(LEAF),
            {
                "leaf_hash": LEAF,
                "beacon_round": 20,
                "reason": "escrow_expired",
            },
        )
        self.assert_erased(*transient, packet.ciphertext, packet.key_slot)

    def test_expiry_at_exact_boundary_without_a_sweeper(self) -> None:
        transient = self.stage()
        self.now = DEADLINE - timedelta(microseconds=1)
        self.assertEqual(self.store.status(LEAF), "pending")
        self.assertEqual(self.store.sweep(), 0)
        self.now = DEADLINE
        self.assertEqual(self.store.resolve(BINDING, selected=True), "gap")
        self.assertIsNone(self.store.transfer(LEAF))
        self.assert_erased(*transient)
        gap = self.store.gap(LEAF)
        self.assertEqual(
            gap, {"leaf_hash": LEAF, "beacon_round": 20, "reason": "escrow_expired"}
        )
        self.assert_redacted(json.dumps(gap).encode())
        self.assertEqual(self.store.sweep(), 0)
        self.assertEqual(self.store.stage(BINDING, MATERIAL), "gap")
        self.assertIsNone(self.store.next_expiry())

    def test_restart_after_missed_deadline_sweeps_before_serving(self) -> None:
        transient = self.stage()
        self.now = DEADLINE + timedelta(hours=1)
        restarted = self.reopen()
        self.assert_erased(*transient)
        self.assertEqual(restarted.status(LEAF), "gap")
        self.assertIsNone(restarted.transfer(LEAF))
        self.assertEqual(restarted.resolve(BINDING, selected=False), "gap")
        self.assertEqual(restarted.stage(BINDING, MATERIAL), "gap")
        self.assertIsNone(restarted.next_expiry())

    def test_record_first_seen_after_deadline_does_not_enter_custody(self) -> None:
        self.now = DEADLINE
        with patch(
            "escrow.store.seal_record", side_effect=AssertionError("already expired")
        ):
            self.assertEqual(self.store.stage(BINDING, MATERIAL), "gap")
        self.assertIsNone(self.store.next_expiry())
        self.assertIsNone(self.store.transfer(LEAF))
        for image in self.images():
            self.assert_redacted(image)

    def test_transfer_that_crosses_deadline_cannot_publish_a_job(self) -> None:
        transient = self.stage()
        self.now = DEADLINE - timedelta(microseconds=1)
        encrypted = Event()
        release = Event()

        def encrypt(*args: Any) -> tuple[bytes, bytes]:
            result = transfer_record(*args)
            encrypted.set()
            if not release.wait(10):
                raise TimeoutError("Test did not release transfer")
            return result

        with (
            patch("escrow.store.transfer_record", side_effect=encrypt),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            selected = pool.submit(self.store.resolve, BINDING, selected=True)
            try:
                self.assertTrue(encrypted.wait(10))
                self.now = DEADLINE
                sweep = pool.submit(self.store.sweep)
            finally:
                release.set()
            self.assertEqual(selected.result(timeout=10), "gap")
            sweep.result(timeout=10)
        self.assertEqual(self.reopen().status(LEAF), "gap")
        self.assertIsNone(self.store.transfer(LEAF))
        self.assert_erased(*transient)
