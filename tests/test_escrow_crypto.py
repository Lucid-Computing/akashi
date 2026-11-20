"""Transient custody and selected-only auditor decryption for RFC-0005."""

import hashlib
import secrets
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.public import PrivateKey, SealedBox

from escrow.crypto import (
    EscrowCryptoError,
    open_record,
    open_transfer,
    seal_record,
    transfer_record,
)
from escrow.mailbox import AuditorInbox
from escrow.store import Binding, Transfer


class EscrowCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.wrapping_key = secrets.token_bytes(32)
        self.auditor = PrivateKey.generate()
        self.metadata = (
            b'["test leaf","test commitment","served_at",1,"live","expires_at"]'
        )
        self.plaintext = b"private messages, salt, prompt and reply tokens\x00\xff"
        self.ciphertext, self.key_slot = seal_record(
            self.wrapping_key, self.metadata, self.plaintext
        )

    def test_wraps_a_fresh_record_key_and_binds_both_parts(self) -> None:
        data, slot = self.ciphertext, self.key_slot
        self.assertEqual(
            open_record(self.wrapping_key, self.metadata, data, slot), self.plaintext
        )
        other_data, other_slot = seal_record(
            self.wrapping_key, self.metadata, self.plaintext
        )
        self.assertNotEqual(data[:24], other_data[:24])
        self.assertNotEqual(slot[:24], other_slot[:24])
        for changed in (
            (secrets.token_bytes(32), self.metadata, data, slot),
            (self.wrapping_key, self.metadata + b" ", data, slot),
            (self.wrapping_key, self.metadata, other_data, slot),
            (self.wrapping_key, self.metadata, data, other_slot),
            (self.wrapping_key, self.metadata, data[:-1], slot),
            (self.wrapping_key, self.metadata, data, slot[:-1]),
            (self.wrapping_key, self.metadata, slot, data),
        ):
            with self.assertRaisesRegex(
                EscrowCryptoError, "^escrow authentication failed$"
            ):
                open_record(*changed)

    def test_transfers_use_fresh_keys_and_require_the_auditor_private_key(self) -> None:
        sent, slot = transfer_record(
            self.wrapping_key,
            bytes(self.auditor.public_key),
            self.metadata,
            self.ciphertext,
            self.key_slot,
        )
        context = hashlib.sha256(self.metadata).digest()
        transient_key = crypto_aead_xchacha20poly1305_ietf_decrypt(
            self.key_slot[24:],
            b"vig/escrow/1/key\0" + context,
            self.key_slot[:24],
            self.wrapping_key,
        )
        sealed = SealedBox(self.auditor).decrypt(slot)
        self.assertEqual(sealed[:-32], b"vig/escrow/1/transfer-key\0" + context)
        self.assertNotEqual(sealed[-32:], transient_key)
        self.assertNotEqual(sent[:24], self.ciphertext[:24])
        self.assertEqual(
            open_transfer(bytes(self.auditor), self.metadata, sent, slot),
            self.plaintext,
        )
        with self.assertRaises(EscrowCryptoError):
            open_record(self.wrapping_key, self.metadata, sent, slot)
        for changed in (
            (bytes(PrivateKey.generate()), self.metadata, sent, slot),
            (bytes(self.auditor.public_key), self.metadata, sent, slot),
            (bytes(self.auditor), self.metadata + b" ", sent, slot),
            (bytes(self.auditor), self.metadata, self.ciphertext, slot),
            (bytes(self.auditor), self.metadata, sent, self.key_slot),
            (bytes(self.auditor), self.metadata, sent[:-1], slot),
            (bytes(self.auditor), self.metadata, sent, slot[:-1]),
        ):
            with self.assertRaisesRegex(
                EscrowCryptoError, "^escrow transfer authentication failed$"
            ):
                open_transfer(*changed)

    def test_transfer_authenticates_source_before_sealing_for_recipient(self) -> None:
        for changed in (
            (self.metadata + b" ", self.ciphertext, self.key_slot),
            (self.metadata, self.ciphertext[:-1], self.key_slot),
            (self.metadata, self.ciphertext, self.key_slot[:-1]),
        ):
            with self.assertRaises(EscrowCryptoError):
                transfer_record(
                    self.wrapping_key, bytes(self.auditor.public_key), *changed
                )
        with self.assertRaisesRegex(
            EscrowCryptoError, "^escrow transfer encryption failed$"
        ):
            transfer_record(
                self.wrapping_key,
                bytes(32),
                self.metadata,
                self.ciphertext,
                self.key_slot,
            )


class AuditorInboxTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "auditor.db"
        self.private_key = PrivateKey.generate()
        self.binding = Binding(
            "12" * 32, "34" * 32, "2026-01-01T00:00:00.000Z", 42, "soak"
        )
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.payload = b"auditor private transcript canary"
        provider_key = secrets.token_bytes(32)
        context = self.binding.metadata()
        ciphertext, slot = seal_record(provider_key, context, self.payload)
        self.transfer = Transfer(
            self.binding,
            *transfer_record(
                provider_key,
                bytes(self.private_key.public_key),
                context,
                ciphertext,
                slot,
            ),
        )

    def inbox(self) -> AuditorInbox:
        return AuditorInbox(
            self.path,
            auditor_private_key=bytes(self.private_key),
            clock=lambda: self.now,
        )

    def test_commit_before_ack_and_purged_job_are_replay_safe_after_restart(
        self,
    ) -> None:
        inbox = self.inbox()
        leaf = inbox.accept(self.transfer)
        self.assertEqual(leaf, self.binding.leaf_hash)
        self.assertNotIn(self.payload, self.path.read_bytes())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        # Delivery committed, but the sender lost the acknowledgment.
        self.now = self.binding.deadline() + timedelta(seconds=1)
        recovered = self.inbox()
        self.assertEqual(recovered.accept(self.transfer), leaf)
        self.assertEqual(recovered.read(leaf), self.payload)
        self.assertEqual(recovered.read(self.binding), self.payload)
        with self.assertRaises(ValueError):
            recovered.read(replace(self.binding, beacon_round=43))
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM selected_jobs").fetchone(), (1,)
            )
        with self.assertRaisesRegex(ValueError, "conflicting"):
            recovered.accept(
                replace(self.transfer, ciphertext=self.transfer.ciphertext[:-1])
            )
        self.assertTrue(recovered.purge(leaf))
        self.assertFalse(recovered.purge(leaf))
        self.assertEqual(recovered.accept(self.transfer), leaf)
        self.assertIsNone(recovered.read(leaf))
        for part in (self.transfer.ciphertext, self.transfer.key_slot, self.payload):
            self.assertNotIn(part, self.path.read_bytes())

    def test_late_or_over_deadline_during_accept_cannot_create_a_job(self) -> None:
        self.now = self.binding.deadline()
        with self.assertRaisesRegex(ValueError, "deadline"):
            self.inbox().accept(self.transfer)
        clock = Mock(side_effect=[self.now - timedelta(milliseconds=1), self.now])
        inbox = AuditorInbox(
            self.path, auditor_private_key=bytes(self.private_key), clock=clock
        )
        with self.assertRaisesRegex(ValueError, "deadline"):
            inbox.accept(self.transfer)
        self.assertIsNone(inbox.read(self.binding))
        self.now -= timedelta(milliseconds=1)
        with self.assertRaises(EscrowCryptoError):
            self.inbox().accept(
                replace(self.transfer, binding=replace(self.binding, beacon_round=43))
            )
        self.assertIsNone(inbox.read(self.binding))
