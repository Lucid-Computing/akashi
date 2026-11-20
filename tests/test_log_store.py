"""File-backed RFC-0004 recovery tests, including the independently signed #60 vector."""

import hashlib
import multiprocessing
import os
import tempfile
import unittest
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from unittest.mock import Mock
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from log.store import IdentityConflict, MerkleLog

# RFC 8032 §7.1 first public test seed, also used by the independent Node.js
# receipt vector in #60. These bytes are intentionally public.
KEY = Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
)
LOG_ID = "bb" * 32
KEY_ID = "key-1"
NOW = datetime(2026, 11, 20, 10, 20, tzinfo=timezone.utc)
LEAF = "a1144836a6630c736665f92461411e86411a00727f3e8041793745b639b0cb0c"
PROMISE = (
    "ff9114ef61866b7b95e1c26441b4b38d06a27f340f2e263b633314b083f66f23b"
    "85fb1ed123e8e57c0b57537e4f0fac0fad842cc343c31e3d3e74af05373b004"
)


def preimage(number: int = 0) -> dict[str, object]:
    identity = UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479").int + number
    return {
        "log_id": LOG_ID,
        "endpoint_id": "maverick-int-c7982f8a",
        "request_id": str(UUID(int=identity)),
        "served_at": "2024-02-29T23:59:59.999Z",
        "commitment_id": "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46",
        "render_profile": "aa" * 32,
        "params_digest": "9d9f290527a6be626a8f5985b26e19b237b44872b03631811df4416fc1713178",
        "transcript_commitment": "9234a1388156118cd6c82cd30283019a7685babccf8f2f3ea56bbd46a9314593",
        "beacon_round": 4294967297,
        "sampling_mode": "live",
        "log_key_id": KEY_ID,
    }


def wire_hash(fields: Mapping[str, object]) -> str:
    """Frame known test inputs directly per docs/spec/03-data-model.md."""
    fixed = bytes.fromhex(
        "".join(
            str(fields[k])
            for k in (
                "log_id",
                "commitment_id",
                "render_profile",
                "params_digest",
                "transcript_commitment",
            )
        )
    )
    frame = bytearray()
    for name in (
        "served_at",
        "endpoint_id",
        "request_id",
        "log_key_id",
        "sampling_mode",
    ):
        value = str(fields[name]).encode("utf-8")
        frame.extend(len(value).to_bytes(4, "little"))
        frame.extend(value)
    number = int(str(fields["beacon_round"]))
    return hashlib.sha256(
        b"vig/leaf/1" + fixed + number.to_bytes(8, "big") + frame
    ).hexdigest()


def leaf_node(record: Mapping[str, object]) -> bytes:
    return hashlib.sha256(b"\0" + bytes.fromhex(str(record["leaf_hash"]))).digest()


def parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def store_at(
    path: Path, now: datetime = NOW, key: Ed25519PrivateKey = KEY
) -> MerkleLog:
    return MerkleLog(
        path,
        log_id=LOG_ID,
        log_key_id=KEY_ID,
        signing_key=key,
        clock=lambda: now,
        leaf_hash=wire_hash,
    )


def crash_append(path: Path, before_commit: bool) -> None:
    key = Mock(spec=Ed25519PrivateKey, wraps=KEY)

    def sign(message: bytes) -> bytes:
        if before_commit and message.startswith(b"STH"):
            size = int.from_bytes(message[35:43], "big")
            if size == 2:
                os._exit(41)
        return KEY.sign(message)

    key.sign.side_effect = sign
    store_at(path, key=key).append(preimage(1))
    os._exit(42)  # The append committed, but no result was delivered.


class MerkleStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "log.sqlite"
        self.log = store_at(self.path)

    def verify_head(
        self,
        head: Mapping[str, object],
        size: int,
        root: bytes,
        key: Ed25519PrivateKey = KEY,
        key_id: str = KEY_ID,
    ) -> None:
        self.assertEqual(head["version"], "vig-log/1")
        self.assertEqual(head["log_id"], LOG_ID)
        self.assertEqual(head["log_key_id"], key_id)
        self.assertEqual(head["tree_size"], size)
        self.assertEqual(head["root_hash"], root.hex())
        timestamp = str(head["timestamp"])
        self.assertRegex(timestamp, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        signed = (
            b"STH"
            + bytes.fromhex(LOG_ID)
            + size.to_bytes(8, "big")
            + timestamp.encode()
            + root
        )
        key.public_key().verify(bytes.fromhex(str(head["signature"])), signed)

    def test_append_and_historical_signed_evidence_survive_restart(self) -> None:
        self.verify_head(self.log.head(), 0, hashlib.sha256(b"").digest())
        target = preimage()
        self.assertEqual(wire_hash(target), LEAF)
        first = self.log.append(target)
        self.assertEqual(
            first,
            {**target, "leaf_hash": LEAF, "leaf_index": 0, "promise_sig": PROMISE},
        )
        KEY.public_key().verify(
            bytes.fromhex(PROMISE), b"PromiseReceipt" + bytes.fromhex(LOG_ID + LEAF)
        )
        heads = [self.log.head()]
        leaves = [leaf_node(first)]
        for i in (1, 2):
            leaves.append(leaf_node(self.log.append(preimage(i))))
            heads.append(self.log.head())
        reopened = store_at(self.path)
        self.assertEqual(reopened.append({**target, "leaf_hash": LEAF}), first)
        left = parent(leaves[0], leaves[1])
        for size, root in enumerate((leaves[0], left, parent(left, leaves[2])), 1):
            self.verify_head(reopened.head(size), size, root)
            self.assertEqual(reopened.head(size), heads[size - 1])
        self.assertEqual(reopened.path(0, 1), ())
        self.assertEqual(reopened.path(0, 2), (leaves[1],))
        self.assertEqual(reopened.path(0, 3), (leaves[1], leaves[2]))
        self.assertEqual(reopened.path(2, 3), (left,))
        self.assertEqual(reopened.consistency(1, 3), (leaves[1], leaves[2]))
        self.assertEqual(reopened.consistency(2, 3), (leaves[2],))
        self.assertEqual(reopened.consistency(3, 3), ())
        public = {k: v for k, v in first.items() if k != "promise_sig"}
        self.assertEqual(reopened.receipt(0), public)
        self.assertEqual(reopened.receipts(0, 3)[0], public)

    def test_concurrent_retries_and_distinct_requests(self) -> None:
        ids = [0, 1, 0, 2, 0, 3, 0, 4]
        barrier = Barrier(len(ids), timeout=15)

        def append(i: int) -> dict[str, object]:
            writer = store_at(self.path)
            barrier.wait()
            return writer.append(preimage(i))

        with ThreadPoolExecutor(max_workers=len(ids)) as pool:
            results = list(pool.map(append, ids))
        by_id: dict[int, dict[str, object]] = {}
        for identity, result in zip(ids, results, strict=True):
            self.assertEqual(by_id.setdefault(identity, result), result)
        fresh = store_at(self.path)
        self.assertEqual(fresh.head()["tree_size"], 5)
        self.assertEqual({r["leaf_index"] for r in results}, set(range(5)))
        self.assertEqual(len(fresh.receipts(0, 5)), 5)
        for i in set(ids):
            self.assertEqual(fresh.append(preimage(i)), by_id[i])

    def test_conflicting_concurrent_writers_have_one_winner(self) -> None:
        barrier = Barrier(2, timeout=15)
        candidates = [preimage(), {**preimage(), "sampling_mode": "soak"}]

        def append(fields: dict[str, object]) -> dict[str, object] | None:
            writer = store_at(self.path)
            barrier.wait()
            try:
                return writer.append(fields)
            except IdentityConflict:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(append, candidates))
        self.assertEqual(results.count(None), 1)
        winning = 1 - results.index(None)
        fresh = store_at(self.path)
        self.assertEqual(fresh.append(candidates[winning]), results[winning])
        with self.assertRaises(IdentityConflict):
            fresh.append(candidates[1 - winning])
        self.assertEqual(fresh.head()["tree_size"], 1)
        self.assertEqual(
            fresh.receipt(0)["sampling_mode"], candidates[winning]["sampling_mode"]
        )

    def test_process_death_before_commit_then_lost_reply_after_commit(self) -> None:
        first = self.log.append(preimage())
        first_head = self.log.head()
        for before_commit, code in ((True, 41), (False, 42)):
            with self.subTest(before_commit=before_commit):
                child = multiprocessing.get_context("spawn").Process(
                    target=crash_append, args=(self.path, before_commit)
                )
                child.start()
                try:
                    child.join(timeout=15)
                    self.assertEqual(child.exitcode, code)
                finally:
                    if child.is_alive():
                        child.kill()
                        child.join()
                    child.close()
                fresh = store_at(self.path)
                self.assertEqual(fresh.head(1), first_head)
                if before_commit:
                    self.assertEqual(fresh.head(), first_head)
                    with self.assertRaises(KeyError):
                        fresh.receipt(1)
                else:
                    head = fresh.head()
                    self.assertEqual(head["tree_size"], 2)
                    recovered = fresh.append(preimage(1))
                    self.assertEqual(recovered["leaf_index"], 1)
                    self.assertEqual(
                        fresh.receipt(1)["leaf_hash"], recovered["leaf_hash"]
                    )
                    self.verify_head(
                        head, 2, parent(leaf_node(first), leaf_node(recovered))
                    )
                    self.assertEqual(fresh.head(), head)

    def test_rotation_preserves_promises_and_historical_signatures(self) -> None:
        first = self.log.append(preimage())
        first_head = self.log.head()
        second = self.log.append(preimage(1))
        previous = self.log.head()
        # Keep a live old signer open past the next checkpoint, then rotate.
        stale = store_at(self.path, NOW + timedelta(seconds=125))
        new_key = Ed25519PrivateKey.generate()
        rotated = MerkleLog(
            self.path,
            log_id=LOG_ID,
            log_key_id="key-2",
            replaces_key_id=KEY_ID,
            signing_key=new_key,
            leaf_hash=wire_hash,
            clock=lambda: NOW + timedelta(seconds=60),
        )
        root = parent(leaf_node(first), leaf_node(second))
        self.assertEqual(rotated.head(2, log_key_id=KEY_ID), previous)
        self.verify_head(previous, 2, root)
        self.verify_head(rotated.head(2), 2, root, new_key, "key-2")
        self.assertEqual(rotated.head(1), first_head)
        self.verify_head(first_head, 1, leaf_node(first))
        self.assertEqual(stale.append(preimage()), first)
        self.assertEqual(rotated.append(preimage()), first)
        with self.assertRaises(ValueError):
            stale.append(preimage(2))
        with self.assertRaises(ValueError):
            stale.checkpoint()
        new_fields = {**preimage(2), "log_key_id": "key-2"}
        third = rotated.append(new_fields)
        self.assertEqual(third["leaf_index"], 2)
        new_key.public_key().verify(
            bytes.fromhex(str(third["promise_sig"])),
            b"PromiseReceipt" + bytes.fromhex(LOG_ID + str(third["leaf_hash"])),
        )
        self.verify_head(
            rotated.head(), 3, parent(root, leaf_node(third)), new_key, "key-2"
        )

    def test_rotation_with_a_stale_clock_preserves_previous_writer(self) -> None:
        first = self.log.append(preimage())
        head = self.log.head()
        with self.assertRaises(ValueError):
            MerkleLog(
                self.path,
                log_id=LOG_ID,
                log_key_id="key-2",
                replaces_key_id=KEY_ID,
                signing_key=Ed25519PrivateKey.generate(),
                leaf_hash=wire_hash,
                clock=lambda: NOW - timedelta(seconds=1),
            )
        self.assertEqual(self.log.head(), head)
        self.assertEqual(self.log.append(preimage()), first)
        self.assertEqual(self.log.append(preimage(1))["leaf_index"], 1)

    def test_idle_checkpoint_cadence_and_retries(self) -> None:
        first = self.log.append(preimage())
        initial = self.log.head()
        before = store_at(self.path, NOW + timedelta(seconds=59, milliseconds=999))
        self.assertEqual(before.checkpoint(), initial)
        at_boundary = store_at(self.path, NOW + timedelta(seconds=60))
        refreshed = at_boundary.checkpoint()
        self.assertNotEqual(refreshed["timestamp"], initial["timestamp"])
        self.assertNotEqual(refreshed["signature"], initial["signature"])
        self.verify_head(refreshed, 1, leaf_node(first))
        self.assertEqual(at_boundary.checkpoint(), refreshed)
        self.assertEqual(at_boundary.append(preimage()), first)
        self.assertEqual(at_boundary.head(), refreshed)

    def test_append_rejects_private_fields_and_hash_or_identity_mismatch(self) -> None:
        initial = self.log.head()
        canary = "private-canary-must-never-reach-the-log"
        for field, value in (
            ("salt", canary),
            ("prompt_token_ids", [123]),
            ("messages", canary),
            ("reply_token_ids", [321]),
            ("promise_sig", "00" * 64),
            ("leaf_index", 0),
            ("leaf_hash", "00" * 32),
            ("log_id", "ee" * 32),
            ("log_key_id", "wrong-key"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.log.append({**preimage(), field: value})
        self.assertEqual(self.log.head(), initial)
        self.assertNotIn(canary.encode(), self.path.read_bytes())
        with self.assertRaises(KeyError):
            self.log.receipt(0)
