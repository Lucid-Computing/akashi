"""Offline operations drill using disposable signing keys and synthetic holder data."""

import json
import secrets
import subprocess
import sys
import tempfile
import unittest
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from escrow.store import EscrowStore
from gateway.commit_delivery import DeliveryCommitter
from gateway.discovery import ServiceConfig
from gateway.policy import InferenceRequest
from log.receipt import leaf_hash
from log.store import MerkleLog, WriterMismatch
from operations.key_archive import PublicKeyArchive
from operations.publish_keys import publish
from pickup.crypto import open as open_pickup
from pickup.store import PICKUP_LIFETIME, PickupStore
from tests.test_discovery import CONFIG

_ROOT = Path(__file__).resolve().parents[1]


class PrivateOperationsDrill(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.served = datetime(2025, 5, 8, 12, tzinfo=timezone.utc)
        self.now = self.served
        self.escrow = EscrowStore(
            self.root / "escrow.sqlite",
            wrapping_key=secrets.token_bytes(32),
            auditor_public_key=bytes(PrivateKey.generate().public_key),
            clock=lambda: self.now,
        )

    def writer(
        self,
        config: ServiceConfig,
        signer: Ed25519PrivateKey,
        *,
        replaces: str | None = None,
    ) -> MerkleLog:
        return MerkleLog(
            self.root / "log.sqlite",
            log_id=config.log_id,
            log_key_id=config.log_key_id,
            signing_key=signer,
            leaf_hash=leaf_hash,
            clock=lambda: self.now,
            replaces_key_id=replaces,
        )

    def delivery(
        self, config: ServiceConfig, log: MerkleLog, checkpoint: dict[str, object]
    ) -> dict[str, Any]:
        committer = DeliveryCommitter(
            config,
            endpoint_id="private-operations-drill",
            sampling_mode="live",
            stage=self.escrow.stage,
            append=log.append,
            clock=lambda: self.now,
        )
        request = InferenceRequest(config.model, "raw", (19, 23), 2, False, False)
        attempt = committer.prepare(request, (29, 31))
        data = committer.commit(attempt, guard=lambda: None)
        head = log.head()
        size = cast(int, head["tree_size"])
        old_size = cast(int, checkpoint["tree_size"])
        return {
            "verification": data,
            "input": list(request.prompt),
            "max_tokens": 2,
            "text": None,
            "history": {
                "sth": head,
                "inclusion": {
                    "tree_size": size,
                    "leaf_index": size - 1,
                    "audit_path": [x.hex() for x in log.path(size - 1, size)],
                },
                "consistency": {
                    "from": old_size,
                    "to": size,
                    "consistency_path": [
                        x.hex() for x in log.consistency(old_size, size)
                    ],
                },
            },
        }

    def holder(
        self, bundle: dict[str, Any], descriptor: Path, checkpoint: dict[str, object]
    ) -> tuple[int, str]:
        evidence = self.root / "holder.json"
        trust = self.root / "checkpoint.json"
        evidence.write_text(json.dumps(bundle))
        trust.write_text(json.dumps(checkpoint))
        result = subprocess.run(
            [
                sys.executable,
                str(_ROOT / "akashi"),
                "verify",
                str(evidence),
                "--descriptor",
                str(descriptor),
                "--checkpoint",
                str(trust),
                "--receipt-only",
            ],
            capture_output=True,
            check=False,
            timeout=20,
            text=True,
        )
        self.assertEqual(result.stderr, "")
        response = json.loads(result.stdout)
        self.assertEqual(response["exit_code"], result.returncode)
        return result.returncode, response["outcome"]

    def test_role_replacement_and_private_expiry_preserve_holder_evidence(self) -> None:
        archive = PublicKeyArchive(self.root / "verification.sqlite")
        old_signer = Ed25519PrivateKey.generate()
        old_public = old_signer.public_key().public_bytes_raw()
        config = ServiceConfig(**{**CONFIG, "log_public_key": old_public.hex()})
        archive.rotate("log", config.log_key_id, old_public)
        archive.rotate(
            "auditor", config.auditor_key_id, bytes.fromhex(config.auditor_public_key)
        )
        descriptor = self.root / "descriptor.json"
        publish(config.descriptor(), archive, descriptor)
        old = self.writer(config, old_signer)
        empty = old.head()
        first = self.delivery(config, old, empty)
        prior = old.head()
        self.assertEqual(
            self.holder(first, descriptor, empty), (30, "RECEIPT_VERIFIED")
        )

        fixture = json.loads((_ROOT / "tests/fixtures/pickup-v1.json").read_bytes())
        pickup = PickupStore(self.root / "pickup.sqlite", clock=lambda: self.now)
        lookup = fixture["pickup_id"]
        tag = secrets.token_hex(32)
        expires = self.now + PICKUP_LIFETIME
        pickup.reserve(lookup, tag, expires)
        pickup.publish(lookup, tag, fixture["envelope"], expires)
        self.assertEqual(
            open_pickup(
                pickup.get(lookup),
                bytes.fromhex(fixture["holder_secret_hex"]),
                fixture["original_chat"],
                fixture["budget"],
                fixture["reply_text"],
            ),
            fixture["verification"],
        )

        self.now += timedelta(minutes=1)
        fresh = Ed25519PrivateKey.generate()
        new_public = fresh.public_key().public_bytes_raw()
        updated = replace(
            config, log_key_id="drill-log-successor", log_public_key=new_public.hex()
        )
        archive.rotate(
            "log", updated.log_key_id, new_public, replaces=config.log_key_id
        )
        publish(config.descriptor(), archive, descriptor)
        replacement = self.writer(updated, fresh, replaces=config.log_key_id)
        self.assertEqual(replacement.head(1, log_key_id=config.log_key_id), prior)
        self.assertEqual(replacement.head()["root_hash"], prior["root_hash"])
        preimage = old.receipt(0)
        del preimage["leaf_index"], preimage["leaf_hash"]
        self.assertEqual(
            old.append(preimage)["promise_sig"],
            first["verification"]["receipt"]["promise_sig"],
        )
        with self.assertRaises(WriterMismatch):
            old.append({**preimage, "request_id": str(uuid.uuid4())})
        with self.assertRaises(WriterMismatch):
            old.checkpoint()
        with self.assertRaises(WriterMismatch):
            self.writer(updated, old_signer)
        second = self.delivery(updated, replacement, prior)
        self.assertEqual(second["history"]["sth"]["tree_size"], 2)
        self.assertEqual(
            second["verification"]["receipt"]["log_key_id"], updated.log_key_id
        )

        # Retained public evidence authenticates both generations offline, even
        # after all provider-private escrow material and the sealed pickup expire.
        first_leaf = first["verification"]["receipt"]["leaf_hash"]
        first_deadline = self.escrow.binding(first_leaf).deadline()
        self.now = first_deadline - timedelta(microseconds=1)
        self.assertEqual(self.escrow.status(first_leaf), "pending")
        self.now = first_deadline
        self.assertEqual(self.escrow.status(first_leaf), "gap")
        self.assertIsNone(self.escrow.transfer(first_leaf))
        self.assertEqual(
            self.escrow.gap(first_leaf),
            {
                "leaf_hash": first_leaf,
                "beacon_round": first["verification"]["receipt"]["beacon_round"],
                "reason": "escrow_expired",
            },
        )
        self.now = expires - timedelta(microseconds=1)
        self.assertIsNotNone(pickup.get(lookup))
        self.now = expires
        self.assertIsNone(pickup.get(lookup))
        self.assertEqual(pickup.sweep(), 0)
        self.assertEqual(self.escrow.sweep(), 1)
        self.assertIsNone(
            PickupStore(self.root / "pickup.sqlite", clock=lambda: self.now).get(lookup)
        )
        self.assertEqual(
            self.holder(first, descriptor, empty), (30, "RECEIPT_VERIFIED")
        )
        self.assertEqual(
            self.holder(second, descriptor, prior), (30, "RECEIPT_VERIFIED")
        )
        active_only = self.root / "active-only.json"
        active_only.write_text(json.dumps(updated.descriptor()))
        self.assertEqual(self.holder(first, active_only, empty)[0], 10)
        self.assertEqual(replacement.head(1, log_key_id=config.log_key_id), prior)
        self.assertEqual(replacement.head()["tree_size"], 2)


if __name__ == "__main__":
    unittest.main()
