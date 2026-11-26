"""Historical verification of the independent RFC-0004 receipt vector used in #11."""

import json
import shutil
import subprocess
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from typing import cast

from operations.key_archive import PublicKeyArchive

LOG = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
NEW = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
AUDITOR = bytes.fromhex(
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
)


class KeyArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name, "verification.sqlite3")
        self.archive = PublicKeyArchive(self.path)
        self.archive.rotate("log", "key-1", LOG)
        self.archive.rotate("auditor", "key-1", AUDITOR)

    @unittest.skipUnless(
        shutil.which("node"), "independent Ed25519 check requires Node.js"
    )
    def test_retired_key_verifies_historical_signature(self) -> None:
        self.archive.rotate("log", "key-2", NEW, replaces="key-1")
        self.archive.rotate("log", "key-2", NEW, replaces="key-1")
        reopened = PublicKeyArchive(self.path)
        published = reopened.public_keys()
        self.assertIn(
            {
                "role": "log",
                "key_id": "key-1",
                "public_key": LOG.hex(),
                "active": False,
            },
            published,
        )
        self.assertIn(
            {"role": "log", "key_id": "key-2", "public_key": NEW.hex(), "active": True},
            published,
        )
        self.assertIn(
            {
                "role": "auditor",
                "key_id": "key-1",
                "public_key": AUDITOR.hex(),
                "active": True,
            },
            published,
        )
        self.assertEqual(len(published), 3)
        # Verify the already-signed promise bytes with an independent Ed25519 implementation.
        message = b"PromiseReceipt" + bytes.fromhex(
            "bb" * 32
            + "9e4cd3ec7fbaf6b6ef84a81e3281b6a854b28443ec9ea067a75b6a5f32bfb3aa"
        )
        signature = "175ff155f049d5fd305f5d39aaa9387da97e70412da0ceb991aa39ab24a5d8cd35415cdff4cf930f700c57cdd67c1e5ed65e3a5b291c0095f1be8ef1ef3c7b01"
        inputs = [
            [reopened.lookup("log", "key-1").hex(), message.hex(), signature],
            [reopened.lookup("log", "key-2").hex(), message.hex(), signature],
            [reopened.lookup("auditor", "key-1").hex(), message.hex(), signature],
            [reopened.lookup("log", "key-1").hex(), (message + b"!").hex(), signature],
        ]
        check = """
const {createPublicKey, verify} = require("node:crypto");
const inputs = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const results = inputs.map(([raw, message, signature]) => {
  const key = createPublicKey({format:"der", type:"spki", key:Buffer.from("302a300506032b6570032100"+raw, "hex")});
  return verify(null, Buffer.from(message,"hex"), key, Buffer.from(signature,"hex"));
});
console.log(JSON.stringify(results));
"""
        result = subprocess.run(
            ["node", "-e", check],
            input=json.dumps(inputs),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(result.stdout), [True, False, False, False])

    def test_collision_rolls_back_entire_rotation(self) -> None:
        self.archive.rotate("log", "key-2", NEW, replaces="key-1")
        before = self.archive.public_keys()
        for key_id, data, replaces in (
            ("key-1", AUDITOR, "key-2"),
            ("key-1", LOG, "key-2"),
            ("key-3", AUDITOR, "key-2"),
            ("key-3", LOG, "key-2"),
            ("key-3", bytes(32), "key-1"),
        ):
            with self.subTest(key_id=key_id), self.assertRaises(ValueError):
                self.archive.rotate("log", key_id, data, replaces=replaces)
            self.assertEqual(self.archive.public_keys(), before)
        with self.assertRaises(ValueError):
            self.archive.lookup("auditor", "key-2")

    def test_concurrent_rotations_have_one_winner(self) -> None:
        barrier = Barrier(2)

        def attempt(number: int) -> bool:
            barrier.wait()
            try:
                self.archive.rotate(
                    "log", f"next-{number}", bytes([number]) * 32, replaces="key-1"
                )
            except ValueError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as workers:
            self.assertCountEqual(workers.map(attempt, (1, 2)), [True, False])
        current = [
            k for k in self.archive.public_keys() if k["role"] == "log" and k["active"]
        ]
        self.assertEqual(len(current), 1)
        self.assertEqual(self.archive.lookup("log", "key-1"), LOG)

    def test_invalid_inputs_do_not_publish(self) -> None:
        before = self.archive.public_keys()
        for role, key_id, key in (
            ("gateway", "new", NEW),
            ("log", "\n", NEW),
            ("log", "new", b"short"),
            ("log", "new", cast(bytes, NEW.hex())),
        ):
            with self.subTest(role=role, key_id=key_id), self.assertRaises(ValueError):
                self.archive.rotate(role, key_id, key, replaces="key-1")
        self.assertEqual(self.archive.public_keys(), before)
