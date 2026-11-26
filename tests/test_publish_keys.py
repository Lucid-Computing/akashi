import json
import tempfile
import unittest
from pathlib import Path

from operations.key_archive import PublicKeyArchive
from operations.publish_keys import publish


class PublishKeysTests(unittest.TestCase):
    def test_rotation_preserves_descriptor_identity_and_last_good_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "akashi.json")
            target.write_bytes(b"previous snapshot")
            archive = PublicKeyArchive(Path(directory, "keys.sqlite"))
            base: dict[str, object] = {
                "version": "akashi/1",
                "window": 1024,
                "log": {
                    "log_id": "a" * 64,
                    "log_key_id": "old",
                    "log_public_key": bytes(range(32)).hex(),
                },
                "auditor_key_id": "auditor-1",
                "auditor_public_key": bytes(range(2, 34)).hex(),
            }
            archive.rotate("log", "old", bytes(range(32)))
            with self.assertRaises(ValueError):
                publish(base, archive, target)
            self.assertEqual(target.read_bytes(), b"previous snapshot")
            archive.rotate("log", "new", bytes(range(1, 33)), replaces="old")
            archive.rotate("auditor", "auditor-1", bytes(range(2, 34)))
            with self.assertRaisesRegex(ValueError, "does not belong"):
                publish(base | {"auditor_public_key": "00" * 32}, archive, target)
            self.assertEqual(target.read_bytes(), b"previous snapshot")
            publish(base, archive, target)
            doc = json.loads(target.read_bytes())
            self.assertEqual(
                doc["log"],
                {
                    "log_id": "a" * 64,
                    "log_key_id": "new",
                    "log_public_key": bytes(range(1, 33)).hex(),
                },
            )
            self.assertEqual(doc["window"], 1024)
            self.assertEqual(doc["auditor_key_id"], "auditor-1")
            self.assertIn(
                {
                    "role": "log",
                    "key_id": "old",
                    "public_key": bytes(range(32)).hex(),
                    "active": False,
                },
                doc["verification_keys"],
            )

    def test_unknown_fields_do_not_reach_static_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "akashi.json")
            target.write_bytes(b"previous")
            archive = PublicKeyArchive(Path(directory, "keys.sqlite"))
            archive.rotate("log", "l", bytes(range(32)))
            archive.rotate("auditor", "a", bytes(range(1, 33)))
            base: dict[str, object] = {"version": "akashi/1", "log": {}}
            additions: tuple[dict[str, object], ...] = (
                {"authorization": "canary"},
                {"log": {"token_ids": [1, 2]}},
                {"render_profiles": [{"private": "canary"}]},
                {"pickup_url": {"credentials": "canary"}},
            )
            for addition in additions:
                with self.subTest(addition=addition), self.assertRaises(ValueError):
                    publish(base | addition, archive, target)
                self.assertEqual(target.read_bytes(), b"previous")
