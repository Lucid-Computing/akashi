"""Verify immutable Go Merkle fixtures and independently signed Node.js Ed25519 heads."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from log.verification import verify_consistency, verify_head, verify_inclusion
from operations.key_archive import PublicKeyArchive

LOG_ID = "ab" * 32
# Node crypto.sign(null, message, RFC 8032 test key) over the size-7 and
# size-9 Go roots. message starts with ASCII STH, raw log ID and a u64 BE size.
HEAD7: dict[str, object] = {
    "version": "akashi-log/1",
    "log_id": LOG_ID,
    "log_key_id": "old",
    "tree_size": 7,
    "timestamp": "2026-01-01T01:02:03.456Z",
    "root_hash": "7fd99db1920c38659959553e38f6fe7375d2b0d649c05702d4b9305fcede1bdd",
    "signature": "317273e54914f7639582ebf84a0a43b9ab0dafb78e518102db6b0e5dd71e72ac0e99df484f7e890d781debe7d088223272ad66b86db8f0ab6ab01cea9e4b0009",
}
HEAD9 = {
    **HEAD7,
    "log_key_id": "new",
    "tree_size": 9,
    "timestamp": "2026-01-01T01:03:03.456Z",
    "root_hash": "bc19085107aba081f03e36767a76da9dea8cee9443d5cf76915e7cb7aab7335a",
    "signature": "840a7748bf601b35b2ad97ce36b0d1c78858991564ddea9721349a0889fe7f826b12101994bbba198a0ad0c11385eb0e50098cbf6fdf227009021fee53721306",
}
OLD_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
NEW_KEY = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)


class LogVerificationTests(unittest.TestCase):
    def test_historical_and_current_signed_heads_use_archived_log_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            keys = PublicKeyArchive(Path(temp) / "archive")
            keys.rotate("log", "old", OLD_KEY)
            keys.rotate("log", "new", NEW_KEY, replaces="old")
            keys.rotate("auditor", "only-auditor", bytes(32))
            for head in (HEAD7, HEAD9):
                self.assertEqual(
                    verify_head(
                        {**head, "extra": "ignore"},
                        log_id=LOG_ID,
                        lookup_key=keys.lookup,
                    ),
                    head,
                )
            for field, value in (
                ("version", "akashi-log/2"),
                ("log_id", "de" * 32),
                ("log_key_id", "only-auditor"),
                ("log_key_id", "new"),
                ("tree_size", 8),
                ("tree_size", True),
                ("tree_size", 2**64),
                ("timestamp", "2026-01-01T01:02:03.456000Z"),
                ("timestamp", "2026-02-30T01:02:03.456Z"),
                ("timestamp", "2026-01-01T01:02:03.457Z"),
                ("root_hash", "00" * 32),
                ("signature", str(HEAD7["signature"]).upper()),
                ("signature", "00" * 64),
            ):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    verify_head(
                        {**HEAD7, field: value}, log_id=LOG_ID, lookup_key=keys.lookup
                    )
            with self.assertRaises(ValueError):
                verify_head(HEAD7, log_id="de" * 32, lookup_key=keys.lookup)

    def test_signed_zero_size_requires_the_empty_tree_root(self) -> None:
        empty = {
            **HEAD7,
            "tree_size": 0,
            "root_hash": hashlib.sha256(b"").hexdigest(),
            "signature": "16755174799d91b8803ce5e9f5a6bd9182bb369c79e02fec01dc0b597daef8c6389a785699a014894df4647f616da2d8d4c17980e64c61aba42240565e2b370b",
        }
        self.assertEqual(
            verify_head(empty, log_id=LOG_ID, lookup_key=lambda *_: OLD_KEY), empty
        )
        # Node signs this second zero-size head successfully; its root violates RFC 6962.
        invalid = {
            **empty,
            "root_hash": "00" * 32,
            "signature": "9e9d79e334867736e4f24c6a08bc54a6bfa56e7d31994f9e87ecd8bd4cfc1d19ff265d9efcaddec94b771b197cd463740045abf04c9b01c64aa51b01005c4c08",
        }
        with self.assertRaisesRegex(ValueError, "empty tree root"):
            verify_head(invalid, log_id=LOG_ID, lookup_key=lambda *_: OLD_KEY)

    def test_all_go_generated_inclusion_and_prefix_paths(self) -> None:
        vectors = json.loads(
            (Path(__file__).parent / "fixtures/merkle-v1.json").read_bytes()
        )
        nodes = vectors["node_hashes"]
        roots = [nodes[k] for k in vectors["roots"]]
        self.assertEqual((roots[7], roots[9]), (HEAD7["root_hash"], HEAD9["root_hash"]))
        for size, root in enumerate(roots):
            for index, path in enumerate(vectors["inclusion"][size]):
                with self.subTest(size=size, index=index):
                    leaf = vectors["leaf_hashes"][index]
                    wire = [nodes[k] for k in path]
                    verify_inclusion(leaf, index, size, root, wire)
                    self.assertRaises(
                        ValueError,
                        verify_inclusion,
                        leaf,
                        index,
                        size,
                        root,
                        [*wire, "00" * 32],
                    )
                    self.assertRaises(
                        ValueError, verify_inclusion, "00" * 32, index, size, root, wire
                    )
                    if wire:
                        self.assertRaises(
                            ValueError,
                            verify_inclusion,
                            leaf,
                            index,
                            size,
                            root,
                            wire[:-1],
                        )
                        self.assertRaises(
                            ValueError,
                            verify_inclusion,
                            leaf,
                            index,
                            size,
                            root,
                            ["00" * 32, *wire[1:]],
                        )
            for old, path in enumerate(vectors["consistency"][size]):
                with self.subTest(old=old, size=size):
                    wire = [nodes[k] for k in path]
                    verify_consistency(old, size, roots[old], root, wire)
                    self.assertRaises(
                        ValueError,
                        verify_consistency,
                        old,
                        size,
                        roots[old],
                        root,
                        [*wire, "00" * 32],
                    )
                    self.assertRaises(
                        ValueError, verify_consistency, old, size, "00" * 32, root, wire
                    )
                    if old:
                        self.assertRaises(
                            ValueError,
                            verify_consistency,
                            old,
                            size,
                            roots[old],
                            "00" * 32,
                            wire,
                        )
                    if wire:
                        self.assertRaises(
                            ValueError,
                            verify_consistency,
                            old,
                            size,
                            roots[old],
                            root,
                            wire[:-1],
                        )
                        self.assertRaises(
                            ValueError,
                            verify_consistency,
                            old,
                            size,
                            roots[old],
                            root,
                            ["ff" * 32, *wire[1:]],
                        )

    def test_large_sizes_and_unbalanced_right_edge(self) -> None:
        leaf = "01" * 32
        node = hashlib.sha256(b"\0" + bytes.fromhex(leaf)).digest()
        siblings = []
        root = node
        for _ in range(63):
            siblings.append(root.hex())
            root = hashlib.sha256(b"\1" + root + root).digest()
        large = 1 << 63
        verify_inclusion(leaf, large - 1, large, root.hex(), siblings)
        plus_one = hashlib.sha256(b"\1" + root + node).hexdigest()
        verify_inclusion(leaf, large, large + 1, plus_one, [root.hex()])
        verify_consistency(large, large + 1, root.hex(), plus_one, [node.hex()])
        with self.assertRaises(ValueError):
            verify_inclusion(leaf, large - 1, large + 1, plus_one, [root.hex()])
        with self.assertRaises(ValueError):
            verify_consistency(large - 1, large + 1, root.hex(), plus_one, [node.hex()])

    def test_strict_wire_indices_nodes_and_empty_shape(self) -> None:
        valid = "ab" * 32
        for invalid in (-1, 2**64, True, 1.0, "1"):
            bad: Any = invalid
            with self.subTest(invalid=bad), self.assertRaises(ValueError):
                verify_inclusion(valid, bad, 2, valid, [valid])
            with self.assertRaises(ValueError):
                verify_consistency(bad, 2, valid, valid, [])
        for malformed in (b"x" * 32, "ab" * 31, "ab " * 32, valid.upper()):
            with self.subTest(node=malformed), self.assertRaises(ValueError):
                verify_inclusion(valid, 0, 2, valid, [malformed])  # type: ignore[list-item]
        with self.assertRaises(ValueError):
            verify_consistency(9, 7, valid, valid, [])
        with self.assertRaises(ValueError):
            verify_consistency(0, 3, valid, valid, [])
        with self.assertRaises(ValueError):
            verify_inclusion(valid, 0, 0, hashlib.sha256(b"").hexdigest(), [])
