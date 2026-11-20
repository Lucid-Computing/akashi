"""Fixed roots and proofs from github.com/transparency-dev/merkle v0.0.2.

The Go reference testonly.Tree.AppendData received each binary VIG leaf digest.
For every tree size, HashAt, InclusionProof and ConsistencyProof produced the
fixture; proof.VerifyInclusion and proof.VerifyConsistency checked each result.
The first input is the signed VIG/1 sample leaf from the receipt vectors. The
others are SHA-256 of UTF-8 "vig fixture leaf i" for i = 1 through 8.

Inclusion paths are indexed by [tree size][leaf index], consistency paths by
[new size][old size]. Every entry in a path is an index into node_hashes. This
retains the exact order and cardinality without repeating shared nodes.
"""

import hashlib
import json
import unittest
from pathlib import Path
from typing import TypedDict

from log.merkle import append_nodes, consistency_path, inclusion_path, root_hash


class Vectors(TypedDict):
    leaf_hashes: list[str]
    node_hashes: list[str]
    roots: list[int]
    inclusion: list[list[list[int]]]
    consistency: list[list[list[int]]]


class MerkleTests(unittest.TestCase):
    def test_every_historical_root_and_proof_matches_go_vectors(self) -> None:
        path = Path(__file__).parent / "fixtures" / "merkle-v1.json"
        vectors: Vectors = json.loads(path.read_text())
        known = list(map(bytes.fromhex, vectors["node_hashes"]))
        stored: dict[tuple[int, int], bytes] = {}

        def read(start: int, width: int) -> bytes:
            return stored[start, width]

        for index, data in enumerate(vectors["leaf_hashes"]):
            for start, width, digest in append_nodes(index, bytes.fromhex(data), read):
                self.assertNotIn((start, width), stored)
                self.assertEqual(start % width, 0)
                self.assertEqual(width & (width - 1), 0)
                self.assertEqual(start + width, index + 1)
                stored[start, width] = digest

        for size, node in enumerate(vectors["roots"]):
            with self.subTest(size=size):
                self.assertEqual(root_hash(size, read), known[node])
                self.assertEqual(len(vectors["inclusion"][size]), size)
                self.assertEqual(len(vectors["consistency"][size]), size + 1)
            for index, path_nodes in enumerate(vectors["inclusion"][size]):
                with self.subTest(inclusion=(index, size)):
                    self.assertEqual(
                        inclusion_path(index, size, read),
                        tuple(known[node] for node in path_nodes),
                    )
            for old, path_nodes in enumerate(vectors["consistency"][size]):
                with self.subTest(consistency=(old, size)):
                    self.assertEqual(
                        consistency_path(old, size, read),
                        tuple(known[node] for node in path_nodes),
                    )

    def test_append_reads_one_complete_left_sibling_per_merge(self) -> None:
        reads: list[tuple[int, int]] = []

        def read(start: int, width: int) -> bytes:
            reads.append((start, width))
            return bytes(32)

        index = 2**63 - 1
        nodes = append_nodes(index, bytes(32), read)
        self.assertEqual(len(nodes), 64)
        self.assertEqual(
            reads, [(index + 1 - 2 ** (level + 1), 2**level) for level in range(63)]
        )
        self.assertEqual(nodes[-1][:2], (0, 2**63))
        reads.clear()
        self.assertEqual(root_hash(0, read), hashlib.sha256(b"").digest())
        self.assertEqual(reads, [])
        root_hash(2**64 - 1, read)
        self.assertEqual(len(reads), 64)

    def test_indices_sizes_and_binary_digests_are_checked(self) -> None:
        def read(start: int, width: int) -> bytes:
            raise AssertionError("invalid request accessed the node store")

        for bad in (-1, True, 2**64):
            with self.subTest(size=bad), self.assertRaises(ValueError):
                root_hash(bad, read)
        for index, size in ((0, 0), (1, 1), (True, 2), (0, 2**64)):
            with self.subTest(inclusion=(index, size)), self.assertRaises(ValueError):
                inclusion_path(index, size, read)
        for old, new in ((1, 0), (True, 1), (-1, 1), (1, 2**64)):
            with self.subTest(consistency=(old, new)), self.assertRaises(ValueError):
                consistency_path(old, new, read)
        with self.assertRaises(ValueError):
            append_nodes(2**64 - 1, bytes(32), read)
        with self.assertRaises(ValueError):
            append_nodes(0, bytes(31), read)
        with self.assertRaises(ValueError):
            root_hash(1, lambda _start, _width: bytes(31))
