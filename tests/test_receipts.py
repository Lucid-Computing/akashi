"""AKASHI/1 vectors generated independently with Node.js 24 crypto.

Inputs below follow docs/spec/03-data-model.md's binary frames and the
PromiseReceipt domain from specs/receipt-log.md. Node Buffer.writeUInt32LE
and writeBigUInt64BE encoded the words. crypto.createHash('sha256') hashed
the preimages and crypto.sign(null, message, key) signed with RFC 8032
section 7.1's first (public test) seed.
"""

import unittest
from typing import cast

from log.receipt import (
    leaf_hash,
    params_digest,
    promise_preimage,
    public_leaf,
    transcript_commitment,
    verify_promise,
)

LOG_ID = "bb" * 32
KEY_ID = "key-1"
KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
C = "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46"
PROFILE = "aa" * 32
SALT = bytes(range(32)).hex()
PARAMS = "9d9f290527a6be626a8f5985b26e19b237b44872b03631811df4416fc1713178"
TRANSCRIPT = "5decc65412dc8650c33e7ab5b1ae498c2fcd8dc7f83909c26b0d40642ca3d73d"
LEAF = "9e4cd3ec7fbaf6b6ef84a81e3281b6a854b28443ec9ea067a75b6a5f32bfb3aa"
RECEIPT: dict[str, object] = {
    "log_id": LOG_ID,
    "endpoint_id": "maverick-int-c7982f8a",
    "request_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "served_at": "2024-02-29T23:59:59.999Z",
    "commitment_id": C,
    "render_profile": PROFILE,
    "params_digest": PARAMS,
    "transcript_commitment": TRANSCRIPT,
    "leaf_hash": LEAF,
    "beacon_round": 4294967297,
    "sampling_mode": "live",
    "promise_sig": (
        "175ff155f049d5fd305f5d39aaa9387da97e70412da0ceb991aa39ab24a5d8cd3"
        "5415cdff4cf930f700c57cdd67c1e5ed65e3a5b291c0095f1be8ef1ef3c7b01"
    ),
    "log_key_id": KEY_ID,
    "salt": SALT,
}


def verify(receipt: dict[str, object]) -> None:
    verify_promise(receipt, log_id=LOG_ID, log_key_id=KEY_ID, public_key=KEY)


class ReceiptTests(unittest.TestCase):
    def test_signed_vector(self) -> None:
        self.assertEqual(params_digest(3), PARAMS)
        self.assertEqual(
            transcript_commitment(C, PROFILE, 3, SALT, [200000, 511], [257, 200001]),
            TRANSCRIPT,
        )
        self.assertEqual(leaf_hash(RECEIPT), LEAF)
        self.assertEqual(
            promise_preimage(LOG_ID, LEAF),
            b"PromiseReceipt" + bytes.fromhex(LOG_ID + LEAF),
        )
        verify(RECEIPT)

    def test_same_token_stream_with_a_different_split(self) -> None:
        self.assertNotEqual(
            transcript_commitment(C, PROFILE, 3, SALT, [200000], [511, 257, 200001]),
            TRANSCRIPT,
        )

    def test_metadata_is_covered_by_the_signature(self) -> None:
        for field, value in {
            "endpoint_id": "other-endpoint",
            "request_id": "f47ac10b-58cc-4372-a567-0e02b2c3d478",
            "served_at": "2024-02-29T23:59:59.998Z",
            "beacon_round": 4294967296,
            "sampling_mode": "soak",
            "render_profile": "dd" * 32,
            "transcript_commitment": "ee" * 32,
            "params_digest": "cd" * 32,
            "commitment_id": "ed" * 32,
        }.items():
            with self.subTest(field=field):
                changed = RECEIPT | {field: value}
                changed["leaf_hash"] = leaf_hash(changed)
                self.assertNotEqual(changed["leaf_hash"], LEAF)
                with self.assertRaises(ValueError):
                    verify(changed)

    def test_receipt_requires_pinned_log_key_and_signature(self) -> None:
        for log_id, key_id, key in (
            ("11" * 32, KEY_ID, KEY),
            (LOG_ID, "next-key", KEY),
            (LOG_ID, KEY_ID, bytes(32)),
        ):
            with (
                self.subTest(log_id=log_id, key_id=key_id),
                self.assertRaises(ValueError),
            ):
                verify_promise(
                    RECEIPT, log_id=log_id, log_key_id=key_id, public_key=key
                )
        with self.assertRaises(ValueError):
            verify(RECEIPT | {"promise_sig": "00" * 64})
        with self.assertRaises(ValueError):
            verify(RECEIPT | {"leaf_hash": "00" * 32})

    def test_rejects_malformed_wire_fields(self) -> None:
        for field, values in {
            "log_id": (LOG_ID.upper(), LOG_ID + "\n", LOG_ID[:-2], b"\xbb" * 32),
            "transcript_commitment": ("gg" * 32,),
            "request_id": (
                "F47AC10B-58CC-4372-A567-0E02B2C3D479",
                "f47ac10b58cc4372a5670e02b2c3d479",
            ),
            "served_at": (
                "2023-02-29T02:03:04.005Z",
                "2024-02-29T23:59:59Z",
                "2024-02-29T23:59:59.999+00:00",
            ),
            "beacon_round": (True, -1, 2**64, "42", 3.5),
            "sampling_mode": ("shadow",),
            "salt": (None, "ab cd" * 8),
            "promise_sig": ("00" * 63, "ZZ" * 64),
        }.items():
            for value in values:
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    if field in {"salt", "promise_sig"}:
                        public_leaf(RECEIPT | {field: value}, 0)
                    else:
                        leaf_hash(RECEIPT | {field: value})

    def test_public_leaf_reconstructs_digest_and_omits_private_fields(self) -> None:
        projected = public_leaf(RECEIPT, 0)
        self.assertEqual(
            projected,
            {k: v for k, v in RECEIPT.items() if k not in {"salt", "promise_sig"}}
            | {"leaf_index": 0},
        )
        self.assertNotIn(SALT, projected.values())
        self.assertEqual(leaf_hash(projected), LEAF)
        for index in (True, -1, 2**64):
            with self.subTest(index=index), self.assertRaises(ValueError):
                public_leaf(RECEIPT, index)
        with self.assertRaises(ValueError):
            public_leaf(RECEIPT | {"prompt_token_ids": [200000]}, 0)

    def test_rejects_invalid_transcript_inputs(self) -> None:
        for token in (True, -1, 202048, 2**32, 1.0):
            with self.subTest(token=token), self.assertRaises(ValueError):
                transcript_commitment(C, PROFILE, 1, SALT, [0], [cast(int, token)])
        for budget in (True, 0, -1, 2**32):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                params_digest(budget)
        for prompt, reply, budget in (
            ([], [1], 1),
            ([1], [], 1),
            ([1], [2, 3], 1),
            ([1] * 1024, [2], 1),
        ):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                transcript_commitment(C, PROFILE, budget, SALT, prompt, reply)
