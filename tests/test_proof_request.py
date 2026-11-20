"""Exact bytes from FlashProve 9e2bdd8ff5bf9c62f18263d7dac189b0400b260c.

The vectors are integrations/spool.py whole_reply(prompt, reply, 1024) outputs,
with repeated four-byte words expanded below to keep the fixtures readable.
"""

import unittest
from collections.abc import Sequence
from typing import cast
from unittest.mock import call, patch

from prover.request import build_spool_request, build_statement

VECTORS = [
    (
        "minimum",
        [200000],
        [200001],
        bytes.fromhex("400d0300 410d0300") + bytes(4092) + bytes.fromhex("01000000"),
    ),
    (
        "multi_token_reply",
        [200000, 257, 202047],
        [514, 200007],
        bytes.fromhex("400d0300 01010000 3f150300 02020000 470d0300")
        + bytes(4076)
        + bytes.fromhex("02000000 04000000"),
    ),
    (
        "one_padding_token",
        [257] * 767,
        [514] * 256,
        bytes.fromhex("01010000") * 767
        + bytes.fromhex("02020000") * 256
        + bytes.fromhex("00000000 fe020000 fe030000"),
    ),
    (
        "full_window",
        [200000] * 1023,
        [202047],
        bytes.fromhex("400d0300") * 1023 + bytes.fromhex("3f150300 fe030000 ff030000"),
    ),
]


class ProofRequestTests(unittest.TestCase):
    def test_pinned_statements_and_spool_requests(self) -> None:
        nonce = bytes(range(32))
        for name, prompt, reply, reference in VECTORS:
            with (
                self.subTest(name=name),
                patch("prover.request.os.urandom", return_value=nonce) as rng,
            ):
                self.assertEqual(build_statement(prompt, reply), reference)
                rng.assert_not_called()
                self.assertEqual(build_spool_request(prompt, reply), reference + nonce)
                rng.assert_called_once_with(32)

    def test_invalid_lengths(self) -> None:
        for prompt, reply in (([], [1]), ([1], []), ([1] * 1024, [1])):
            with (
                self.subTest(prompt=len(prompt), reply=len(reply)),
                self.assertRaises(ValueError),
            ):
                build_statement(prompt, reply)

    def test_token_validation_applies_to_both_sequences(self) -> None:
        for invalid in (-1, 202048, 2**32, True, "7", 7.0):
            tokens = cast(Sequence[int], [invalid])
            for prompt, reply in ((tokens, [1]), ([1], tokens)):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    build_spool_request(prompt, reply)

    def test_rejects_binary_and_text_containers(self) -> None:
        for value in (b"abc", bytearray(b"abc"), "abc"):
            with self.subTest(value=value), self.assertRaises(TypeError):
                build_statement(cast(Sequence[int], value), [1])

    def test_each_submission_draws_a_new_nonce(self) -> None:
        first, second = bytes(32), bytes(range(32))
        with patch("prover.request.os.urandom", side_effect=[first, second]) as rng:
            statement = build_statement([1], [2])
            self.assertEqual(build_spool_request([1], [2]), statement + first)
            self.assertEqual(build_spool_request([1], [2]), statement + second)
        self.assertEqual(rng.call_args_list, [call(32), call(32)])

    def test_rng_failure_aborts_encoding(self) -> None:
        with (
            patch("prover.request.os.urandom", side_effect=OSError),
            self.assertRaises(OSError),
        ):
            build_spool_request([1], [2])
