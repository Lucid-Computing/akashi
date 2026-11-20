"""Encode whole-reply requests for the pinned FlashProve verifier and spool (F7–F8)."""

import os
import struct
from collections.abc import Sequence

# specs/parameters.md fixes T, z and the vocabulary for the published commitment.
WINDOW = 1024
VOCABULARY_SIZE = 202048
END_TOKENS = frozenset({200001, 200007, 200008})  # F37


def reply_complete(tokens: Sequence[int], budget: int) -> bool:
    """A nonempty reply stops at its first end token or exhausts the holder's budget."""
    return (
        1 <= len(tokens) <= budget
        and END_TOKENS.isdisjoint(tokens[:-1])
        and (tokens[-1] in END_TOKENS or len(tokens) == budget)
    )


def _token_ids(ids: Sequence[int]) -> tuple[int, ...]:
    if isinstance(ids, (str, bytes, bytearray, memoryview)) or not isinstance(
        ids, Sequence
    ):
        raise TypeError("expected a sequence of integer token IDs")
    if not 1 <= len(ids) <= WINDOW:
        raise ValueError("prompt and reply must each contain 1 to 1024 IDs")
    values = tuple(ids)
    if any(
        type(token) is not int or not 0 <= token < VOCABULARY_SIZE for token in values
    ):
        raise ValueError("token ID outside the model vocabulary or not an integer")
    return values


def build_statement(prompt: Sequence[int], reply: Sequence[int]) -> bytes:
    """Encode the exact supplied token split. The caller verifies reply completeness."""
    prompt_ids = _token_ids(prompt)
    reply_ids = _token_ids(reply)
    used = len(prompt_ids) + len(reply_ids)
    if used > WINDOW:
        raise ValueError("prompt and reply exceed the 1024-token window")
    tokens = prompt_ids + reply_ids + (0,) * (WINDOW - used)
    # A checked position t predicts token t+1, including the first reply token.
    return struct.pack(f"<{WINDOW + 2}I", *tokens, len(prompt_ids) - 1, used - 1)


def build_spool_request(prompt: Sequence[int], reply: Sequence[int]) -> bytes:
    """Append a fresh private nonce to the verifier statement for submission."""
    return build_statement(prompt, reply) + os.urandom(32)
