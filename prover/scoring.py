"""Prepare the exact statement for a receipted reply or its first divergent token."""

import hashlib
import struct
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol

from prover.reference import ReferenceTrace, ReferenceUnavailable
from prover.request import VOCABULARY_SIZE, WINDOW, build_statement, reply_complete
from prover.request import Divergence as Divergence  # noqa: PLC0414 -- preserve the existing public import
from prover.request import deviation_statement as deviation_statement  # noqa: PLC0414 -- preserve the existing public import
from prover.worker import Unavailable


class Scorer(Protocol):
    def score(self, tokens: tuple[int, ...]) -> ReferenceTrace: ...


@dataclass(frozen=True)
class RangeEvidence:
    statement_sha256: str = field(repr=False)
    position: int = field(repr=False)
    condition: int = field(repr=False)


@dataclass(frozen=True)
class Assessment:
    kind: Literal[
        "conformance", "deviation", "incomplete", "excused_range", "unavailable"
    ]
    statement: bytes | None = field(default=None, repr=False)
    divergence: Divergence | None = field(default=None, repr=False)
    private_range: RangeEvidence | None = field(default=None, repr=False)


def assess(
    prompt: Sequence[int],
    served: Sequence[int],
    max_tokens: int,
    scorer: Scorer,
    *,
    failure: Unavailable | None = None,
) -> Assessment:
    """Score the original padded window; proof candidates still require independent verification."""
    encoded = build_statement(prompt, served)
    if type(max_tokens) is not int or not 1 <= max_tokens <= min(
        256, WINDOW - len(prompt)
    ):
        raise ValueError("Invalid receipt budget")
    if not reply_complete(served, max_tokens):
        return Assessment("incomplete")
    if failure is not None and failure.reason != "spool_failure":
        return Assessment("unavailable")
    tokens = struct.unpack_from(f"<{WINDOW}I", encoded)
    try:
        trace = scorer.score(tokens)
    except ReferenceUnavailable:
        return Assessment("unavailable")
    if not isinstance(trace, ReferenceTrace) or not isinstance(trace.choices, tuple):
        return Assessment("unavailable")
    position, condition = trace.range_position, trace.range_condition
    if position is None:
        if condition is not None or len(trace.choices) != WINDOW:
            return Assessment("unavailable")
    elif (
        type(position) is not int
        or not 0 <= position < WINDOW
        or len(trace.choices) != position
        or type(condition) is not int
        or not 1 <= condition <= 8
    ):
        return Assessment("unavailable")
    if any(type(v) is not int or not 0 <= v < VOCABULARY_SIZE for v in trace.choices):
        return Assessment("unavailable")
    first = len(prompt) - 1
    last = first + len(served)
    for d, actual in enumerate(trace.choices[first:last]):
        if actual != served[d]:
            diff = Divergence(d, actual)
            return Assessment(
                "deviation", deviation_statement(prompt, served, diff), diff
            )
    if position is not None:
        if position >= last and condition is not None and failure is not None:
            evidence = RangeEvidence(
                hashlib.sha256(encoded).hexdigest(), position, condition
            )
            return Assessment("excused_range", private_range=evidence)
        return Assessment("unavailable")
    return (
        Assessment("conformance", encoded)
        if failure is None
        else Assessment("unavailable")
    )
