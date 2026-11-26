"""Prepare role-private independent scoring evidence for the M2 substituted reply."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

from engine.mock import MockEngine
from prover.reference import ReferenceScorer, ReferenceTrace
from prover.request import WINDOW, build_statement
from prover.runtime import REVISION
from prover.scoring import Scorer, assess
from prover.submission import COMMITMENT

_LAYOUT = struct.Struct(f"<{WINDOW + 2}I")


class BoundTrace:
    """Replay only the exact padded tokens scored by the independent reference role."""

    def __init__(self, inputs: tuple[int, ...], trace: ReferenceTrace) -> None:
        self.inputs = inputs
        self.trace = trace

    def score(self, tokens: tuple[int, ...]) -> ReferenceTrace:
        if tokens != self.inputs:
            raise ValueError("Reference record belongs to a different input")
        return self.trace


def observe(original: bytes, scorer: Scorer) -> dict[str, object]:
    words = _LAYOUT.unpack(original)
    start, end = words[-2:]
    if not 0 <= start < end < WINDOW or end != start + 1:
        raise ValueError("The M2 fixture requires one claimed reply token")
    prompt, reply = words[: start + 1], words[start + 1 : end + 1]
    if build_statement(prompt, reply) != original:
        raise ValueError("Noncanonical captured statement")
    substitute = MockEngine().generate(prompt, 1).tokens
    changed = build_statement(prompt, substitute)
    if changed == original:
        raise ValueError("Substitute fixture agrees with the original")
    inputs = _LAYOUT.unpack(changed)[:WINDOW]
    trace = scorer.score(inputs)
    diagnosis = assess(prompt, substitute, 1, BoundTrace(inputs, trace))
    if (
        diagnosis.kind != "deviation"
        or diagnosis.divergence is None
        or diagnosis.statement != original
        or diagnosis.divergence.index != 0
    ):
        raise ValueError("Reference did not establish the corrected statement")
    return {
        "schema_version": 1,
        "flashprove_revision": REVISION,
        "commitment_id": COMMITMENT,
        "original_statement_sha256": hashlib.sha256(original).hexdigest(),
        "substitute_statement_sha256": hashlib.sha256(changed).hexdigest(),
        "choices": list(trace.choices),
        "range_position": trace.range_position,
        "range_condition": trace.range_condition,
    }


def host_id() -> str:
    machine = Path("/etc/machine-id").read_bytes().strip()
    if len(machine) != 32 or any(c not in b"0123456789abcdef" for c in machine):
        raise ValueError("Missing Linux machine identity")
    return hashlib.sha256(b"akashi/m2-host/1" + machine).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("model", "manifest", "rebuild", "statement", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    scorer = ReferenceScorer.load(
        args.model, args.manifest, rebuild_report=args.rebuild
    )
    record = observe(args.statement.read_bytes(), scorer)
    record["source_host"] = host_id()
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, separators=(",", ":"))
    print("Independent F4 scorer established the first divergent token.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
