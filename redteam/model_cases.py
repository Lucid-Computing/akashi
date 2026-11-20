"""Classify fixed public toy transcripts for R1–R9 and R18.

The corpus supplies synthetic token choices and F9 terminal records. Scenario
names identify the regression contract; no alternative model or native proof
was run to produce these records.
"""

import hashlib
import json
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from auditor.beacon import select_round
from gateway.renderer import RAW_PROFILE_DIGEST
from log.receipt import transcript_commitment
from prover.reference import ReferenceTrace
from prover.request import WINDOW, build_statement
from prover.scoring import assess
from prover.submission import COMMITMENT
from prover.worker import CandidateProof
from tests.test_beacon import INFO, LATER
from tests.test_proof_verification import _POLICY, _PROOF
from verifier.native_output import Outcome, native_outcome
from verifier.proof import verify_reply

_FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures"
_CORPUS = "model-outcomes-v1.jsonl"
_RECORDS = "model-f9-records-v1.json"
_INVENTORY = {
    _CORPUS: "93d5e4e0453d25560453e1e4fd09caf303995bf617095251ac38ebe82c5ad905",
    _RECORDS: "4ed1bc0df41aa9c4bd4f719c8b33f6313a67fde63a463ccfd890853652db3d0e",
}
_SCENARIOS = ("R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R18")
_WORDS = struct.Struct(f"<{WINDOW}I")


def _read(name: str) -> bytes:
    data = (_FIXTURES / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != _INVENTORY[name]:
        raise ValueError(
            "Public model regression fixture differs from pinned inventory"
        )
    return data


@dataclass
class _RecordedTrace:
    input_digest: str
    trace: ReferenceTrace
    calls: int = 0

    def score(self, tokens: tuple[int, ...]) -> ReferenceTrace:
        self.calls += 1
        if hashlib.sha256(_WORDS.pack(*tokens)).hexdigest() != self.input_digest:
            raise ValueError("Reference trace belongs to a different fixture input")
        return self.trace


@dataclass(frozen=True)
class _RecordedF9:
    records: dict[str, str]
    statement_digest: str | None

    def check(self, statement: bytes, y: bytes, proof: bytes) -> Outcome:
        if (
            hashlib.sha256(statement).hexdigest() != self.statement_digest
            or y != bytes(4)
            or proof != _PROOF
        ):
            return "rejected"
        start, end = struct.unpack_from("<II", statement, _WORDS.size)
        output = self.records[f"{start},{end}"].encode("ascii")
        return native_outcome(0, output, statement, proof, _POLICY)


def _evaluate(
    prompt: tuple[int, ...],
    reply: tuple[int, ...],
    budget: int,
    choices: tuple[int, ...],
    input_digest: str,
    statement_digest: str | None,
    index: int | None,
    records: dict[str, str],
) -> str:
    # The compact corpus stores the choices over reply positions. The other
    # positions of this public toy trace have the recorded constant value zero.
    start = len(prompt) - 1
    trace = ReferenceTrace(
        (0,) * start + choices + (0,) * (WINDOW - start - len(choices))
    )
    scorer = _RecordedTrace(input_digest, trace)
    plan = assess(prompt, reply, budget, scorer)
    checker = _RecordedF9(records, statement_digest)
    if plan.kind == "incomplete":
        proof_check = verify_reply(prompt, reply, budget, None, checker)
        if (
            scorer.calls == 0
            and plan.statement is None
            and proof_check.outcome == "incomplete"
        ):
            return "INCOMPLETE"
        return "INCONSISTENT_INCOMPLETE"
    if (
        scorer.calls != 1
        or plan.statement is None
        or plan.kind not in {"conformance", "deviation"}
    ):
        return "NO_VERDICT"
    if (plan.kind == "conformance") != (plan.divergence is None):
        return "NO_VERDICT"
    if (plan.divergence.index if plan.divergence else None) != index:
        return "WRONG_FIRST_DIFFERENCE"
    evidence = CandidateProof(plan.statement, bytes(4), _PROOF)
    checked = verify_reply(
        prompt, reply, budget, evidence, checker, divergence=plan.divergence
    )
    if checked.outcome != "verified":
        return "PROOF_POLICY_MISMATCH"
    if plan.divergence is None:
        return "CONFORMS"
    # The uncorrected served statement must never substantiate first divergence.
    stale = CandidateProof(build_statement(prompt, reply), bytes(4), _PROOF)
    refused = verify_reply(
        prompt, reply, budget, stale, checker, divergence=plan.divergence
    )
    return (
        "DEVIATES"
        if refused.outcome == "statement_mismatch"
        else "STALE_STATEMENT_ACCEPTED"
    )


def _honest(
    row: dict[str, Any], records: dict[str, str], *, long_prompt: bool = False
) -> str:
    prompt = tuple(row["long_prompt" if long_prompt else "prompt"])
    reply = tuple(row["honest_reply"])
    digest = row[
        "long_honest_statement_sha256"
        if long_prompt
        else "short_honest_statement_sha256"
    ]
    encoded = build_statement(prompt, reply)
    return _evaluate(
        prompt,
        reply,
        row["budget"],
        reply,
        hashlib.sha256(encoded[: _WORDS.size]).hexdigest(),
        digest,
        None,
        records,
    )


def _selected(
    row: dict[str, Any], prompt: tuple[int, ...], reply: tuple[int, ...]
) -> bool:
    # This public fixture salt is fixed before selection and holds no secrets.
    salt = hashlib.sha256(row["case"].encode("ascii")).hexdigest()
    binding = transcript_commitment(
        COMMITMENT, RAW_PROFILE_DIGEST, row["budget"], salt, prompt, reply
    )
    return select_round(bytes.fromhex(binding), 1_000_000, INFO, LATER)[1]


def run_model_cases() -> list[dict[str, object]]:
    """Run paired examples through completion, first-divergence and verifier policies."""
    rows = [json.loads(line) for line in _read(_CORPUS).splitlines()]
    f9 = json.loads(_read(_RECORDS))
    if (
        len({r["case"] for r in rows}) != 20
        or len(rows) != 20
        or f9["kind"] != "synthetic-f9-output-policy"
    ):
        raise ValueError("Unexpected public model corpus dimensions")
    records = f9["records"]
    result = []
    for name in _SCENARIOS:
        expected = "INCOMPLETE" if name == "R8" else "DEVIATES"
        observed: Counter[str] = Counter()
        honest: Counter[str] = Counter()
        selected = short_controls = short_conforms = 0
        for row in rows:
            is_long = name == "R18"
            prompt = tuple(row["long_prompt"] if is_long else row["prompt"])
            candidate = row["candidates"][name]
            reply = tuple(candidate["reply"])
            control = _honest(row, records, long_prompt=is_long)
            honest[control] += 1
            if is_long:
                short_controls += 1
                short = _evaluate(
                    tuple(row["prompt"]),
                    tuple(candidate["short_reply"]),
                    row["budget"],
                    tuple(row["honest_reply"]),
                    candidate["short_input_sha256"],
                    row["short_honest_statement_sha256"],
                    None,
                    records,
                )
                if short != "CONFORMS":
                    observed["SHORT_CONTROL_FAILED"] += 1
                    continue
                short_conforms += 1
                if not _selected(row, prompt, reply):
                    observed["NOT_SELECTED"] += 1
                    continue
                selected += 1
            outcome = _evaluate(
                prompt,
                reply,
                row["budget"],
                tuple(candidate["choices"]),
                candidate["input_sha256"],
                candidate["corrected_sha256"],
                candidate["first_difference"],
                records,
            )
            observed[outcome] += 1
        summary: dict[str, object] = {
            "scenario": name,
            "trials": observed.total(),
            "caught": observed[expected],
            "expected": expected,
            "observed": dict(observed),
            "honest_controls": honest.total(),
            "honest_passed": honest["CONFORMS"],
            "honest_expected": "CONFORMS",
            "honest_observed": dict(honest),
        }
        if name == "R18":
            summary.update(
                selected_long=selected,
                short_controls=short_controls,
                short_conforms=short_conforms,
                selection_divisor=1,
            )
        result.append(summary)
    return result
