"""Offline R10–R15 checks against named public rendering and terminal-output fixtures.

R14 and R15 exercise the holder's statement and F9 result policies. Their fixture
has no cryptographic proof of model execution.
"""

import base64
import hashlib
import json
import secrets
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from auditor.intake import ChallengeIntake, IntakeError
from escrow.store import EscrowStore
from gateway.commit_delivery import DeliveryCommitter
from gateway.discovery import ServiceConfig
from gateway.policy import InferenceRequest
from gateway.renderer import ChatRenderer
from log.receipt import leaf_hash
from log.store import MerkleLog
from prover.request import build_statement
from prover.scoring import Divergence
from prover.submission import COMMITMENT
from prover.worker import CandidateProof
from tests.test_discovery import CONFIG
from tests.test_proof_verification import _OUTPUT, _POLICY, _PROOF
from verifier.holder import verify
from verifier.holder_proof import _check_evidence
from verifier.native_output import Outcome, native_outcome
from verifier.proof import verify_reply

_CORPUS = (
    Path(__file__).resolve().parents[1] / "tests/fixtures/render-goldens/chat.jsonl"
)
_CORPUS_SHA = "c07f80636fff3daaa26eb0417d49f70087b82a7b4b512c91aa7c9d62395dbd72"
_CASES = (
    "arithmetic-change",
    "arithmetic-mean",
    "arithmetic-minutes",
    "kitchen-whisk",
    "kitchen-oven",
    "kitchen-bread",
    "library-spine",
    "library-edition",
    "library-genre",
    "geography-scale",
    "geography-delta",
    "geography-legend",
    "music-count",
    "music-interval",
    "music-voice",
    "garden-sprout",
    "garden-water",
    "garden-pollinators",
    "editing-plural",
    "editing-tense",
)
_NOW = datetime(2025, 5, 8, 12, tzinfo=timezone.utc)
_HONEST = "30/RECEIPT_VERIFIED"
_FOREIGN_RECORD = _OUTPUT.replace(COMMITMENT.encode("ascii"), b"0" * 64)


@dataclass
class _Observations:
    scenario: str
    expected: str
    honest_expected: str
    observed: Counter[str] = field(default_factory=Counter)
    honest_observed: Counter[str] = field(default_factory=Counter)

    def record(self, actual: str, honest: str) -> None:
        self.observed[actual] += 1
        self.honest_observed[honest] += 1

    def report(self) -> dict[str, object]:
        return {
            "scenario": self.scenario,
            "trials": sum(self.observed.values()),
            "caught": self.observed[self.expected],
            "expected": self.expected,
            "observed": dict(self.observed),
            "honest_controls": sum(self.honest_observed.values()),
            "honest_passed": self.honest_observed[self.honest_expected],
            "honest_expected": self.honest_expected,
            "honest_observed": dict(self.honest_observed),
        }


def _intake(
    service: ChallengeIntake, subject: str, bundle: dict[str, Any], index: int
) -> str:
    try:
        result = service.submit(subject, bundle, index)
    except IntakeError as error:
        if (error.status, error.code) == (400, "invalid_bundle"):
            return "400/invalid_bundle"
        return "unexpected_intake_result"
    return (
        "accepted/pending"
        if result.get("status") == "pending"
        else "unexpected_intake_result"
    )


def _holder(bundle: dict[str, Any], descriptor: dict[str, Any], assets: Path) -> str:
    result = verify(bundle, descriptor, assets=assets, now=_NOW, receipt_only=True)
    if (result.exit_code, result.outcome) in (
        (30, "RECEIPT_VERIFIED"),
        (11, "RENDER_MISMATCH"),
        (12, "TEXT_MISMATCH"),
        (10, "RECEIPT_INVALID"),
        (30, "ASSETS_UNAVAILABLE"),
    ):
        return f"{result.exit_code}/{result.outcome}"
    return "unexpected_holder_result"


@dataclass(frozen=True)
class _ResultRecord:
    output: bytes

    def check(self, statement: bytes, y: bytes, proof: bytes) -> Outcome:
        if proof != _PROOF or y != bytes(4):
            return "rejected"
        return native_outcome(0, self.output, statement, proof, _POLICY)


def _proof_policy(index: int, *, adjacent: bool = False, foreign: bool = False) -> str:
    # All fixed CPU policy cases use the published test record's r=1, e=3.
    # Neighboring test rows have the same shape and different public inputs.
    prompt, reply = (3, 4 + index), (5, 6)
    other = (index + 1) % len(_CASES) if adjacent else index
    evidence = {
        "kind": "conformance",
        "statement": build_statement((3, 4 + other), reply).hex(),
        "proof": base64.b64encode(_PROOF).decode("ascii"),
    }
    record = _ResultRecord(_FOREIGN_RECORD if foreign else _OUTPUT)

    def check(candidate: CandidateProof, divergence: Divergence | None) -> str:
        return verify_reply(
            prompt, reply, 2, candidate, record, divergence=divergence
        ).outcome

    code, outcome = _check_evidence(
        evidence, reply, max_proof_bytes=len(_PROOF), verify=check
    )
    return f"{code}/{outcome}"


def run_cases(assets: Path) -> list[dict[str, object]]:
    """Check twenty fixed public pairs per scenario and return counts only."""
    data = _CORPUS.read_bytes()
    if hashlib.sha256(data).hexdigest() != _CORPUS_SHA:
        raise ValueError("Public rendering corpus differs from its pinned inventory")
    rows = {r["id"]: r for r in map(json.loads, data.splitlines())}
    renderer = ChatRenderer(assets)
    results = [
        _Observations(
            "R10",
            "11/RENDER_MISMATCH + 400/invalid_bundle",
            _HONEST + " + accepted/pending",
        ),
        _Observations("R11", "11/RENDER_MISMATCH", _HONEST),
        _Observations("R12", "12/TEXT_MISMATCH", _HONEST),
        _Observations("R13", "10/RECEIPT_INVALID", _HONEST),
        _Observations("R14", "20/PROOF_REJECTED", "0/CONFORMS"),
        _Observations("R15", "30/NO_VERDICT", "0/CONFORMS"),
    ]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        signer = Ed25519PrivateKey.generate()
        config = ServiceConfig(
            **{**CONFIG, "log_public_key": signer.public_key().public_bytes_raw().hex()}
        )
        public = config.descriptor()

        def clock() -> datetime:
            return _NOW

        log = MerkleLog(
            root / "log.sqlite",
            log_id=config.log_id,
            log_key_id=config.log_key_id,
            signing_key=signer,
            leaf_hash=leaf_hash,
            clock=clock,
        )
        recipient = PrivateKey.generate()
        escrow = EscrowStore(
            root / "escrow.sqlite",
            wrapping_key=secrets.token_bytes(32),
            auditor_public_key=bytes(recipient.public_key),
            clock=clock,
        )
        delivery = DeliveryCommitter(
            config,
            endpoint_id="public-corpus-fixture",
            sampling_mode="live",
            stage=escrow.stage,
            append=log.append,
            clock=clock,
        )
        intake = ChallengeIntake(
            root / "intake.sqlite",
            descriptor=public,
            assets=assets,
            auditor_public_key=bytes(recipient.public_key),
            holder_hmac_key=secrets.token_bytes(32),
            clock=clock,
        )
        for index, name in enumerate(_CASES):
            row = rows[name]
            messages = row["messages"]
            prompt, reply = tuple(row["prompt_ids"]), tuple(row["reply_ids"])
            if (
                [m["role"] for m in messages] != ["system", "user"]
                or renderer.render(messages) != prompt
                or renderer.decode(reply) != row["reply_text"]
            ):
                raise ValueError(
                    "Public render fixture differed from the pinned profile"
                )
            req = InferenceRequest(
                config.model, "chat", prompt, len(reply), False, False
            )
            receipt = delivery.commit(
                delivery.prepare(
                    req, reply, original_chat=messages, reply_text=row["reply_text"]
                ),
                guard=lambda: None,
            )
            head = log.head()
            size = cast(int, head["tree_size"])
            honest: dict[str, Any] = {
                "verification": receipt,
                "max_tokens": len(reply),
                "input": messages,
                "text": row["reply_text"],
                "history": {
                    "sth": head,
                    "inclusion": {
                        "tree_size": size,
                        "leaf_index": index,
                        "audit_path": [n.hex() for n in log.path(index, size)],
                    },
                },
            }
            # The signed record is the published two-message conversation. The
            # holder fixture presents the preexisting user message alone.
            user_only = {**honest, "input": [messages[1]]}
            subject = "corpus-" + name
            results[0].record(
                _holder(user_only, public, assets)
                + " + "
                + _intake(intake, subject, user_only, index),
                _holder(honest, public, assets)
                + " + "
                + _intake(intake, subject, honest, index),
            )
            # All twenty pinned two-message snapshots end with the same
            # assistant generation header. The upstream template with
            # add_generation_prompt=False emits exactly the preceding IDs.
            if prompt[-4:] != (200005, 140680, 200006, 368):
                raise ValueError("Unexpected fixture generation header")
            no_header = {**receipt, "prompt_token_ids": list(prompt[:-4])}
            results[1].record(
                _holder({**honest, "verification": no_header}, public, assets),
                _holder(honest, public, assets),
            )
            results[2].record(
                _holder({**honest, "text": "[display fixture]"}, public, assets),
                _holder(honest, public, assets),
            )
            invalid = {
                **receipt,
                "receipt": {
                    **cast(dict[str, object], receipt["receipt"]),
                    "promise_sig": "00" * 64,
                },
            }
            results[3].record(
                _holder({**honest, "verification": invalid}, public, assets),
                _holder(honest, public, assets),
            )
            results[4].record(_proof_policy(index, adjacent=True), _proof_policy(index))
            results[5].record(_proof_policy(index, foreign=True), _proof_policy(index))
    return [result.report() for result in results]
