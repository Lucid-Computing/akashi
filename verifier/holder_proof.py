"""Decode bounded holder-supplied proof evidence and check it against a trusted runtime."""

from __future__ import annotations

import base64
import importlib
import math
from collections.abc import Callable, Mapping
from pathlib import Path

from prover.request import VOCABULARY_SIZE, WINDOW, CandidateProof, Divergence

_REJECTED = (20, "PROOF_REJECTED")
_UNAVAILABLE = (30, "NO_VERDICT")
_FIELDS = {"kind", "statement", "proof"}
_NATIVE = {
    "binary",
    "manifest",
    "config_dir",
    "public_key_dir",
    "timeout_seconds",
    "memory_bytes",
    "max_proof_bytes",
}


def _hex(value: object, size: int) -> bytes:
    if not isinstance(value, str) or len(value) != 2 * size:
        raise ValueError("Invalid proof field")
    result = bytes.fromhex(value)
    if result.hex() != value:
        raise ValueError("Invalid proof field")
    return result


def _proof_bytes(value: object, limit: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) % 4:
        raise ValueError("Invalid proof encoding")
    padding = 2 if value.endswith("==") else int(value.endswith("="))
    if len(value) // 4 * 3 - padding > limit:
        raise ValueError("Proof exceeds configured limit")
    proof = base64.b64decode(value, validate=True)
    if not proof or base64.b64encode(proof).decode("ascii") != value:
        raise ValueError("Invalid proof encoding")
    return proof


def _check_evidence(
    evidence: object,
    reply: tuple[int, ...],
    *,
    max_proof_bytes: int,
    verify: Callable[[CandidateProof, Divergence | None], str],
) -> tuple[int, str]:
    if evidence is None:
        return _UNAVAILABLE
    if not isinstance(evidence, Mapping):
        return _REJECTED
    kind = evidence.get("kind")
    divergence = None
    if kind == "deviation" and evidence.keys() - {"y"} == _FIELDS | {
        "index",
        "expected",
    }:
        index, expected = evidence["index"], evidence["expected"]
        if (
            type(index) is not int
            or not 0 <= index < len(reply)
            or type(expected) is not int
            or not 0 <= expected < VOCABULARY_SIZE
            or reply[index] == expected
        ):
            return _REJECTED
        divergence = Divergence(index, expected)
    elif kind != "conformance" or evidence.keys() - {"y"} != _FIELDS:
        return _REJECTED
    try:
        if evidence.get("y", "00000000") != "00000000":
            return _REJECTED
        candidate = CandidateProof(
            _hex(evidence["statement"], (WINDOW + 2) * 4),
            bytes(4),
            _proof_bytes(evidence["proof"], max_proof_bytes),
        )
    except ValueError:
        return _REJECTED
    try:
        outcome = verify(candidate, divergence)
    except Exception:  # noqa: BLE001 -- tooling failures carry only a bounded no-verdict result.
        return _UNAVAILABLE
    if outcome == "verified":
        return (0, "CONFORMS") if divergence is None else (21, "DEVIATES")
    if outcome in ("rejected", "statement_mismatch"):
        return _REJECTED
    if outcome == "disagreement":
        return 30, "VERIFIER_DISAGREEMENT"
    if outcome == "incomplete":
        return 13, "INCOMPLETE"
    return _UNAVAILABLE


def _path(value: object) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError("Absolute verifier paths required")
    return Path(value)


def _timeout(value: object) -> float:
    if (
        not isinstance(value, (float, int))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError("Positive finite verifier timeout required")
    return float(value)


def check_proof(
    prompt: tuple[int, ...],
    reply: tuple[int, ...],
    budget: int,
    evidence: object,
    *,
    runtime: object,
    record_disagreement: Callable[[str, str], None] | None = None,
) -> tuple[int, str]:
    """Check an exact or corrected-prefix statement through the pinned #25 adapter."""
    if not isinstance(runtime, Mapping):
        return _UNAVAILABLE
    bounds = {"timeout_seconds", "memory_bytes", "max_proof_bytes"}
    if runtime.keys() - {"lean"} == bounds:
        native = Path(__file__).resolve().parent / "native"
        runtime = {
            **runtime,
            "binary": str(native / "cp_verify"),
            "manifest": str(native / "manifest.json"),
            "config_dir": str(native / "config"),
            "public_key_dir": str(native / "ivk"),
        }
    if runtime.keys() - {"lean"} != _NATIVE:
        return _UNAVAILABLE
    limit, memory = runtime.get("max_proof_bytes"), runtime.get("memory_bytes")
    if type(limit) is not int or limit <= 0 or type(memory) is not int or memory <= 0:
        return _UNAVAILABLE

    def verify(candidate: CandidateProof, divergence: Divergence | None) -> str:
        # The independently released native backend is optional on receipt-only hosts.
        backend = importlib.import_module("verifier.proof")
        primary = backend.NativeVerifier(
            _path(runtime["binary"]),
            _path(runtime["manifest"]),
            _path(runtime["config_dir"]),
            _path(runtime["public_key_dir"]),
            _timeout(runtime["timeout_seconds"]),
            memory,
            limit,
        )
        secondary = None
        if "lean" in runtime:
            config = runtime["lean"]
            if not isinstance(config, Mapping) or config.keys() != {
                "checkout",
                "lake",
                "temp",
                "timeout_seconds",
            }:
                raise ValueError("Invalid secondary verifier configuration")
            lean = importlib.import_module("verifier.lean")
            secondary = backend.LeanVerifier(
                primary,
                lean.LeanConfig(
                    _path(config["checkout"]),
                    _path(config["lake"]),
                    _path(config["temp"]),
                ),
                _timeout(config["timeout_seconds"]),
            )
        result = backend.verify_reply(
            prompt,
            reply,
            budget,
            candidate,
            primary,
            divergence=divergence,
            secondary=secondary,
        )
        if result.outcome == "disagreement" and record_disagreement is not None:
            outcomes = ("verified", "rejected", "unavailable")
            if (
                result.primary not in outcomes
                or result.secondary not in outcomes
                or result.primary == result.secondary
            ):
                return "unavailable"
            record_disagreement(result.primary, result.secondary)
        return str(result.outcome)

    return _check_evidence(evidence, reply, max_proof_bytes=limit, verify=verify)
