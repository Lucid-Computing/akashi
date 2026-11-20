"""Verify a holder's original input and evidence against a separately trusted descriptor."""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from auditor.beacon import CHAIN_HASH, round_for
from gateway.renderer import (
    CHAT_PROFILE_DIGEST,
    RAW_PROFILE_DIGEST,
    ChatRenderer,
    raw_ids,
)
from log.receipt import (
    params_digest,
    promise_backdated,
    transcript_commitment,
    verify_promise,
)
from log.verification import verify_consistency, verify_head, verify_inclusion
from prover.request import END_TOKENS, WINDOW, reply_complete
from verifier.holder_proof import check_proof

COMMITMENT = "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46"


@dataclass(frozen=True)
class VerificationResult:
    exit_code: int
    outcome: str
    warnings: tuple[str, ...] = ()
    verifier_outcomes: tuple[str, str] | None = None

    def as_json(self) -> dict[str, object]:
        result = {"schema_version": 1, **asdict(self)}
        pair = result.pop("verifier_outcomes")
        if pair:
            result["verifier_outcomes"] = {"native": pair[0], "lean": pair[1]}
        return result


def _keys(descriptor: dict[str, Any]) -> dict[tuple[str, str], bytes]:
    log = descriptor["log"]
    current = ("log", log["log_key_id"])
    values = {current: bytes.fromhex(log["log_public_key"])}
    for row in descriptor.get("verification_keys", []):
        if row["role"] == "log":
            key = ("log", row["key_id"])
            material = bytes.fromhex(row["public_key"])
            if values.setdefault(key, material) != material or len(material) != 32:
                raise ValueError("Conflicting trusted log history")
    return values


def _history(
    history: dict[str, Any],
    digest: str,
    descriptor: dict[str, Any],
    checkpoint: dict[str, Any] | None,
) -> None:
    identity = descriptor["log"]["log_id"]
    keys = _keys(descriptor)

    def lookup(role: str, key: str) -> bytes:
        return keys[role, key]

    head = history["sth"]
    verify_head(head, log_id=identity, lookup_key=lookup)
    proof = history["inclusion"]
    if type(proof["tree_size"]) is not int or proof["tree_size"] != head["tree_size"]:
        raise ValueError("Wrong inclusion checkpoint")
    verify_inclusion(
        digest,
        proof["leaf_index"],
        head["tree_size"],
        head["root_hash"],
        proof["audit_path"],
    )
    if checkpoint is not None:
        verify_head(checkpoint, log_id=identity, lookup_key=lookup)
        consistency = history["consistency"]
        old, new = checkpoint["tree_size"], head["tree_size"]
        if (
            type(consistency["from"]) is not int
            or type(consistency["to"]) is not int
            or (consistency["from"], consistency["to"]) != (old, new)
            or checkpoint["timestamp"] > head["timestamp"]
        ):
            raise ValueError("Wrong consistency checkpoints")
        verify_consistency(
            old,
            new,
            checkpoint["root_hash"],
            head["root_hash"],
            consistency["consistency_path"],
        )


def verify(
    bundle: dict[str, Any],
    descriptor: dict[str, Any],
    checkpoint: dict[str, Any] | None = None,
    *,
    assets: Path | None = None,
    runtime: object = None,
    receipt_only: bool = False,
    now: datetime | None = None,
    observed_at: datetime | None = None,
) -> VerificationResult:
    if observed_at is not None and (
        not isinstance(observed_at, datetime) or observed_at.utcoffset() != timedelta(0)
    ):
        return VerificationResult(64, "USAGE")
    clock = now or datetime.now(timezone.utc)
    result = VerificationResult(10, "RECEIPT_INVALID")
    try:
        if (
            descriptor["version"] != "vig/1"
            or descriptor["commitment_id"] != COMMITMENT
            or descriptor["window"] != WINDOW
            or descriptor["beacon"]["chain_hash"] != CHAIN_HASH
            or descriptor["end_tokens"] != sorted(END_TOKENS)
            or type(descriptor["max_tokens_cap"]) is not int
            or not 1 <= descriptor["max_tokens_cap"] <= 256
        ):
            return result
        verification = bundle["verification"]
        receipt = verification["receipt"]
        if verification["version"] != "vig/1" or receipt["commitment_id"] != COMMITMENT:
            return result
        key_id = receipt["log_key_id"]
        verify_promise(
            receipt,
            log_id=descriptor["log"]["log_id"],
            log_key_id=key_id,
            public_key=_keys(descriptor)["log", key_id],
        )
        served = datetime.fromisoformat(receipt["served_at"].replace("Z", "+00:00"))
        if receipt["beacon_round"] != round_for(served):
            return result
        original = bundle["input"]
        budget = bundle["max_tokens"]
        if (
            type(budget) is not int
            or not 1 <= budget <= descriptor["max_tokens_cap"]
            or receipt["params_digest"] != params_digest(budget)
        ):
            return result
        chat = receipt["render_profile"] == CHAT_PROFILE_DIGEST
        profile = CHAT_PROFILE_DIGEST if chat else RAW_PROFILE_DIGEST
        name = "llama4-chat/1" if chat else "raw-ids/1"
        result = VerificationResult(11, "RENDER_MISMATCH")
        if receipt["render_profile"] != profile or not any(
            item["profile"] == name and item["digest"] == profile
            for item in descriptor["render_profiles"]
        ):
            return result
        renderer = None
        if chat:
            if assets is None:
                return VerificationResult(30, "ASSETS_UNAVAILABLE")
            try:
                renderer = ChatRenderer(assets)
            except (OSError, ValueError):
                return VerificationResult(30, "ASSETS_UNAVAILABLE")
        prompt = renderer.render(original) if renderer else raw_ids(original)
        if prompt != raw_ids(verification["prompt_token_ids"]):
            return result
        result = VerificationResult(10, "RECEIPT_INVALID")
        if verification["reply_token_ids"] == []:
            return VerificationResult(13, "INCOMPLETE")
        reply = raw_ids(verification["reply_token_ids"])
        if receipt["transcript_commitment"] != transcript_commitment(
            COMMITMENT, profile, budget, receipt["salt"], prompt, reply
        ):
            return result
        if bundle["text"] != (renderer.decode(reply) if renderer else None):
            return VerificationResult(12, "TEXT_MISMATCH")
        # A delivery witness belongs to the holder, separately from the bundle.
        warnings: tuple[str, ...] = (
            ("PROMISE_BACKDATED",)
            if observed_at is not None and promise_backdated(served, observed_at)
            else ()
        )
        history = bundle.get("history", {})
        if not isinstance(history, dict):
            return result
        if history.get("sth") is None or history.get("inclusion") is None:
            # Absence of a bundled path alone does not establish omission by the log.
            overdue = clock > served + timedelta(seconds=10)
            return VerificationResult(
                30,
                "INCLUSION_UNAVAILABLE",
                warnings + (("MERGE_DEADLINE_ELAPSED",) if overdue else ()),
            )
        if (
            not isinstance(history["sth"], dict)
            or history["sth"].get("timestamp", "") < receipt["served_at"]
        ):
            return result
        if checkpoint is not None and "consistency" not in history:
            return VerificationResult(30, "CONSISTENCY_UNAVAILABLE", warnings)
        _history(history, receipt["leaf_hash"], descriptor, checkpoint)
        warnings += (
            ("CHALLENGE_WINDOW_EXPIRED",)
            if clock >= served + timedelta(days=30)
            else ()
        )
        if not reply_complete(reply, budget):
            return VerificationResult(13, "INCOMPLETE", warnings)
        if receipt_only:
            return VerificationResult(30, "RECEIPT_VERIFIED", warnings)
        discrepancy: tuple[str, str] | None = None

        def record(primary: str, secondary: str) -> None:
            nonlocal discrepancy
            discrepancy = primary, secondary

        code, label = check_proof(
            prompt,
            reply,
            budget,
            bundle.get("proof"),
            runtime=runtime,
            record_disagreement=record,
        )
        return VerificationResult(code, label, warnings, discrepancy)
    except (
        KeyError,
        ValueError,
        TypeError,
        AttributeError,
        OverflowError,
    ):
        return result
