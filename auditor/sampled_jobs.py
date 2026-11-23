"""Reconcile authenticated selections and auditor custody into private audit jobs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, cast

import rfc8785

from auditor.selections import Selections
from escrow.mailbox import AuditorInbox
from escrow.store import Binding
from gateway.renderer import (
    CHAT_PROFILE_DIGEST,
    RAW_PROFILE_DIGEST,
    ChatRenderer,
    raw_ids,
)
from log.monitor import LogMonitor
from log.receipt import checked_public_leaf, params_digest, transcript_commitment
from prover.request import WINDOW
from prover.submission import COMMITMENT


class SampleJobs(Protocol):
    def has_selected_custody(self, leaf_hash: str, job: str) -> bool: ...

    def enqueue_sample(
        self,
        *,
        leaf_hash: str,
        transcript: str,
        served_at: datetime,
        prompt: tuple[int, ...],
        reply: tuple[int, ...],
        budget: int,
        original_transcript: bytes | None = None,
        envelope_digest: bytes | None = None,
    ) -> str: ...
    def sample_unavailable(
        self,
        *,
        leaf_hash: str,
        transcript: str,
        served_at: datetime,
        reason: str,
        original_transcript: bytes | None = None,
        envelope_digest: bytes | None = None,
    ) -> str: ...


@dataclass(frozen=True)
class SampleCursor:
    next_index: int
    horizon: int


def _transcript(
    data: bytes,
    leaf: dict[str, object],
    renderer: ChatRenderer,
) -> tuple[tuple[int, ...], tuple[int, ...], int]:
    # Gateway escrow stores the canonical JCS material. Exact bytes also reject
    # duplicate fields, ambiguous numbers and alternate interpretations.
    value = json.loads(data.decode("utf-8"))
    if not isinstance(value, dict) or rfc8785.dumps(value) != data:
        raise ValueError("Invalid private material")
    prompt, reply = (
        raw_ids(value["prompt_token_ids"]),
        raw_ids(value["reply_token_ids"]),
    )
    budget = value["max_tokens"]
    profile = leaf["render_profile"]
    if (
        type(budget) is not int
        or not 1 <= budget <= min(256, WINDOW - len(prompt))
        or len(reply) > budget
        or leaf["commitment_id"] != COMMITMENT
        or leaf["params_digest"] != params_digest(budget)
        or not isinstance(profile, str)
        or transcript_commitment(
            COMMITMENT, profile, budget, value["salt"], prompt, reply
        )
        != leaf["transcript_commitment"]
    ):
        raise ValueError("Private material differs from signed transcript")
    if profile == RAW_PROFILE_DIGEST:
        if "messages" in value or value["reply_text"] is not None:
            raise ValueError("Invalid raw input or display")
    elif profile == CHAT_PROFILE_DIGEST:
        if (
            renderer.render(value["messages"]) != prompt
            or renderer.decode(reply) != value["reply_text"]
        ):
            raise ValueError("Chat rendering differs from signed transcript")
    else:
        raise ValueError("Unknown render profile")
    return prompt, reply, budget


class SampleBridge:
    def __init__(
        self,
        selections: Selections,
        history: LogMonitor,
        inbox: AuditorInbox,
        jobs: SampleJobs,
        *,
        renderer: ChatRenderer,
    ) -> None:
        if selections.log_id != history.log_id:
            raise ValueError("Selection history belongs to a different log")
        self._selections, self._history, self._inbox = selections, history, inbox
        self._jobs, self._renderer = jobs, renderer

    def poll(
        self, cursor: SampleCursor | None = None, *, limit: int
    ) -> SampleCursor | None:
        """Process a bounded page. After None start another pass to revisit pending leaves."""
        start = cursor.next_index if cursor else 0
        if cursor and (
            type(cursor.horizon) is not int or not 0 <= start < cursor.horizon
        ):
            raise ValueError("Invalid sample cursor")
        page = self._selections.page(start, limit)
        size = page["indexed_size"]
        horizon = cursor.horizon if cursor else size
        if horizon > size:
            raise ValueError("Selection history shrank")
        if start == horizon:
            return None
        head = page["checkpoint"]
        if (
            head is None
            or head["tree_size"] < horizon
            or self._history.root_at(head["tree_size"]) != head["root_hash"]
        ):
            raise ValueError("Selection checkpoint differs from signed log")
        stop = min(start + limit, horizon)
        records = page["selections"][: stop - start]
        if len(records) != stop - start:
            raise ValueError("Selection history has a missing record")
        for index, record in enumerate(records, start):
            if record["leaf_index"] != index:
                raise ValueError("Selection index differs from signed log")
            if record["selected"] is True:
                self._reconcile(index, record)
        return SampleCursor(stop, horizon) if stop < horizon else None

    def _reconcile(self, index: int, record: dict[str, object]) -> None:
        leaf = checked_public_leaf(
            self._history.verified_leaf(index), index=index, log_id=self._history.log_id
        )
        if (
            not record["beacon_signature"]
            or record["status"] not in ("selected", "pending", "gap")
            or any(
                record[k] != leaf[k]
                for k in (
                    "leaf_hash",
                    "transcript_commitment",
                    "sampling_mode",
                    "beacon_round",
                )
            )
        ):
            raise ValueError("Selected record differs from signed log")
        key = cast(str, leaf["leaf_hash"])
        transcript = cast(str, leaf["transcript_commitment"])
        served = cast(str, leaf["served_at"])
        at = datetime.fromisoformat(served[:-1] + "+00:00")
        binding = Binding(
            key,
            transcript,
            served,
            cast(int, leaf["beacon_round"]),
            cast(str, leaf["sampling_mode"]),
        )

        def commit(data: bytes, envelope_digest: bytes) -> str:
            try:
                prompt, reply, budget = _transcript(data, leaf, self._renderer)
            except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
                return self._jobs.sample_unavailable(
                    leaf_hash=key,
                    transcript=transcript,
                    served_at=at,
                    reason="invalid_material",
                    original_transcript=data,
                    envelope_digest=envelope_digest,
                )
            return self._jobs.enqueue_sample(
                leaf_hash=key,
                transcript=transcript,
                served_at=at,
                prompt=prompt,
                reply=reply,
                budget=budget,
                original_transcript=data,
                envelope_digest=envelope_digest,
            )

        job = self._inbox.handoff(binding, commit)
        if job is not None:
            if not self._jobs.has_selected_custody(key, job):
                raise ValueError("Confirmed handoff is missing from challenge custody")
        elif record["status"] != "pending":
            reason = "selection_gap" if record["status"] == "gap" else "missing_handoff"
            self._jobs.sample_unavailable(
                leaf_hash=key, transcript=transcript, served_at=at, reason=reason
            )
