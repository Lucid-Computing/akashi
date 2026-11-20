"""Independently check final signed log history, beacon draws and verdicts."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from auditor.selection_record import evaluate
from auditor.verdict_signing import verify_signed
from log.receipt import checked_public_leaf, params_digest
from log.verification import verify_head, verify_inclusion
from prover.submission import COMMITMENT
from soak.ledger import CASES, GOOD, WORKLOAD, require

HEX = re.compile(r"^[0-9a-f]{64}$")


def reconcile(
    attempts: list[tuple[int, str, dict[str, Any]]],
    archive: dict[str, Any],
    *,
    descriptor: dict[str, Any],
    lookup: Callable[[str, str], bytes],
) -> dict[str, object]:
    identity = descriptor["log"]["log_id"]
    head = verify_head(archive["head"], log_id=identity, lookup_key=lookup)
    size = head["tree_size"]
    if type(size) is not int:
        raise ValueError("Invalid signed tree size")
    require(
        type(size) is int and size > 0 and len(archive["leaves"]) == size,
        "Incomplete signed history",
    )
    now = datetime.now(timezone.utc)
    cases = {c: 0 for c in CASES}
    outcomes: Counter[str] = Counter()
    lengths: list[int] = []
    padding: list[int] = []
    commitments: set[str] = set()
    signed_ids: set[str] = set()
    served = holder_checks = unwarranted = 0
    for number, (seq, shape, holder) in enumerate(attempts):
        require(
            number == seq and shape == CASES[seq % len(CASES)],
            "Missing or reordered workload attempt",
        )
        if holder["status"] == "unwarranted":
            require(holder.get("http_status") == 502, "Unexplained gateway rejection")
            unwarranted += 1
            continue
        require(holder["status"] in GOOD, "Unexplained or unverified holder outcome")
        require(
            holder["leaf_index"] == served and type(holder["leaf_index"]) is int,
            "Holder leaf is not contiguous",
        )
        row = archive["leaves"][served]
        leaf = checked_public_leaf(row["leaf"], index=served, log_id=identity)
        require(
            leaf["commitment_id"] == COMMITMENT
            and leaf["sampling_mode"] == "soak"
            and holder["leaf_hash"] == leaf["leaf_hash"]
            and holder["transcript_commitment"] == leaf["transcript_commitment"],
            "Holder and signed history disagree",
        )
        verify_inclusion(
            str(leaf["leaf_hash"]),
            served,
            size,
            str(head["root_hash"]),
            row["audit_path"],
        )
        transcript = str(leaf["transcript_commitment"])
        require(transcript not in commitments, "Repeated salted transcript commitment")
        commitments.add(transcript)
        chosen = evaluate(
            served,
            leaf,
            mode="soak",
            now=now,
            chain_info=archive["chain"],
            beacon=row["beacon"],
            escrow_status="selected",
        )
        require(
            chosen["selected"] is True
            and chosen["divisor"] == 1
            and chosen["status"] == "selected"
            and all(
                row["selection"].get(key) == value for key, value in chosen.items()
            ),
            "Published selection disagrees with authenticated round",
        )
        result = verify_signed(row["sample_verdict"], lookup)
        require(
            result["transcript_commitment"] == transcript
            and result["challenge_id"] not in signed_ids,
            "Mismatched sampled verdict",
        )
        signed_ids.add(str(result["challenge_id"]))
        outcome = str(result["outcome"])
        require(outcome in {"CONFORMS", "EXCUSED_RANGE"}, "Unexplained sampled outcome")
        outcomes[outcome] += 1
        if holder["status"] == "excused_range":
            require(
                outcome == "EXCUSED_RANGE"
                and holder["verdict_outcome"] == outcome
                and holder["verdict_reason"] == result["reason"],
                "Independent range outcome disagrees",
            )
        if holder["status"] == "conforms":
            require(
                outcome == "CONFORMS"
                and result["proof_sha256"] == holder["proof_sha256"]
                and result["statement_sha256"] == holder["statement_sha256"],
                "Independent proof digest differs from sample",
            )
            holder_checks += 1
        prompt, reply, budget = (
            holder["prompt_tokens"],
            holder["reply_tokens"],
            row["budget"],
        )
        require(
            all(type(i) is int for i in (prompt, reply, budget))
            and (prompt, budget) == WORKLOAD[shape]
            and prompt == row["prompt_length"]
            and 50 <= prompt <= 768
            and 1 <= reply <= budget <= 256
            and prompt + reply <= 1024,
            "Unverified workload counts",
        )

        require(
            leaf["params_digest"] == params_digest(budget),
            "Budget differs from signed parameters",
        )
        cases[shape] += 1
        lengths.append(reply)
        padding.append(1024 - prompt - reply)
        served += 1
    require(
        served == size and all(cases.values()) and holder_checks > 0,
        "Incomplete all-audit or independent-holder coverage",
    )
    require(
        min(lengths) <= 10 and max(lengths) == 256,
        "Reply-length endpoints were not observed",
    )
    return {
        "attempted": len(attempts),
        "warranted": served,
        "unwarranted": unwarranted,
        "unwarranted_fraction": unwarranted / len(attempts),
        "selected": served,
        "terminal_verdicts": dict(outcomes),
        "unexplained_errors": 0,
        "holder_native_verifications": holder_checks,
        "shape_counts": cases,
        "observed_reply_range": [min(lengths), max(lengths)],
        "padding_token_range": [min(padding), max(padding)],
        "oq8": {
            "excused_range": outcomes["EXCUSED_RANGE"],
            "sampled": served,
            "fraction": outcomes["EXCUSED_RANGE"] / served,
        },
        "log_root": head["root_hash"],
        "holder_operation": "separate_local_process",
        "router": "local_opaque_mock",
    }
