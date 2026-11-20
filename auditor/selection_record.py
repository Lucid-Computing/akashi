"""Public selection evidence from authenticated log history and role-owned escrow."""

from collections.abc import Mapping
from datetime import datetime
from typing import cast

from auditor.beacon import round_for, round_is_open, select_round
from log.receipt import checked_public_leaf

_DIVISORS = {"live": 20, "soak": 1}  # specs/sampling.md


def evaluate(
    index: int,
    leaf: Mapping[str, object],
    *,
    mode: str,
    now: datetime,
    chain_info: Mapping[str, object] | None,
    beacon: Mapping[str, object] | None,
    escrow_status: str | None,
) -> dict[str, object]:
    """Bind an authenticated log leaf to its published epoch and original quicknet round.

    The caller authenticates log inclusion, supplies the epoch at this index and
    looks up escrow by this leaf's hash. An unavailable escrow observation is None.
    """
    fields = dict(leaf)
    # The caller authenticates the log identity with its signed head. This also
    # checks the canonical digest encoding before accepting any claim from the leaf.
    fields = checked_public_leaf(
        fields, index=index, log_id=cast("str", fields.get("log_id"))
    )
    if mode not in _DIVISORS or fields["sampling_mode"] != mode:
        raise ValueError("Signed sampling mode differs from published epoch")
    if escrow_status not in (
        None,
        "pending",
        "transferring",
        "selected",
        "unselected",
        "gap",
    ):
        raise ValueError("Unknown escrow status")

    # checked_public_leaf validates each field's wire type and canonical encoding.
    number = cast("int", fields["beacon_round"])
    transcript = cast("str", fields["transcript_commitment"])
    served_at = datetime.fromisoformat(cast("str", fields["served_at"])[:-1] + "+00:00")
    if number != round_for(served_at):
        raise ValueError("Signed round differs from fixed assignment")

    divisor = _DIVISORS[mode]
    result: dict[str, object] = {
        "leaf_index": index,
        "leaf_hash": fields["leaf_hash"],
        "transcript_commitment": transcript,
        "beacon_round": number,
        "sampling_mode": mode,
        "divisor": divisor,
        "status": "pending",
        "selected": None,
        "shadow_selected": None,
        "beacon_signature": None,
    }
    if escrow_status == "gap":
        result.update(status="gap", reason="escrow_expired")
    if not round_is_open(number, now) or chain_info is None or beacon is None:
        return result

    signed_round = dict(beacon)
    decisions = select_round(
        bytes.fromhex(transcript), number, chain_info, signed_round
    )
    selected = decisions[divisor]
    result.update(
        selected=selected,
        shadow_selected=decisions[1000],
        beacon_signature=signed_round["signature"],
    )
    if escrow_status in ("selected", "transferring") and not selected:
        raise ValueError("Selected escrow differs from authenticated selection")
    if escrow_status == "unselected" and selected:
        raise ValueError("Unselected escrow differs from authenticated selection")
    if escrow_status in ("selected", "unselected"):
        result["status"] = escrow_status
    return result
