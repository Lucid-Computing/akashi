"""Recheck the aggregate evidence emitted by the M4 signed-history and resource gates."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any

from release.evidence import fingerprint, require

# The order and bounds are defined by the M4 synthetic workload and its journal.
_SHAPES = ("empty_system", "long_single", "multi_turn", "system_user")
_COVERAGE = {
    "min_exact_fd_processes",
    "peak_exact_fd_processes",
    "final_exact_fd_processes",
    "protected_fd_processes",
}


def _count(value: Any) -> int:
    require(type(value) is int and value >= 0, "invalid soak count")
    return int(value)


def _number(value: Any) -> float:
    require(
        type(value) in (int, float) and math.isfinite(value), "invalid soak measure"
    )
    return float(value)


def _resources(role: str, row: dict[str, Any]) -> None:
    basis = row["fd_basis"]
    partial = basis == "exact_visible_plus_native_fdsize"
    require(
        basis == "exact_open_descriptors" or (partial and role == "prover"),
        "invalid descriptor basis",
    )
    metrics = ["rss_bytes", "gpu_bytes", "exact_fds_visible" if partial else "fds"]
    if partial:
        metrics.append("protected_fd_slots")
    keys = {"fd_basis"} | {
        f"{p}_{m}" for p in ("warm_peak", "peak", "final") for m in metrics
    }
    modern = bool(_COVERAGE.intersection(row))
    require(
        row.keys() == (keys | _COVERAGE if modern else keys)
        and (modern or not partial),
        "incomplete or mixed role resource evidence",
    )
    if modern:
        minimum, maximum, final_count = (
            _count(row[k + "_exact_fd_processes"]) for k in ("min", "peak", "final")
        )
        require(
            minimum <= final_count <= maximum
            and (partial or minimum > 0)
            and _count(row["protected_fd_processes"]) == int(partial),
            "inconsistent process coverage",
        )
    for name in metrics:
        warm, peak, final = (
            row[p + "_" + name] for p in ("warm_peak", "peak", "final")
        )
        if name == "exact_fds_visible":
            require(
                (peak is None) == (maximum == 0)
                and (final is None) == (final_count == 0)
                and (minimum == 0 or warm is not None),
                "descriptor subtotal disagrees with visibility",
            )
        else:
            require(None not in (warm, peak, final), "missing measured resource")
        for measure in (warm, peak, final):
            if measure is not None:
                value = _count(measure)
                if name in {"rss_bytes", "protected_fd_slots"}:
                    require(value > 0, "empty resource reading")
                if name == "gpu_bytes" and role in {"gateway", "auditor"}:
                    require(value == 0, "GPU attributed to a CPU role")
        require(
            (warm is None or (peak is not None and warm <= peak))
            and (final is None or (warm is not None and final <= warm)),
            "retained resource growth or impossible peak",
        )


def _utc(value: Any) -> datetime:
    require(isinstance(value, str), "missing UTC observation")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(stamp.utcoffset() == timedelta(0), "expected UTC timestamp")
    return stamp


def check_soak(report: dict[str, Any]) -> None:
    """Check a final gate_m4 report after its evidence chain has been pinned."""
    require(
        report["execution"]
        == "elapsed physical all-audit soak with local opaque router"
        and fingerprint(report["evaluation_revision"], 40),
        "missing physical soak evaluation provenance",
    )
    t, c = report["timing"], report["checks"]
    elapsed = _number(t["elapsed_seconds"])
    start, end = _utc(t["start_utc"]), _utc(t["end_utc"])
    span = (end - start).total_seconds()
    observations = _count(t["resource_observations"])
    # N observations leave N+1 possible gaps including the two endpoints.
    require(
        min(span, elapsed) >= 72 * 3600
        and end <= datetime.now(timezone.utc)
        and max(span, elapsed) <= (observations + 1) * 300,
        "incomplete dual-clock soak or insufficient observation coverage",
    )
    resources = t["resources"]
    require(
        isinstance(resources, dict)
        and resources.keys() == {"engine", "prover", "gateway", "auditor"},
        "missing soak role",
    )
    for role, row in resources.items():
        require(isinstance(row, dict), "missing role evidence")
        _resources(role, row)

    attempts, warrants, rejects, selected, holders, errors = (
        _count(c[n])
        for n in (
            "attempted",
            "warranted",
            "unwarranted",
            "selected",
            "holder_native_verifications",
            "unexplained_errors",
        )
    )
    outcomes, counts = c["terminal_verdicts"], c["shape_counts"]
    require(
        attempts > len(_SHAPES)
        and attempts == warrants + rejects
        and warrants == selected
        and errors == 0
        and c["holder_operation"] == "separate_local_process"
        and c["router"] == "local_opaque_mock"
        and fingerprint(c["log_root"], 64)
        and isinstance(outcomes, dict)
        and outcomes.keys() <= {"CONFORMS", "EXCUSED_RANGE"}
        and sum(_count(n) for n in outcomes.values()) == selected
        and 0 < holders <= min(len(_SHAPES), outcomes.get("CONFORMS", 0)),
        "unaccounted request or terminal verdict",
    )
    require(
        isinstance(counts, dict) and counts.keys() == set(_SHAPES),
        "missing workload shape",
    )
    rounds, extra = divmod(attempts, len(_SHAPES))
    require(
        all(
            0 < _count(counts[s]) <= rounds + (i < extra) for i, s in enumerate(_SHAPES)
        )
        and sum(counts.values()) == warrants,
        "shape totals disagree with round-robin attempts",
    )
    replies, padding = c["observed_reply_range"], c["padding_token_range"]
    require(
        all(isinstance(r, list) and len(r) == 2 for r in (replies, padding)),
        "missing workload range",
    )
    shortest, longest = map(_count, replies)
    least_pad, most_pad = map(_count, padding)
    # A 256-token reply requires the 768-token long_single prompt. The 50-token
    # empty_system input has budget 10 and contributes the greatest padding.
    require(
        1 <= shortest <= 10
        and longest == 256
        and least_pad == 0
        and 1024 - 50 - 10 <= most_pad <= 1024 - 50 - shortest,
        "impossible workload range",
    )
    oq, capacity = c["oq8"], c["observed_capacity"]
    excused = outcomes.get("EXCUSED_RANGE", 0)
    require(
        _count(oq["sampled"]) == selected
        and _count(oq["excused_range"]) == excused
        and _number(oq["fraction"]) == excused / selected
        and _number(c["unwarranted_fraction"]) == rejects / attempts
        and _count(capacity["synthetic_requests_in_flight_limit"]) == 1,
        "inconsistent sampled or unwarranted classification",
    )
    for key, count in (
        ("requests_per_hour", attempts),
        ("warranted_per_hour", warrants),
    ):
        expected = count / (elapsed / 3600)
        # gate_m4 divides monotonic nanoseconds directly into hours. Converting
        # its exported seconds to hours can differ by a floating-point rounding.
        require(
            abs(_number(capacity[key]) - expected) <= 2 * math.ulp(expected),
            "capacity disagrees with elapsed requests",
        )
