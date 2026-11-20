"""Validate and project the three freshly executed M3 regression reports."""

from __future__ import annotations

import hashlib
import json
import platform
import re
from pathlib import Path
from typing import Any

from redteam.evidence_regressions import (
    ADMISSION_CONTRACT,
    CONTRACT,
    MODEL_CONTRACT,
    SUITES,
)

_CONTRACTS = {
    "model": MODEL_CONTRACT,
    "evidence": CONTRACT,
    "admission": ADMISSION_CONTRACT,
}
# These versioned suites each run exactly the M3 minimum of twenty pairs.
# Extend the fixture corpus and this count together when adding public trials.
_FIXED_PAIRS_PER_SCENARIO = 20
_REPORT_FIELDS = {
    "schema_version",
    "source_revision",
    "environment",
    "execution",
    "scope",
    "status",
    "fixture_sha256",
    "scenarios",
}
_FIELDS = {
    "scenario",
    "expected",
    "honest_expected",
    "trials",
    "caught",
    "honest_controls",
    "honest_passed",
    "passed",
}
_LONG = ("selection_divisor", "selected_long", "short_controls", "short_conforms")
_ADMISSION = (
    "holder_boundaries",
    "transcript_boundaries",
    "retry_after_verified",
    "durable_queue_verified",
    "dedup_verified",
    "rollovers_verified",
)


def _count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("Invalid M3 count")
    return value


def _scenario(
    raw: dict[str, Any], ident: str, labels: tuple[str, str]
) -> dict[str, Any]:
    extra = _LONG if ident == "R18" else _ADMISSION if ident == "R19" else ()
    if (
        raw.keys() != _FIELDS.union(extra)
        or (raw["expected"], raw["honest_expected"]) != labels
        or raw["passed"] is not True
    ):
        raise ValueError("Invalid M3 scenario contract")
    trials, caught = _count(raw["trials"]), _count(raw["caught"])
    controls, honest = _count(raw["honest_controls"]), _count(raw["honest_passed"])
    if (
        trials != _FIXED_PAIRS_PER_SCENARIO
        or controls != _FIXED_PAIRS_PER_SCENARIO
        or caught != trials
        or honest != controls
    ):
        raise ValueError("Incomplete M3 trial or control results")

    subchecks = {name: _count(raw[name]) for name in extra}
    if ident == "R18" and (
        subchecks["selection_divisor"] != 1
        or subchecks["selected_long"] != trials
        or subchecks["short_controls"] != _FIXED_PAIRS_PER_SCENARIO
        or subchecks["short_conforms"] != subchecks["short_controls"]
    ):
        raise ValueError("Incomplete M3 long-prompt controls")
    if ident == "R19" and any(count != trials for count in subchecks.values()):
        raise ValueError("Incomplete M3 admission controls")
    return {
        "scenario": ident,
        "expected": labels[0],
        "honest_expected": labels[1],
        "trials": trials,
        "caught": caught,
        "honest_controls": controls,
        "honest_passed": honest,
        "passed": True,
        **subchecks,
    }


def _fixture_hash(root: Path, name: str) -> str:
    try:
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("Invalid public M3 fixture")
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, RuntimeError):
        raise ValueError("Unavailable public M3 fixture") from None


def checked_report(
    reports: dict[str, dict[str, Any]], *, revision: str, root: Path
) -> dict[str, object]:
    """Raise ValueError on any unsuccessful, incomplete or mismatched subreport."""
    if (
        not isinstance(revision, str)
        or not re.fullmatch("[0-9a-f]{40}", revision)
        or not isinstance(reports, dict)
        or reports.keys() != _CONTRACTS.keys()
    ):
        raise ValueError("Invalid M3 suite set or revision")
    environment = {"python": platform.python_version(), "machine": platform.machine()}
    if not all(
        re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value) for value in environment.values()
    ):
        raise ValueError("Invalid M3 execution environment")
    root = root.resolve()
    by_id: dict[str, dict[str, Any]] = {}
    digests: dict[str, str] = {}
    for name, contract in _CONTRACTS.items():
        spec, report = SUITES[name], reports[name]
        if (
            not isinstance(report, dict)
            or report.keys() != _REPORT_FIELDS
            or type(report["schema_version"]) is not int
            or report["schema_version"] != 1
            or report["source_revision"] != revision
            or report["environment"] != environment
            or report["scope"] != spec.scope
            or report["execution"] != spec.execution
            or report["status"] != "passed"
        ):
            raise ValueError("M3 subreport provenance or status mismatch")
        advertised = report["fixture_sha256"]
        if not isinstance(advertised, dict) or advertised.keys() != set(spec.fixtures):
            raise ValueError("M3 fixture inventory mismatch")
        for source in spec.fixtures:
            digest = _fixture_hash(root, source)
            if advertised[source] != digest:
                raise ValueError("M3 fixture digest mismatch")
            digests[source] = digest
        rows = report["scenarios"]
        if not isinstance(rows, list) or len(rows) != len(contract):
            raise ValueError("M3 suite scenario count mismatch")
        for raw in rows:
            ident = raw.get("scenario") if isinstance(raw, dict) else None
            if not isinstance(ident, str) or ident not in contract or ident in by_id:
                raise ValueError("Unknown or duplicated M3 scenario")
            by_id[ident] = _scenario(raw, ident, contract[ident])

    sequence = [f"R{i}" for i in range(1, 20)]
    if by_id.keys() != set(sequence):
        raise ValueError("Incomplete M3 scenario set")
    ordered = [by_id[ident] for ident in sequence]
    totals = {
        key: sum(row[key] for row in ordered)
        for key in ("trials", "caught", "honest_controls", "honest_passed")
    }
    totals.update(
        scenarios=len(ordered),
        missed=totals["trials"] - totals["caught"],
        false_positives=totals["honest_controls"] - totals["honest_passed"],
    )
    canonical = json.dumps(digests, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    return {
        "scenarios": ordered,
        "totals": totals,
        "fixture_digest": hashlib.sha256(canonical).hexdigest(),
        "environment": environment,
    }
