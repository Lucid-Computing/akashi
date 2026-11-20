"""Validate isolated regression outcomes against the M3 source contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

from tools.gate_m1 import FIXTURES, ROOT, _assets, _write

CONTRACT = {
    "R10": (
        "11/RENDER_MISMATCH + 400/invalid_bundle",
        "30/RECEIPT_VERIFIED + accepted/pending",
    ),
    "R11": ("11/RENDER_MISMATCH", "30/RECEIPT_VERIFIED"),
    "R12": ("12/TEXT_MISMATCH", "30/RECEIPT_VERIFIED"),
    "R13": ("10/RECEIPT_INVALID", "30/RECEIPT_VERIFIED"),
    "R14": ("20/PROOF_REJECTED", "0/CONFORMS"),
    "R15": ("30/NO_VERDICT", "0/CONFORMS"),
    "R16": ("omitted_promise", "included"),
    "R17": ("PROMISE_BACKDATED + promise_backdated", "receipt_verified + no_alert"),
}


def summarize(
    rows: list[dict[str, Any]], contract: dict[str, tuple[str, str]]
) -> list[dict[str, object]]:
    """Project only contract labels and checked counts into public evidence."""
    by_scenario = {row["scenario"]: row for row in rows}
    if len(rows) != len(contract) or by_scenario.keys() != contract.keys():
        raise ValueError("Missing or duplicated release scenario")
    summary: list[dict[str, object]] = []
    for ident, (expected, honest) in contract.items():
        row = by_scenario[ident]
        trials, controls = row["trials"], row["honest_controls"]
        if (
            type(trials) is not int
            or type(controls) is not int
            or trials < 20
            or controls < 1
        ):
            raise ValueError("Incomplete release trial or honest control count")
        counts = {}
        for key, total, wanted, matched in (
            ("observed", trials, expected, "caught"),
            ("honest_observed", controls, honest, "honest_passed"),
        ):
            by_outcome = row[key]
            if (
                not isinstance(by_outcome, dict)
                or any(type(n) is not int or n < 1 for n in by_outcome.values())
                or sum(by_outcome.values()) != total
            ):
                raise ValueError("Invalid observed result counts")
            observed = by_outcome.get(wanted, 0)
            if type(row[matched]) is not int or row[matched] != observed:
                raise ValueError(
                    "Outcome totals do not match observed release controls"
                )
            counts[matched] = observed
        if (row["expected"], row["honest_expected"]) != (expected, honest):
            raise ValueError("Unknown release contract")
        summary.append(
            {
                "scenario": ident,
                "expected": expected,
                "honest_expected": honest,
                "trials": trials,
                "honest_controls": controls,
                **counts,
                "passed": counts["caught"] == trials
                and counts["honest_passed"] == controls,
            }
        )
    return summary


MODEL_CONTRACT = {
    f"R{i}": ("INCOMPLETE" if i == 8 else "DEVIATES", "CONFORMS")
    for i in (*range(1, 10), 18)
}


def _long_prompt_controls(
    rows: list[dict[str, Any]], checked: list[dict[str, object]]
) -> None:
    long = next(row for row in rows if row["scenario"] == "R18")
    fields = (
        "selected_long",
        "short_controls",
        "short_conforms",
        "selection_divisor",
    )
    for key in fields:
        if type(long[key]) is not int or long[key] < 0:
            raise ValueError("Invalid long-prompt control count")
    if (
        long["selection_divisor"] != 1
        or long["selected_long"] != long["trials"]
        or long["short_controls"] < 20
        or long["short_conforms"] > long["short_controls"]
    ):
        raise ValueError("Incomplete long-prompt selection evidence")
    public = next(row for row in checked if row["scenario"] == "R18")
    for key in fields:
        public[key] = long[key]
    public["passed"] = (
        public["passed"] is True and long["short_controls"] == long["short_conforms"]
    )


ADMISSION_CONTRACT = {
    "R19": ("429/rate_limited + bounded_queue", "202/pending + independent_handle")
}


def _receipt_rows() -> list[dict[str, object]]:
    from redteam.history_cases import run_history_cases
    from redteam.transcript_cases import run_cases

    manifest = json.loads((FIXTURES / "render-goldens/manifest.json").read_bytes())
    with tempfile.TemporaryDirectory() as tmp:
        rows = run_cases(_assets(Path(tmp), manifest)) + run_history_cases()
    return summarize(rows, CONTRACT)


def _model_rows() -> list[dict[str, object]]:
    from redteam.model_cases import run_model_cases

    rows = run_model_cases()
    checked = summarize(rows, MODEL_CONTRACT)
    _long_prompt_controls(rows, checked)
    return checked


def _admission_rows() -> list[dict[str, object]]:
    from redteam.admission_cases import run_admission_cases

    rows = run_admission_cases()
    checked = summarize(rows, ADMISSION_CONTRACT)
    _admission_controls(rows[0], checked[0])
    return checked


def _admission_controls(row: dict[str, object], public: dict[str, object]) -> None:
    trials = row["trials"]
    if type(trials) is not int:
        raise ValueError("Invalid admission trial count")
    for key in (
        "holder_boundaries",
        "transcript_boundaries",
        "retry_after_verified",
        "durable_queue_verified",
        "dedup_verified",
        "rollovers_verified",
    ):
        count = row[key]
        if type(count) is not int or not 0 <= count <= trials:
            raise ValueError("Invalid admission control count")
        public[key] = count
        if count != trials:
            public["passed"] = False


class Suite(NamedTuple):
    scope: str
    execution: str
    fixtures: tuple[str, ...]
    checks: Callable[[], list[dict[str, object]]]


SUITES = {
    "evidence": Suite(
        "R10-R17",
        "offline synthetic receipt, proof-policy and history fixtures",
        (
            "tests/fixtures/render-goldens/manifest.json",
            "tests/fixtures/render-goldens/chat.jsonl",
            "redteam/history_cases.py",
            "redteam/transcript_cases.py",
        ),
        _receipt_rows,
    ),
    "model": Suite(
        "R1-R9,R18",
        "offline synthetic reference choices, controlled completions and verifier policy",
        (
            "tests/fixtures/model-outcomes-v1.jsonl",
            "tests/fixtures/model-f9-records-v1.json",
            "redteam/model_cases.py",
            "tests/test_beacon.py",
            "tests/test_proof_verification.py",
        ),
        _model_rows,
    ),
    "admission": Suite(
        "R19",
        "in-process signed challenge fixtures with independent SQLite connections",
        (
            "redteam/admission_cases.py",
            "tests/test_challenge_intake.py",
            "tests/test_discovery.py",
        ),
        _admission_rows,
    ),
}


def gate(output: Path, *, suite: str = "evidence") -> bool:
    if suite not in SUITES:
        raise ValueError("Unknown M3 suite")
    spec = SUITES[suite]
    report: dict[str, object] = {
        "schema_version": 1,
        "scope": spec.scope,
        "environment": {
            "python": platform.python_version(),
            "machine": platform.machine(),
        },
        "status": "incomplete",
        "execution": spec.execution,
    }
    _write(output, report)
    stage = "fixture_provenance"
    try:
        report["source_revision"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        report["fixture_sha256"] = {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in spec.fixtures
        }
        stage = "local_evidence_checks"
        checked = spec.checks()
        report["scenarios"] = checked
        report["status"] = (
            "passed" if all(row["passed"] for row in checked) else "failed"
        )
    except (
        AssertionError,
        ImportError,
        KeyError,
        TypeError,
        ValueError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        report.update(failed_stage=stage, reason=type(exc).__name__)
    _write(output, report)
    return report["status"] == "passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=tuple(SUITES), default="evidence")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or ROOT / f"build/gates/m3-{args.suite}.json"
    passed = gate(output, suite=args.suite)
    print(
        f"{args.suite} regressions {'passed' if passed else 'incomplete'}. Evidence is in {output}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
