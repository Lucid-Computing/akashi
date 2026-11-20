"""Validate synthetic receipt and monitor outcomes against the M3 source contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

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


def gate(output: Path) -> bool:
    report: dict[str, object] = {
        "schema_version": 1,
        "scope": "R10-R17",
        "status": "incomplete",
        "execution": "offline synthetic receipt, proof-policy and history fixtures",
    }
    _write(output, report)
    stage = "fixture_provenance"
    try:
        from redteam.history_cases import run_history_cases
        from redteam.transcript_cases import run_cases

        report["source_revision"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        manifest_path = FIXTURES / "render-goldens/manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        public_inputs = [
            manifest_path,
            FIXTURES / "render-goldens/chat.jsonl",
            ROOT / "redteam/history_cases.py",
            ROOT / "redteam/transcript_cases.py",
        ]
        report["fixture_sha256"] = {
            p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in public_inputs
        }
        stage = "local_evidence_checks"
        with tempfile.TemporaryDirectory() as tmp:
            assets = _assets(Path(tmp), manifest)
            rows = run_cases(assets) + run_history_cases()
        checked = summarize(rows, CONTRACT)
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
    parser.add_argument(
        "--output", type=Path, default=ROOT / "build/gates/m3-evidence.json"
    )
    output = parser.parse_args().output
    passed = gate(output)
    print(f"R10–R17 {'passed' if passed else 'incomplete'}. Evidence is in {output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
