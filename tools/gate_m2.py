"""Run the M2 auditor and holder flow on the independent verification host."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

from prover.runtime import REVISION
from prover.submission import COMMITMENT
from tools.gate_m1 import MODE_D_EXPECTED, ROOT, VECTORS, _write

_DIGEST = re.compile(r"[0-9a-f]{64}")
_AGE = timedelta(days=3).total_seconds()


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("Evidence check failed")


def prerequisite(path: Path, milestone: str) -> str:
    raw = path.read_bytes()
    doc = json.loads(raw)
    _require(
        type(doc["schema_version"]) is int
        and doc["schema_version"] == 1
        and doc["gate"] == milestone
        and doc["status"] == "passed"
    )
    if milestone == "M0":
        workload = ROOT / "tests/fixtures/m0-workload.jsonl"
        pinned = [json.loads(line) for line in workload.read_bytes().splitlines()]
        _require(
            doc["commitment_id"] == COMMITMENT
            and type(doc["batch_size"]) is int
            and doc["batch_size"] == 1
            and doc["platform"]["flashprove_revision"] == REVISION
            and doc["platform"]["serving_eligibility_scope"] == "primary_engine_only"
            and bool(_DIGEST.fullmatch(doc["platform"]["eligible_startup_sha256"]))
            and type(doc["proofs_verified"]) is int
            and doc["proofs_verified"] == len(pinned) == len(doc["replies"]) == 16
            and doc["workload_sha256"]
            == hashlib.sha256(workload.read_bytes()).hexdigest()
        )
        for case, row in zip(pinned, doc["replies"], strict=True):
            _require(
                row["id"] == case["id"]
                and bool(_DIGEST.fullmatch(row["evidence_sha256"]))
                and all(
                    type(row[key]) is int and row[key] > 0
                    for key in (
                        "prompt_tokens",
                        "caller_budget",
                        "reply_tokens",
                        "proof_bytes",
                        "proof_ns",
                        "verify_ns",
                    )
                )
                and row["prompt_tokens"] == case["prompt_tokens"]
                and row["caller_budget"] == case["max_tokens"]
                and row["reply_tokens"] <= row["caller_budget"]
            )
    else:
        _require(
            milestone == "M1"
            and doc["source"]["flashprove_commit"] == REVISION
            and doc["public_fixtures"]["renderer"]["cases"] == 200
            and doc["vectors"].keys() == VECTORS.keys()
            and all(
                row["passed"] is True
                and type(row["skipped"]) is int
                and row["skipped"] == 0
                and type(row["tests"]) is int
                and row["tests"] > 0
                for row in doc["vectors"].values()
            )
        )
        expected = doc["mode_d"]["expected"]
        observed = doc["mode_d"]["observed"]
        _require(
            expected.keys() == MODE_D_EXPECTED.keys()
            and observed.keys() == MODE_D_EXPECTED.keys() | {"fixture_sha256"}
            and bool(_DIGEST.fullmatch(observed["fixture_sha256"]))
        )
        for key, value in MODE_D_EXPECTED.items():
            _require(
                type(expected[key]) is type(value)
                and type(observed[key]) is type(value)
                and expected[key] == observed[key] == value
            )
    return hashlib.sha256(raw).hexdigest()


def checked_flow(doc: dict[str, Any], *, elapsed: bool = False) -> dict[str, object]:
    _require(
        type(doc["schema_version"]) is int
        and doc["schema_version"] == 1
        and doc["status"] == "passed"
        and doc["commitment_id"] == COMMITMENT
        and doc["flashprove_revision"] == REVISION
        and type(doc["batch_size"]) is int
        and doc["batch_size"] == 1
    )
    for key in (
        "distinct_prover_verifier_hosts",
        "distinct_rx_verifier_hosts",
        "corrected_prefix_matches_proof",
        "original_matches_proof",
        "reference_trace_bound",
    ):
        _require(doc[key] is True)
    for key in (
        "proof_sha256",
        "eligible_startup_sha256",
        "original_statement_sha256",
        "substitute_statement_sha256",
    ):
        _require(bool(_DIGEST.fullmatch(doc[key])))
    _require(doc["original_statement_sha256"] != doc["substitute_statement_sha256"])
    clock = doc["challenge_clock"]
    _require(clock in ("controlled_plus_three_days", "elapsed_wall_clock"))
    for key in ("actual_elapsed_seconds", "challenge_age_seconds"):
        _require(
            type(doc[key]) in (int, float) and math.isfinite(doc[key]) and doc[key] >= 0
        )
    _require(doc["challenge_age_seconds"] >= _AGE)
    if elapsed:
        _require(clock == "elapsed_wall_clock")
    if clock == "elapsed_wall_clock":
        _require(doc["actual_elapsed_seconds"] >= _AGE)
    for name, outcome, code in (
        ("original", "CONFORMS", 0),
        ("substitute", "DEVIATES", 21),
    ):
        observed = doc[name]
        _require(
            observed["outcome"] == observed["holder_outcome"] == outcome
            and type(observed["holder_exit"]) is int
            and observed["holder_exit"] == code
            and all(
                observed[k] is True
                for k in (
                    "signed_verdict_verified",
                    "receipt_reverified",
                    "capability_rejected",
                )
            )
        )
    return {
        "batch_size": 1,
        "conformance_exit": 0,
        "deviation_exit": 21,
        "receipt_and_verdict_signatures_verified": True,
        "capability_isolation_checked": True,
        "corrected_prefix_matches_proof": True,
        "reference_trace_bound": True,
        "separate_cpu_verifier": True,
        "challenge_clock": clock,
        "elapsed_age_verified": clock == "elapsed_wall_clock",
        "challenge_age_seconds": doc["challenge_age_seconds"],
        "actual_elapsed_seconds": doc["actual_elapsed_seconds"],
    }


def gate(
    config: Path | None,
    work: Path | None,
    m0: Path,
    m1: Path,
    output: Path,
    *,
    elapsed: bool = False,
) -> bool:
    report: dict[str, object] = {
        "schema_version": 1,
        "gate": "M2",
        "status": "incomplete",
        "commitment_id": COMMITMENT,
        "flashprove_revision": REVISION,
        "batch_privacy_oq6": "open_single_request_batches_only",
    }
    _write(output, report)
    stage = "configuration"
    try:
        if config is None or work is None:
            raise ValueError("Private configuration and work directory required")
        for path in (config, work):
            info = path.lstat()
            _require(info.st_uid == os.geteuid() and not info.st_mode & 0o077)
        _require(
            stat.S_ISREG(config.lstat().st_mode) and stat.S_ISDIR(work.lstat().st_mode)
        )
        report["source_revision"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        stage = "previous_milestones"
        prerequisite_hashes = {
            "M0": prerequisite(m0, "M0"),
            "M1": prerequisite(m1, "M1"),
        }
        report["milestone_evidence_sha256"] = prerequisite_hashes
        stage = "independent_challenge_and_holder_verification"
        with tempfile.TemporaryDirectory(dir=work) as folder:
            result = Path(folder) / "result.json"
            command = [
                sys.executable,
                "-m",
                "tools.m2_flow",
                "--config",
                str(config.resolve()),
                "--work",
                str(work.resolve()),
                "--output",
                str(result.resolve()),
            ]
            if elapsed:
                command.append("--elapsed")
            subprocess.run(
                command,
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            flow = json.loads(result.read_bytes())
            checks = checked_flow(flow, elapsed=elapsed)
            raw_m0 = m0.read_bytes()
            _require(hashlib.sha256(raw_m0).hexdigest() == prerequisite_hashes["M0"])
            baseline = json.loads(raw_m0)
            originals = [
                r for r in baseline["replies"] if r["id"] == "arithmetic-apples"
            ]
            evidence = hashlib.sha256(
                b"vig/m0/whole-reply/1"
                + bytes.fromhex(flow["original_statement_sha256"])
                + bytes.fromhex(flow["proof_sha256"])
            ).hexdigest()
            _require(
                flow["eligible_startup_sha256"]
                == baseline["platform"]["eligible_startup_sha256"]
                and len(originals) == 1
                and originals[0]["evidence_sha256"] == evidence
            )
            report["checks"] = {
                **checks,
                "eligible_primary_and_original_proof_bound": True,
            }
        report["status"] = "passed"
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        report.update(failed_stage=stage, reason=type(exc).__name__)
    _write(output, report)
    return report["status"] == "passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=os.environ.get("VIG_M2_CONFIG"))
    parser.add_argument("--work", type=Path, default=os.environ.get("VIG_M2_WORK"))
    parser.add_argument("--m0", type=Path, default=ROOT / "build/gates/m0.json")
    parser.add_argument("--m1", type=Path, default=ROOT / "build/gates/m1.json")
    parser.add_argument("--output", type=Path, default=ROOT / "build/gates/m2.json")
    parser.add_argument(
        "--elapsed",
        action="store_true",
        help="require elapsed wall-clock challenge age",
    )
    args = parser.parse_args()
    passed = gate(
        args.config, args.work, args.m0, args.m1, args.output, elapsed=args.elapsed
    )
    print(f"M2 {'passed' if passed else 'incomplete'}. Evidence is in {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
