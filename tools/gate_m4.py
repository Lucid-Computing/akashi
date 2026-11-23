"""Check elapsed Mode R soak evidence, independent holder recovery and prior milestones."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
from contextlib import closing
from datetime import datetime
from pathlib import Path

from prover.submission import COMMITMENT
from soak.evidence import reconcile
from soak.ledger import CASES, DURATION, measurements, require
from soak.runner import CORPUS
from soak.settings import digest, private, public_keys
from tools.gate_m1 import ROOT, _write


def prerequisites(paths: dict[str, str], primary: str) -> dict[str, str]:
    require(set(paths) == {"M0", "M1", "M2", "M3"}, "Missing earlier milestone")
    docs = {}
    hashes = {}
    for name, path in paths.items():
        raw = Path(path).read_bytes()
        doc = json.loads(raw)
        require(
            type(doc["schema_version"]) is int
            and doc["schema_version"] == 1
            and doc["gate"] == name
            and doc["status"] == "passed",
            "Prior milestone is incomplete",
        )
        docs[name] = doc
        hashes[name] = hashlib.sha256(raw).hexdigest()
    m0, m2, m3 = docs["M0"], docs["M2"], docs["M3"]
    require(
        m0["commitment_id"] == COMMITMENT
        and m0["batch_size"] == 1
        and m0["proofs_verified"] == 16
        and m0["platform"]["serving_eligibility_scope"] == "primary_engine_only"
        and m0["platform"]["eligible_startup_sha256"] == primary,
        "Wrong eligible platform evidence",
    )
    require(
        m2["milestone_evidence_sha256"] == {"M0": hashes["M0"], "M1": hashes["M1"]}
        and m2["checks"]["eligible_primary_and_original_proof_bound"] is True
        and m2["checks"]["elapsed_age_verified"] is True
        and m2["checks"]["conformance_exit"] == 0
        and m2["checks"]["deviation_exit"] == 21,
        "Missing independent naturally aged historical evidence",
    )
    require(
        m3["totals"]["scenarios"] == 19
        and m3["totals"]["missed"] == 0
        and m3["totals"]["false_positives"] == 0
        and m3["totals"]["caught"] == m3["totals"]["trials"] >= 380
        and m3["totals"]["honest_passed"] == m3["totals"]["honest_controls"] >= 380,
        "Missing complete defensive regression evidence",
    )
    return hashes


def gate(config_path: Path | None, target: Path) -> bool:
    report: dict[str, object] = {
        "schema_version": 1,
        "gate": "M4",
        "status": "incomplete",
        "execution": "elapsed physical all-audit soak with local opaque router",
    }
    _write(target, report)
    stage = "configuration"
    try:
        require(config_path is not None, "Private deployment config required")
        if config_path is None:
            raise ValueError("Missing deployment")
        config = private(config_path)
        state = Path(config["state"])
        require(
            state.lstat().st_uid == os.geteuid() and state.lstat().st_mode & 0o077 == 0,
            "Private soak state required",
        )
        archive_path = state / "archive.json"
        stage = "live_run"
        with closing(
            sqlite3.connect(
                (state / "journal.db").resolve().as_uri() + "?mode=ro", uri=True
            )
        ) as db:
            db.execute("BEGIN")
            binding_raw, started, wall, ended, endwall = db.execute(
                "SELECT config,start_ns,start_utc,end_ns,end_utc FROM run"
            ).fetchone()
            require(
                ended is not None
                and (ended - started) / 1e9 >= DURATION
                and endwall - wall >= DURATION,
                "Elapsed soak incomplete",
            )
            bind = json.loads(binding_raw)
            require(
                bind.get("same_physical_primary") is True,
                "Run did not verify the physical primary",
            )
            require(
                bind["primary_startup_sha256"]
                == digest(Path(config["primary_startup"]))
                and bind["active_startup_sha256"]
                == digest(Path(config["active_startup"]))
                and bind["fixture_sha256"] == digest(CORPUS)
                and bind["holder_config_sha256"]
                == digest(Path(config["holder_config"]))
                and bind["descriptor_sha256"] == digest(Path(config["descriptor"])),
                "Live custody or inputs changed",
            )
            active = json.loads(Path(config["active_startup"]).read_bytes())
            primary = json.loads(Path(config["primary_startup"]).read_bytes())
            require(
                all(
                    active[k] == primary[k]
                    for k in (
                        "phase",
                        "commitment_id",
                        "dtype",
                        "same_process_f21",
                        "float64_cases_passed",
                        "platform",
                        "canaries",
                    )
                )
                and active["phase"] == "eligible"
                and active["commitment_id"] == COMMITMENT
                and active["same_process_f21"] is True
                and len(active["canaries"]) == 3,
                "Unqualified physical serving engine",
            )
            rows = list(
                db.execute(
                    "SELECT seq,shape,started_ns,ended_ns,record FROM attempts ORDER BY seq"
                )
            )
            require(
                len(rows) > len(CASES)
                and all(r[3] is not None and r[4] is not None for r in rows),
                "Soak workload did not repeat or drain",
            )
            gap = bind["max_observation_gap_seconds"]
            require(
                0 < gap <= 300, "Resource cadence could miss an entire escrow window"
            )
            times = measurements(
                db, gap_seconds=gap, warmup_end_ns=rows[len(CASES) - 1][3]
            )
        stage = "signed_reconciliation"
        archived = private(archive_path)
        descriptor = json.loads(Path(config["descriptor"]).read_bytes())
        keys = public_keys(descriptor)
        entries = []
        previous = started
        for index, shape, begin, finish, raw in rows:
            require(
                0 <= begin - previous <= gap * 1e9 and begin <= finish <= ended,
                "Gap in synthetic traffic",
            )
            holder = json.loads(raw)
            if "leaf_index" in holder:
                record = archived["leaves"][holder["leaf_index"]]
                stamp = datetime.fromisoformat(
                    record["leaf"]["served_at"].replace("Z", "+00:00")
                ).timestamp()
                require(
                    wall <= stamp <= endwall
                    and wall + (begin - started) / 1e9 - 30
                    <= stamp
                    <= wall + (finish - started) / 1e9 + 30,
                    "Signed delivery occurred outside its observed attempt",
                )
                verdict_time = datetime.fromisoformat(
                    record["sample_verdict"]["verified_at"].replace("Z", "+00:00")
                ).timestamp()
                require(
                    stamp <= verdict_time <= stamp + 24 * 3600,
                    "Sampled verdict outside the documented deadline",
                )
            entries.append((index, shape, holder))
            previous = finish
        require(ended - previous <= gap * 1e9, "Final traffic observation missing")
        results = reconcile(
            entries,
            archived,
            descriptor=descriptor,
            lookup=lambda role, kid: keys[role, kid],
        )
        elapsed_hours = (ended - started) / (3600 * 1e9)
        results["observed_capacity"] = {
            "requests_per_hour": len(rows) / elapsed_hours,
            "warranted_per_hour": len(archived["leaves"]) / elapsed_hours,
            "synthetic_requests_in_flight_limit": 1,
        }
        stage = "prerequisites"
        prior = prerequisites(config["milestones"], bind["primary_startup_sha256"])
        report.update(
            status="passed",
            source_revision=bind["source_revision"],
            evaluation_revision=subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            milestone_evidence_sha256=prior,
            fixture_digest=digest(CORPUS),
            eligible_startup_sha256=bind["primary_startup_sha256"],
            active_startup_sha256=bind["active_startup_sha256"],
            archive_sha256=digest(archive_path),
            timing=times,
            checks=results,
        )
    except (
        OSError,
        sqlite3.Error,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        RuntimeError,
        AttributeError,
        OverflowError,
        subprocess.SubprocessError,
    ) as exc:
        report.update(failed_stage=stage, reason=type(exc).__name__)
    _write(target, report)
    return report["status"] == "passed"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=os.environ.get("VIG_M4_CONFIG"))
    parser.add_argument("--output", type=Path, default=ROOT / "build/gates/m4.json")
    args = parser.parse_args()
    success = gate(args.config, args.output)
    print(f"M4 {'passed' if success else 'incomplete'}. Evidence is in {args.output}")
    raise SystemExit(0 if success else 1)
