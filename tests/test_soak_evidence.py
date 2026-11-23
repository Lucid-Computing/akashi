"""Use fixed signed CPU fixtures to test the M4 gate without manufacturing elapsed evidence."""

import copy
import json
import sqlite3
import tempfile
import time
import unittest
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from auditor.selection_record import evaluate
from auditor.verdict_signing import sign_verdict
from log.receipt import leaf_hash, params_digest
from log.store import MerkleLog
from prover.submission import COMMITMENT
from soak.evidence import reconcile
from soak.ledger import CASES, DURATION, ROLES, Journal, measurements
from tests.test_beacon import GENESIS, INFO, LATER
from tests.test_log_store import KEY, KEY_ID, LOG_ID, preimage
from tools.gate_m4 import gate


class SoakEvidenceTests(unittest.TestCase):
    def signed(
        self, root: Path
    ) -> tuple[list[tuple[int, str, dict[str, Any]]], dict[str, Any]]:
        when = GENESIS + timedelta(seconds=(1_000_000 - 2) * 3 - 13)
        issued = when.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        log = MerkleLog(
            root / "log.db",
            log_id=LOG_ID,
            log_key_id=KEY_ID,
            signing_key=KEY,
            leaf_hash=leaf_hash,
            clock=lambda: when,
        )
        attempts = []
        records = []
        for i, (case, p, r) in enumerate(
            zip(CASES, (50, 768, 200, 512), (10, 256, 64, 128), strict=True)
        ):
            t = f"{i + 1:064x}"
            log.append(
                {
                    **preimage(i),
                    "sampling_mode": "soak",
                    "served_at": issued,
                    "commitment_id": COMMITMENT,
                    "beacon_round": 1_000_000,
                    "params_digest": params_digest(r),
                    "transcript_commitment": t,
                }
            )
            leaf = log.receipt(i)
            verdict = sign_verdict(
                {
                    "version": "vig-verdict/1",
                    "challenge_id": str(uuid.UUID(int=i + 1)),
                    "transcript_commitment": t,
                    "outcome": "CONFORMS",
                    "reason": "exact_match",
                    "verified_at": issued,
                    "auditor_key_id": "fixture",
                    "proof_sha256": "01" * 32,
                    "statement_sha256": "02" * 32,
                },
                KEY,
            )
            choice = evaluate(
                i,
                leaf,
                mode="soak",
                now=datetime.now(timezone.utc),
                chain_info=INFO,
                beacon=LATER,
                escrow_status="selected",
            )
            attempts.append(
                (
                    i,
                    case,
                    {
                        "status": "conforms" if i == 0 else "recovered",
                        "leaf_index": i,
                        "leaf_hash": leaf["leaf_hash"],
                        "transcript_commitment": t,
                        "prompt_tokens": p,
                        "reply_tokens": r,
                        "statement_sha256": "02" * 32,
                        "proof_sha256": "01" * 32,
                    },
                )
            )
            records.append(
                {
                    "leaf": leaf,
                    "beacon": LATER,
                    "selection": choice,
                    "sample_verdict": verdict,
                    "budget": r,
                    "prompt_length": p,
                }
            )
        for i, row in enumerate(records):
            row["audit_path"] = [n.hex() for n in log.path(i, 4)]
        return attempts, {"head": log.head(), "chain": INFO, "leaves": records}

    def test_signed_reconciliation_checks_inclusion_selection_and_each_verdict(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            attempts, archive = self.signed(Path(tmp))

            def check(rows: Any, data: Any) -> dict[str, object]:
                return reconcile(
                    rows,
                    data,
                    descriptor={"log": {"log_id": LOG_ID}},
                    lookup=lambda role, kid: KEY.public_key().public_bytes_raw(),
                )

            self.assertEqual(check(attempts, archive)["selected"], 4)
            for target, field, bad in (
                ("selection", "divisor", 20),
                ("sample_verdict", "proof_sha256", "03" * 32),
                ("leaf", "sampling_mode", "live"),
                ("beacon", "round", 2),
            ):
                changed = copy.deepcopy(archive)
                changed["leaves"][1][target][field] = bad
                with self.subTest(target=target), self.assertRaises(ValueError):
                    check(attempts, changed)
            relabeled = copy.deepcopy(archive)
            wrong_lengths = copy.deepcopy(attempts)
            wrong_lengths[1][2]["prompt_tokens"] = 512
            relabeled["leaves"][1]["prompt_length"] = 512
            with self.assertRaises(ValueError):
                check(wrong_lengths, relabeled)
            with self.assertRaises(ValueError):
                check(attempts[:-1], archive)

    def test_missing_config_replaces_old_pass_and_incomplete_age_stops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "m4.json"
            output.write_text('{"status":"passed"}')
            self.assertFalse(gate(None, output))
            self.assertEqual(json.loads(output.read_bytes())["status"], "incomplete")
            journal = Journal(root / "state.db")
            with closing(sqlite3.connect(journal.path)) as db, db:
                db.execute(
                    "INSERT INTO run VALUES(1,'{}','id',0,?,NULL,NULL)", (time.time(),)
                )
            seq, shape = journal.reserve()
            self.assertEqual(journal.reserve(), (seq, shape))
            self.assertTrue(journal.in_flight())
            journal.record(seq, {"status": "pending"})
            self.assertFalse(journal.in_flight())
            with self.assertRaises(ValueError):
                journal.finish()

    def test_elapsed_resource_checker_rejects_gap_restart_and_retained_growth(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            journal = Journal(Path(tmp) / "state.db")
            wall = time.time() - DURATION - 5
            values = {
                r: [i + 1, 128, 8, 64 if r in ("engine", "prover") else 0]
                for i, r in enumerate(ROLES)
            }
            with closing(sqlite3.connect(journal.path)) as db, db:
                db.execute(
                    "INSERT INTO run VALUES(1,'{}','id',0,?,?,?)",
                    (wall, DURATION * 10**9, wall + DURATION),
                )
                db.executemany(
                    "INSERT INTO observations VALUES(?,?,?)",
                    [
                        (i * 10**9, wall + i, json.dumps(values))
                        for i in range(0, DURATION + 1, 300)
                    ],
                )
                self.assertEqual(
                    measurements(db, gap_seconds=300, warmup_end_ns=600 * 10**9)[
                        "elapsed_seconds"
                    ],
                    DURATION,
                )
                changed = copy.deepcopy(values)
                changed["engine"][1] += 1
                db.execute(
                    "UPDATE observations SET roles=? WHERE ns=?",
                    (json.dumps(changed), DURATION * 10**9),
                )
                with self.assertRaises(ValueError):
                    measurements(db, gap_seconds=300, warmup_end_ns=600 * 10**9)
                db.execute("DELETE FROM observations WHERE ns=?", (300 * 10**9,))
                with self.assertRaises(ValueError):
                    measurements(db, gap_seconds=300, warmup_end_ns=600 * 10**9)
