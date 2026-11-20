"""Crash-recoverable auditor work and independent sampled deadlines (RFC-0007)."""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import uuid
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, SealedBox

from operations.private_db import private_database_file
from prover.request import build_statement, reply_complete
from prover.scoring import Assessment, deviation_statement
from prover.submission import Submission, SubmissionStore

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_DAY_US = 24 * 3600 * 1_000_000
_REASONS = {
    "selection_gap",
    "missing_handoff",
    "escrow_expired",
    "invalid_sample",
    "invalid_material",
    "prover_unavailable",
    "proof_rejected",
    "deadline_missed",
    "verifier_unavailable",
    "verifier_disagreement",
    "statement_mismatch",
}
_DIGEST = re.compile(r"[0-9a-f]{64}")


def _us(value: datetime) -> int:
    return (value - _EPOCH) // timedelta(microseconds=1)


@dataclass(frozen=True)
class Claim:
    job_id: str
    lease: str = field(repr=False)
    transcript: str = field(repr=False)
    prompt: tuple[int, ...] = field(repr=False)
    reply: tuple[int, ...] = field(repr=False)
    budget: int
    incomplete: bool


class AuditJobs:
    """Use the same role-private state and key identity as ChallengeIntake."""

    def __init__(
        self,
        path: Path,
        *,
        auditor_private_key: bytes,
        holder_hmac_key: bytes,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.path = path
        private_database_file(path)
        self._key = PrivateKey(auditor_private_key)
        self._tags = holder_hmac_key
        self._clock = clock
        with self._tx() as db:
            stored = db.execute(
                "SELECT key_tag,recipient FROM intake_identity"
            ).fetchone()
            if stored is None or tuple(stored) != (
                hmac.digest(holder_hmac_key, b"vig/challenge/intake-key/1", "sha256"),
                bytes(self._key.public_key),
            ):
                raise ValueError(
                    "Configure the same private identity as challenge intake"
                )
            db.execute("""CREATE TABLE IF NOT EXISTS audit_jobs(
                job_id TEXT PRIMARY KEY, t TEXT NOT NULL, state TEXT NOT NULL, outcome TEXT, reason TEXT,
                lease BLOB, lease_until INTEGER, completed_us INTEGER, spool_deadline_ns INTEGER)""")
            db.execute("""CREATE TABLE IF NOT EXISTS sampled_obligations(
                leaf TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES audit_jobs(job_id),
                due INTEGER NOT NULL, missed INTEGER NOT NULL DEFAULT 0)""")
            db.execute("""CREATE TABLE IF NOT EXISTS expired_sample_work(
                        job_id TEXT PRIMARY KEY, resumed INTEGER NOT NULL DEFAULT 0)""")
            db.execute(
                "CREATE INDEX IF NOT EXISTS sampled_by_job ON sampled_obligations(job_id)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS available_audit_work ON audit_jobs(state,lease_until)"
            )

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path, isolation_level=None)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            yield db

    def _refresh(self, db: sqlite3.Connection, now: int) -> None:
        db.execute("""INSERT INTO audit_jobs(job_id,t,state)
            SELECT w.job_id,w.transcript,'pending' FROM challenge_work w
            WHERE NOT EXISTS (SELECT 1 FROM audit_jobs a WHERE a.job_id=w.job_id)""")
        db.execute(
            """UPDATE sampled_obligations SET missed=1 WHERE missed=0 AND due<=?
            AND NOT EXISTS (SELECT 1 FROM audit_jobs a WHERE a.job_id=sampled_obligations.job_id
                            AND a.completed_us IS NOT NULL AND a.completed_us<sampled_obligations.due)""",
            (now,),
        )
        # The public sample stays missed. A later holder may open a new proof attempt for the same job.
        db.execute("""INSERT OR IGNORE INTO expired_sample_work(job_id)
                SELECT DISTINCT a.job_id FROM audit_jobs a JOIN sampled_obligations s USING(job_id)
                WHERE s.missed=1 AND a.state!='completed'
                AND NOT EXISTS(SELECT 1 FROM challenge_handles h WHERE h.job_id=a.job_id)""")
        db.execute(
            """UPDATE audit_jobs SET state='completed',outcome='UNAVAILABLE',reason='deadline_missed',
            lease=NULL,lease_until=NULL,completed_us=? WHERE state!='completed' AND job_id IN (
            SELECT job_id FROM expired_sample_work WHERE resumed=0)""",
            (now,),
        )
        db.execute("""UPDATE audit_jobs SET state='pending',outcome=NULL,reason=NULL,completed_us=NULL,
                  spool_deadline_ns=NULL WHERE reason='deadline_missed' AND job_id IN (
                  SELECT x.job_id FROM expired_sample_work x WHERE x.resumed=0 AND EXISTS(
                  SELECT 1 FROM challenge_handles h WHERE h.job_id=x.job_id))""")
        db.execute("""UPDATE expired_sample_work SET resumed=1 WHERE resumed=0 AND EXISTS(
                      SELECT 1 FROM challenge_handles h WHERE h.job_id=expired_sample_work.job_id)""")

    def _sample(
        self,
        leaf: str,
        t: str,
        served: datetime,
        material: tuple[tuple[int, ...], tuple[int, ...], int] | None,
        reason: str | None,
    ) -> str:
        if not _DIGEST.fullmatch(leaf) or not _DIGEST.fullmatch(t):
            raise ValueError("Invalid verified sample identity")
        due = _us(served) + _DAY_US
        with self._tx() as db:
            now = _us(self._clock())
            if now < _us(served):
                raise ValueError("Selected delivery is in the future")
            old = db.execute(
                """SELECT a.job_id,a.t,s.due FROM sampled_obligations s
                    JOIN audit_jobs a ON a.job_id=s.job_id WHERE s.leaf=?""",
                (leaf,),
            ).fetchone()
            if old is not None:
                if (old["t"], old["due"]) != (t, due):
                    raise ValueError("Conflicting selected receipt")
                return str(old["job_id"])
            job = str(uuid.uuid4())
            if material is None:
                db.execute(
                    """INSERT INTO audit_jobs(job_id,t,state,outcome,reason,completed_us)
                              VALUES(?,?,'completed','UNAVAILABLE',?,?)""",
                    (job, t, reason, now),
                )
            else:
                prompt, reply, budget = material
                statement = build_statement(prompt, reply)
                if (
                    type(budget) is not int
                    or not 1 <= budget <= min(256, 1024 - len(prompt))
                    or len(reply) > budget
                ):
                    raise ValueError("Invalid sampled budget")
                tag = hmac.digest(
                    self._tags, b"vig/challenge/statement/1" + statement, "sha256"
                )
                encoded = json.dumps(
                    {
                        "max_tokens": budget,
                        "verification": {
                            "prompt_token_ids": prompt,
                            "reply_token_ids": reply,
                        },
                    }
                ).encode()
                sealed = SealedBox(self._key.public_key).encrypt(encoded)
                db.execute(
                    """INSERT INTO challenge_work VALUES(?,?,?,?,?,?) ON CONFLICT(transcript,statement_tag) DO NOTHING""",
                    (job, t, tag, sealed, now, not reply_complete(reply, budget)),
                )
                job = db.execute(
                    "SELECT job_id FROM challenge_work WHERE transcript=? AND statement_tag=?",
                    (t, tag),
                ).fetchone()[0]
                db.execute(
                    "INSERT OR IGNORE INTO audit_jobs(job_id,t,state) VALUES(?,?,'pending')",
                    (job, t),
                )
            db.execute(
                "INSERT INTO sampled_obligations(leaf,job_id,due) VALUES(?,?,?)",
                (leaf, job, due),
            )
            self._refresh(db, now)
            return job

    def enqueue_sample(
        self,
        *,
        leaf_hash: str,
        transcript: str,
        served_at: datetime,
        prompt: tuple[int, ...],
        reply: tuple[int, ...],
        budget: int,
    ) -> str:
        return self._sample(
            leaf_hash, transcript, served_at, (prompt, reply, budget), None
        )

    def sample_unavailable(
        self, *, leaf_hash: str, transcript: str, served_at: datetime, reason: str
    ) -> str:
        if reason not in _REASONS:
            raise ValueError("Unknown sample failure")
        return self._sample(leaf_hash, transcript, served_at, None, reason)

    def sample_status(self, leaf_hash: str) -> dict[str, object] | None:
        with self._tx() as db:
            self._refresh(db, _us(self._clock()))
            row = db.execute(
                """SELECT a.state,a.outcome,a.reason,s.due,s.missed
                              FROM sampled_obligations s JOIN audit_jobs a ON a.job_id=s.job_id WHERE s.leaf=?""",
                (leaf_hash,),
            ).fetchone()
            if row is None:
                return None
            value = dict(row)
            if row["missed"]:
                value.update(
                    state="completed", outcome="UNAVAILABLE", reason="deadline_missed"
                )
            return value

    def status(self, challenge_id: str, capability: str) -> dict[str, object] | None:
        if not isinstance(capability, str) or not capability.isascii():
            return None
        with self._tx() as db:
            row = db.execute(
                "SELECT job_id,capability_hash,issued_us FROM challenge_handles WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
            if row is None or not hmac.compare_digest(
                row["capability_hash"], hashlib.sha256(capability.encode()).digest()
            ):
                return None
            now = _us(self._clock())
            self._refresh(db, now)
            state = db.execute(
                "SELECT state,outcome,reason,completed_us FROM audit_jobs WHERE job_id=?",
                (row["job_id"],),
            ).fetchone()
            if (
                state["completed_us"] is not None
                and now >= state["completed_us"] + 30 * _DAY_US
            ):
                return None
            return {
                "challenge_id": challenge_id,
                "status": state["state"],
                "outcome": state["outcome"],
                "reason": state["reason"],
                "demand_target_us": row["issued_us"] + 15 * 60 * 1_000_000,
            }

    def claim(self, *, lease_time: timedelta) -> Claim | None:
        duration = lease_time // timedelta(microseconds=1)
        if duration <= 0:
            raise ValueError("Worker lease must be positive")
        with self._tx() as db:
            now = _us(self._clock())
            self._refresh(db, now)
            while True:
                row = db.execute(
                    """SELECT a.job_id,a.t,w.material,w.incomplete,w.statement_tag FROM audit_jobs a JOIN challenge_work w USING(job_id)
                    WHERE a.state='pending' OR (a.state='verifying' AND a.lease_until<=?)
                    ORDER BY w.received_us,a.job_id LIMIT 1""",
                    (now,),
                ).fetchone()
                if row is None:
                    return None
                try:
                    doc = json.loads(SealedBox(self._key).decrypt(row["material"]))
                    v = doc["verification"]
                    prompt, reply, budget = (
                        tuple(v["prompt_token_ids"]),
                        tuple(v["reply_token_ids"]),
                        doc["max_tokens"],
                    )
                    tag = hmac.digest(
                        self._tags,
                        b"vig/challenge/statement/1" + build_statement(prompt, reply),
                        "sha256",
                    )
                    if (
                        type(budget) is not int
                        or not 1 <= budget <= min(256, 1024 - len(prompt))
                        or len(reply) > budget
                        or bool(row["incomplete"]) == reply_complete(reply, budget)
                        or not hmac.compare_digest(tag, row["statement_tag"])
                    ):
                        raise ValueError("Inconsistent job binding")
                except (CryptoError, TypeError, ValueError, KeyError):
                    db.execute(
                        """UPDATE audit_jobs SET state='completed',outcome='UNAVAILABLE',reason='invalid_material',
                                  completed_us=?,lease=NULL,lease_until=NULL WHERE job_id=?""",
                        (now, row["job_id"]),
                    )
                    continue
                break
            token = secrets.token_hex(32)
            db.execute(
                "UPDATE audit_jobs SET state='verifying',lease=?,lease_until=? WHERE job_id=?",
                (
                    hashlib.sha256(token.encode()).digest(),
                    now + duration,
                    row["job_id"],
                ),
            )
            return Claim(
                row["job_id"],
                token,
                row["t"],
                prompt,
                reply,
                budget,
                bool(row["incomplete"]),
            )

    def _owned(self, db: sqlite3.Connection, claim: Claim, now: int) -> sqlite3.Row:
        self._refresh(db, now)
        row = db.execute(
            """SELECT a.*,w.statement_tag,w.incomplete FROM audit_jobs a JOIN challenge_work w USING(job_id)
               WHERE a.job_id=? AND a.state='verifying' AND a.lease_until>?""",
            (claim.job_id, now),
        ).fetchone()
        if row is None or not hmac.compare_digest(
            row["lease"], hashlib.sha256(claim.lease.encode()).digest()
        ):
            raise ValueError("Worker no longer owns this audit claim")
        tag = hmac.digest(
            self._tags,
            b"vig/challenge/statement/1" + build_statement(claim.prompt, claim.reply),
            "sha256",
        )
        if (
            row["t"] != claim.transcript
            or not hmac.compare_digest(tag, row["statement_tag"])
            or bool(row["incomplete"]) != claim.incomplete
        ):
            raise ValueError("Worker claim differs from private evidence")
        return cast(sqlite3.Row, row)

    def dispatch(
        self,
        claim: Claim,
        assessment: Assessment,
        spool: SubmissionStore,
        *,
        deadline_ns: int,
    ) -> Submission:
        if (
            claim.incomplete
            or assessment.kind not in ("conformance", "deviation")
            or assessment.statement is None
        ):
            raise ValueError("Job cannot enter the proof spool")
        expected = (
            build_statement(claim.prompt, claim.reply)
            if assessment.kind == "conformance"
            else deviation_statement(claim.prompt, claim.reply, assessment.divergence)
            if assessment.divergence
            else None
        )
        if expected is None or expected != assessment.statement:
            raise ValueError("Proof statement differs from the claimed job")
        with self._tx() as db:
            row = self._owned(db, claim, _us(self._clock()))
            resumed = db.execute(
                "SELECT resumed FROM expired_sample_work WHERE job_id=?",
                (claim.job_id,),
            ).fetchone()
            dispatch_id = (
                claim.job_id + "/holder" if resumed and resumed[0] else claim.job_id
            )
            stored = row["spool_deadline_ns"]
            if stored is None:
                if type(deadline_ns) is not int or not 0 < deadline_ns < 1 << 63:
                    raise ValueError("Invalid prover deadline")
                stored = deadline_ns
                db.execute(
                    "UPDATE audit_jobs SET spool_deadline_ns=? WHERE job_id=?",
                    (stored, claim.job_id),
                )
        # A crash between the databases retries the same job, statement and frozen deadline.
        return spool.submit(dispatch_id, expected, deadline_ns=stored)

    def complete(self, claim: Claim, outcome: str, reason: str | None = None) -> None:
        # Proof-bearing terminal outcomes enter through the independent verification and signing path.
        if outcome not in {"INCOMPLETE", "UNAVAILABLE"} or (
            reason not in _REASONS if outcome == "UNAVAILABLE" else reason is not None
        ):
            raise ValueError("Invalid audit outcome or reason")
        if claim.incomplete != (outcome == "INCOMPLETE") and outcome != "UNAVAILABLE":
            raise ValueError("Outcome differs from the verified completion rule")
        with self._tx() as db:
            now = _us(self._clock())
            self._owned(db, claim, now)
            db.execute(
                """UPDATE audit_jobs SET state='completed',outcome=?,reason=?,completed_us=?,lease=NULL,lease_until=NULL
                          WHERE job_id=?""",
                (outcome, reason, now, claim.job_id),
            )
