"""Bind terminal audit outcomes to verified private evidence and permanent signed metadata."""

import base64
import hashlib
import hmac
import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import SealedBox

from auditor.verdict_signing import sign_verdict, verify_signed
from prover.reference import ReferenceUnavailable
from prover.request import build_statement, reply_complete
from prover.scoring import Divergence, Scorer, assess
from prover.worker import CandidateProof, Unavailable
from verifier.proof import ProofChecker, verify_reply

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_DAY = 86_400_000_000


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    artifact: dict[str, object] | None = field(default=None, repr=False)
    private_range: dict[str, object] | None = field(default=None, repr=False)


def _stamp(us: int) -> str:
    return (
        (_EPOCH + timedelta(microseconds=us))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _us(at: datetime) -> int:
    return (at - _EPOCH) // timedelta(microseconds=1)


def decide(
    prompt: tuple[int, ...],
    reply: tuple[int, ...],
    budget: int,
    candidate: CandidateProof | Unavailable | None,
    *,
    primary: ProofChecker,
    secondary: ProofChecker | None,
    scorer: Scorer | None,
) -> Decision:
    if not reply_complete(reply, budget):
        return Decision("INCOMPLETE", "completion_rule")
    unavailable = Decision("UNAVAILABLE", "prover_unavailable")
    if candidate is None:
        return unavailable
    divergence: Divergence | None = None
    try:
        if isinstance(candidate, Unavailable):
            if candidate.reason == "deadline":
                return Decision("UNAVAILABLE", "deadline_missed")
            if candidate.reason == "spool_failure" and scorer is not None:
                assessed = assess(prompt, reply, budget, scorer, failure=candidate)
                detail = assessed.private_range
                if assessed.kind == "excused_range" and detail is not None:
                    return Decision(
                        "EXCUSED_RANGE",
                        "padding_range",
                        private_range={
                            "statement_sha256": detail.statement_sha256,
                            "position": detail.position,
                            "condition": detail.condition,
                        },
                    )
            return unavailable
        if candidate.statement != build_statement(prompt, reply):
            if scorer is None:
                return Decision("UNAVAILABLE", "statement_mismatch")
            diagnosis = assess(prompt, reply, budget, scorer)
            if diagnosis.kind != "deviation" or diagnosis.divergence is None:
                return Decision("UNAVAILABLE", "statement_mismatch")
            divergence = diagnosis.divergence
        result = verify_reply(
            prompt,
            reply,
            budget,
            candidate,
            primary,
            divergence=divergence,
            secondary=secondary,
        )
    except (ImportError, ReferenceUnavailable, OSError):
        return Decision("UNAVAILABLE", "verifier_unavailable")
    if result.outcome != "verified":
        reason = {
            "rejected": "proof_rejected",
            "disagreement": "verifier_disagreement",
            "statement_mismatch": "statement_mismatch",
        }.get(result.outcome, "verifier_unavailable")
        return Decision("UNAVAILABLE", reason)
    artifact: dict[str, object] = {
        "kind": "deviation" if divergence else "conformance",
        "statement": candidate.statement.hex(),
        "proof": base64.b64encode(candidate.proof).decode("ascii"),
    }
    if divergence:
        artifact.update(index=divergence.index, expected=divergence.expected)
        return Decision("DEVIATES", "first_divergence", artifact)
    return Decision("CONFORMS", "exact_match", artifact)


class VerdictStore:
    def __init__(
        self,
        jobs: Any,
        *,
        key_id: str,
        signer: Ed25519PrivateKey,
        primary: ProofChecker,
        secondary: ProofChecker | None = None,
        scorer: Scorer | None = None,
    ) -> None:
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("Expected configured auditor signing identity")
        self.jobs, self._signer, self._key_id = jobs, signer, key_id
        self._primary, self._secondary, self._scorer = primary, secondary, scorer
        self._box = SealedBox(jobs._key)
        with jobs._tx() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS verdict_keys(key_id TEXT PRIMARY KEY,public_key BLOB NOT NULL)"
            )
            public = signer.public_key().public_bytes_raw()
            db.execute(
                "INSERT OR IGNORE INTO verdict_keys VALUES(?,?)", (key_id, public)
            )
            if (
                db.execute(
                    "SELECT public_key FROM verdict_keys WHERE key_id=?", (key_id,)
                ).fetchone()[0]
                != public
            ):
                raise ValueError("Conflicting auditor key id")
            db.execute("""CREATE TABLE IF NOT EXISTS audit_evidence(job_id TEXT PRIMARY KEY,proof_digest TEXT,
                       statement_digest TEXT,ciphertext BLOB,expires_us INTEGER NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS signed_verdicts(challenge_id TEXT PRIMARY KEY,
                       t TEXT NOT NULL,verified_us INTEGER NOT NULL,document TEXT NOT NULL)""")
            db.execute(
                "CREATE INDEX IF NOT EXISTS verdicts_by_t ON signed_verdicts(t,verified_us)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS verdicts_by_time ON signed_verdicts(verified_us)"
            )

            db.execute("""CREATE TABLE IF NOT EXISTS sampled_verdict_ids(
                       leaf TEXT PRIMARY KEY,subject TEXT UNIQUE NOT NULL)""")

    def settle(
        self, claim: Any, candidate: CandidateProof | Unavailable | None
    ) -> Decision:
        decision = decide(
            claim.prompt,
            claim.reply,
            claim.budget,
            candidate,
            primary=self._primary,
            secondary=self._secondary,
            scorer=self._scorer,
        )
        evidence = decision.artifact or decision.private_range
        encrypted = (
            self._box.encrypt(json.dumps(evidence, separators=(",", ":")).encode())
            if evidence
            else None
        )
        proof_hash = statement_hash = None
        if decision.artifact is not None:
            assert isinstance(candidate, CandidateProof)
            proof_hash = hashlib.sha256(candidate.proof).hexdigest()
            statement_hash = hashlib.sha256(candidate.statement).hexdigest()
        with self.jobs._tx() as db:
            now = _us(self.jobs._clock())
            self.jobs._owned(db, claim, now)
            if encrypted is not None:
                db.execute(
                    "INSERT INTO audit_evidence VALUES(?,?,?,?,?)",
                    (
                        claim.job_id,
                        proof_hash,
                        statement_hash,
                        encrypted,
                        now + 30 * _DAY,
                    ),
                )
            db.execute(
                """UPDATE audit_jobs SET state='completed',outcome=?,reason=?,completed_us=?,lease=NULL,lease_until=NULL
                       WHERE job_id=?""",
                (decision.outcome, decision.reason, now, claim.job_id),
            )
            self._publish(db, now)
        return decision

    def _persist(
        self,
        db: sqlite3.Connection,
        subject: str,
        row: sqlite3.Row,
        *,
        missed_at: int | None = None,
    ) -> None:
        outcome = "UNAVAILABLE" if missed_at is not None else row["outcome"]
        reason = "deadline_missed" if missed_at is not None else row["reason"]
        stamp = missed_at if missed_at is not None else row["completed_us"]
        doc: dict[str, object] = {
            "version": "vig-verdict/1",
            "challenge_id": subject,
            "transcript_commitment": row["t"],
            "outcome": outcome,
            "reason": reason or {"INCOMPLETE": "completion_rule"}[outcome],
            "verified_at": _stamp(stamp),
            "auditor_key_id": self._key_id,
        }
        if outcome in ("CONFORMS", "DEVIATES"):
            doc.update(
                proof_sha256=row["proof_digest"],
                statement_sha256=row["statement_digest"],
            )
        signed = sign_verdict(doc, self._signer)
        db.execute(
            "INSERT INTO signed_verdicts VALUES(?,?,?,?)",
            (subject, row["t"], stamp, json.dumps(signed)),
        )

    def _publish(self, db: sqlite3.Connection, now: int) -> None:
        self.jobs._refresh(db, now)
        for row in db.execute("""SELECT h.challenge_id,a.*,e.proof_digest,e.statement_digest FROM challenge_handles h
                  JOIN audit_jobs a USING(job_id) LEFT JOIN audit_evidence e USING(job_id)
                  WHERE a.state='completed' AND NOT EXISTS(SELECT 1 FROM signed_verdicts v WHERE v.challenge_id=h.challenge_id)"""):
            self._persist(db, row["challenge_id"], row)
        # Each sampled leaf owns its deadline even when the proof job is shared with several holders.
        for row in db.execute("""SELECT s.leaf,s.due,s.missed,a.*,e.proof_digest,e.statement_digest FROM sampled_obligations s
                  JOIN audit_jobs a USING(job_id) LEFT JOIN audit_evidence e USING(job_id)
                  WHERE (s.missed=1 OR a.state='completed')
                    AND NOT EXISTS(SELECT 1 FROM sampled_verdict_ids v WHERE v.leaf=s.leaf)"""):
            subject = str(uuid.uuid4())
            self._persist(db, subject, row, missed_at=now if row["missed"] else None)
            db.execute(
                "INSERT INTO sampled_verdict_ids VALUES(?,?)", (row["leaf"], subject)
            )

    def _public(self, db: sqlite3.Connection, doc: str) -> dict[str, object]:
        def key(role: str, kid: str) -> bytes:
            row = db.execute(
                "SELECT public_key FROM verdict_keys WHERE key_id=?", (kid,)
            ).fetchone()
            if role != "auditor" or row is None:
                raise KeyError("Unknown auditor identity")
            return bytes(row[0])

        return verify_signed(json.loads(doc), key)

    def _lookup(
        self, challenge_id: str, capability: str, *, artifact: bool
    ) -> dict[str, object] | None:
        if not isinstance(capability, str) or not capability.isascii():
            return None
        with self.jobs._tx() as db:
            row = db.execute(
                "SELECT job_id,capability_hash FROM challenge_handles WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
            if row is None or not hmac.compare_digest(
                row["capability_hash"], hashlib.sha256(capability.encode()).digest()
            ):
                return None
            now = _us(self.jobs._clock())
            self._publish(db, now)
            state = db.execute(
                "SELECT state,completed_us FROM audit_jobs WHERE job_id=?",
                (row["job_id"],),
            ).fetchone()
            if (
                state["completed_us"] is not None
                and now >= state["completed_us"] + 30 * _DAY
            ):
                return None
            signed = db.execute(
                "SELECT document FROM signed_verdicts WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
            verdict = self._public(db, signed[0]) if signed else None
            if artifact:
                if verdict is None or verdict["outcome"] not in (
                    "CONFORMS",
                    "DEVIATES",
                ):
                    return None
                saved = db.execute(
                    """SELECT ciphertext FROM audit_evidence WHERE job_id=? AND proof_digest IS NOT NULL
                                 AND expires_us>?""",
                    (row["job_id"], now),
                ).fetchone()
                if saved is None or saved[0] is None:
                    return None
                decoded: dict[str, Any] = json.loads(self._box.decrypt(saved[0]))
                if (
                    hashlib.sha256(
                        base64.b64decode(decoded["proof"], validate=True)
                    ).hexdigest()
                    != verdict["proof_sha256"]
                    or hashlib.sha256(bytes.fromhex(decoded["statement"])).hexdigest()
                    != verdict["statement_sha256"]
                    or decoded["kind"]
                    != (
                        "conformance"
                        if verdict["outcome"] == "CONFORMS"
                        else "deviation"
                    )
                ):
                    raise ValueError("Private artifact differs from signed verdict")
                if _us(self.jobs._clock()) >= state["completed_us"] + 30 * _DAY:
                    return None
                return decoded
            result: dict[str, object] = {
                "challenge_id": challenge_id,
                "status": state["state"],
            }
            if verdict is not None:
                result["verdict"] = verdict
            return result

    def private_status(
        self, challenge_id: str, capability: str
    ) -> dict[str, object] | None:
        return self._lookup(challenge_id, capability, artifact=False)

    def private_proof(
        self, challenge_id: str, capability: str
    ) -> dict[str, object] | None:
        return self._lookup(challenge_id, capability, artifact=True)

    def _list(self, where: str, arg: object) -> list[dict[str, object]]:
        with self.jobs._tx() as db:
            self._publish(db, _us(self.jobs._clock()))
            return [
                self._public(db, r[0])
                for r in db.execute(
                    f"SELECT document FROM signed_verdicts WHERE {where} ORDER BY verified_us,challenge_id",
                    (arg,),
                )
            ]

    def by_commitment(self, t: str) -> list[dict[str, object]]:
        return self._list("t=?", t)

    def recent(self, hours: int) -> list[dict[str, object]]:
        if type(hours) is not int or not 1 <= hours <= 168:
            raise ValueError("Invalid public query interval")
        return self._list(
            "verified_us>=?", _us(self.jobs._clock()) - hours * 3_600_000_000
        )

    def stats(self) -> dict[str, object]:
        with self.jobs._tx() as db:
            now = _us(self.jobs._clock())
            self._publish(db, now)
            total = int(
                db.execute(
                    "SELECT (SELECT count(*) FROM challenge_handles)+(SELECT count(*) FROM sampled_obligations)"
                ).fetchone()[0]
            )
            counts = {
                k: 0
                for k in (
                    "conform",
                    "deviate",
                    "incomplete",
                    "excused_range",
                    "unavailable",
                )
            }
            names = {
                "CONFORMS": "conform",
                "DEVIATES": "deviate",
                "INCOMPLETE": "incomplete",
                "EXCUSED_RANGE": "excused_range",
                "UNAVAILABLE": "unavailable",
            }
            for name, count in db.execute(
                "SELECT json_extract(document,'$.outcome'),count(*) FROM signed_verdicts GROUP BY 1"
            ):
                counts[names[name]] = count
            return {
                "total_challenges": total,
                "pending": total - sum(counts.values()),
                "last_updated": _stamp(now),
                **counts,
            }
