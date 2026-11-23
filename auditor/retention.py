"""Erase CH private material at the verdict deadline, retaining signed public history."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from operations.private_db import private_database_file

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_RETENTION_US = timedelta(days=30) // timedelta(microseconds=1)


def expire_private(db: sqlite3.Connection, now_us: int) -> int:
    """Use the caller's serialized transaction and secure-delete connection."""
    cutoff = now_us - _RETENTION_US
    completed = "SELECT job_id FROM audit_jobs WHERE completed_us <= ?"
    tables = {
        r[0] for r in db.execute("SELECT name FROM sqlite_schema WHERE type='table'")
    }
    if not {"challenge_work", "challenge_handles", "audit_jobs"}.issubset(tables):
        raise ValueError("Expected the challenge and audit job database")
    # Keep a content-free work identity for signed histories and retry reconciliation.
    count = db.execute(
        f"""UPDATE challenge_work SET material=X'', statement_tag=randomblob(32)
            WHERE length(material)>0 AND job_id IN ({completed})""",
        (cutoff,),
    ).rowcount
    count += db.execute(
        f"""UPDATE challenge_handles SET capability_hash=X'', holder_tag=X''
            WHERE length(capability_hash)>0 AND job_id IN ({completed})""",
        (cutoff,),
    ).rowcount
    if "audit_evidence" in tables:
        # Older stores may already hold large proof blobs when retention first runs.
        db.execute(
            """CREATE INDEX IF NOT EXISTS evidence_live_expiry
               ON audit_evidence(expires_us) WHERE ciphertext IS NOT NULL"""
        )
        count += db.execute(
            """UPDATE audit_evidence SET ciphertext=NULL
               WHERE ciphertext IS NOT NULL AND expires_us<=?""",
            (now_us,),
        ).rowcount
    if "selected_transcripts" in tables:
        deadline = (
            "COALESCE(v.verified_us, a.completed_us)"
            if "sampled_verdict_ids" in tables
            else "a.completed_us"
        )
        signed = (
            """LEFT JOIN sampled_verdict_ids i ON i.leaf=s.leaf
                     LEFT JOIN signed_verdicts v ON v.challenge_id=i.subject"""
            if "sampled_verdict_ids" in tables
            else ""
        )
        count += db.execute(
            f"""UPDATE selected_transcripts SET material=NULL
                WHERE material IS NOT NULL AND leaf IN (
                SELECT s.leaf FROM sampled_obligations s JOIN audit_jobs a USING(job_id)
                {signed} WHERE {deadline} <= ?)""",
            (cutoff,),
        ).rowcount
    if "signed_verdicts" in tables:
        # A signer recovering later can still publish a redacted handle's verdict.
        db.execute("""DELETE FROM challenge_handles WHERE capability_hash=X'' AND
            EXISTS(SELECT 1 FROM signed_verdicts v WHERE v.challenge_id=challenge_handles.challenge_id)""")
    return count


def sweep(path: Path, now: datetime | None = None) -> int:
    """Run one role-local sweep without loading a signing or decryption key."""
    if not path.is_file():
        raise ValueError("Missing challenge database")
    private_database_file(path)
    moment = now if now is not None else datetime.now(timezone.utc)
    stamp = (moment - _EPOCH) // timedelta(microseconds=1)
    with closing(sqlite3.connect(path, isolation_level=None)) as db, db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA secure_delete=ON")
        if db.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            raise ValueError("Challenge retention requires a private rollback journal")
        db.execute("BEGIN IMMEDIATE")
        return expire_private(db, stamp)
