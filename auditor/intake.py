"""Authenticate holder evidence and atomically admit one capability-scoped challenge."""

import hashlib
import hmac
import importlib
import json
import secrets
import sqlite3
import uuid
from collections.abc import Callable
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from nacl.public import PublicKey, SealedBox

from operations.private_db import private_database_file
from prover.request import build_statement

HOUR = 3600
DAY = 24 * HOUR


class IntakeError(Exception):
    def __init__(self, status: int, code: str, retry_after: int | None = None) -> None:
        super().__init__(code)
        self.status, self.code, self.retry_after = status, code, retry_after


def _utc() -> datetime:
    return datetime.now(timezone.utc)


class ChallengeIntake:
    def __init__(
        self,
        path: Path,
        *,
        descriptor: dict[str, Any],
        assets: Path | None,
        auditor_public_key: bytes,
        holder_hmac_key: bytes,
        clock: Callable[[], datetime] = _utc,
    ) -> None:
        if len(holder_hmac_key) != 32:
            raise ValueError("expected a private 32-byte holder-tag key")
        self._seal = SealedBox(PublicKey(auditor_public_key))
        self._tag_key = holder_hmac_key
        self._descriptor = json.loads(json.dumps(descriptor, allow_nan=False))
        self._assets, self._clock = assets, clock
        self.path = path
        private_database_file(path)
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS intake_identity(
                  singleton INTEGER PRIMARY KEY CHECK(singleton=1), key_tag BLOB NOT NULL, recipient BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS challenge_work(
                  job_id TEXT PRIMARY KEY, transcript TEXT NOT NULL, statement_tag BLOB NOT NULL,
                  material BLOB NOT NULL, received_us INTEGER NOT NULL, incomplete INTEGER NOT NULL,
                  UNIQUE(transcript,statement_tag));
                CREATE TABLE IF NOT EXISTS challenge_handles(
                  challenge_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES challenge_work(job_id),
                  capability_hash BLOB NOT NULL, holder_tag BLOB NOT NULL, transcript TEXT NOT NULL,
                  issued_us INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS challenge_by_holder ON challenge_handles(holder_tag,issued_us);
                CREATE INDEX IF NOT EXISTS challenge_by_transcript ON challenge_handles(transcript,issued_us);
            """)
            identity = hmac.digest(
                holder_hmac_key, b"vig/challenge/intake-key/1", "sha256"
            )
            db.execute(
                "INSERT OR IGNORE INTO intake_identity VALUES(1,?,?)",
                (identity, auditor_public_key),
            )
            if db.execute(
                "SELECT key_tag,recipient FROM intake_identity"
            ).fetchone() != (identity, auditor_public_key):
                raise ValueError(
                    "intake key configuration differs from the stored identity"
                )

    def _validate(
        self, bundle: dict[str, Any], index: int, now: datetime
    ) -> tuple[dict[str, Any], bool]:
        try:
            holder = importlib.import_module("verifier.holder")
        except ImportError:
            raise IntakeError(503, "verifier_unavailable") from None
        try:
            # Only the holder contract is retained. Omit optional proof data and unrelated extensions.
            frozen = {
                k: bundle[k]
                for k in ("verification", "max_tokens", "input", "text", "history")
            }
            verified = frozen["verification"]
            frozen["verification"] = {
                k: verified[k]
                for k in ("version", "receipt", "prompt_token_ids", "reply_token_ids")
            }
            history = frozen["history"]
            frozen["history"] = {
                "sth": {
                    k: history["sth"][k]
                    for k in (
                        "version",
                        "log_id",
                        "log_key_id",
                        "tree_size",
                        "timestamp",
                        "root_hash",
                        "signature",
                    )
                },
                "inclusion": {
                    k: history["inclusion"][k]
                    for k in ("leaf_index", "tree_size", "audit_path")
                },
            }
            frozen = json.loads(json.dumps(frozen, allow_nan=False))
            verified = frozen["verification"]
            receipt = verified["receipt"]
            served = datetime.fromisoformat(receipt["served_at"].replace("Z", "+00:00"))
            if (
                type(index) is not int
                or index < 0
                or frozen["history"]["inclusion"]["leaf_index"] != index
            ):
                raise ValueError("incorrect inclusion index")
            result = holder.verify(
                frozen,
                self._descriptor,
                assets=self._assets,
                receipt_only=True,
                now=now,
            )
            if result.outcome == "ASSETS_UNAVAILABLE":
                raise IntakeError(503, "verifier_unavailable")
            if (
                result.outcome not in ("RECEIPT_VERIFIED", "INCOMPLETE")
                or not verified["reply_token_ids"]
                or served > now
            ):
                raise ValueError("invalid holder evidence")
            if now >= served + timedelta(days=30):
                raise IntakeError(400, "expired")
            return frozen, result.outcome == "INCOMPLETE"
        except (AttributeError, TypeError, KeyError, ValueError, OverflowError):
            raise IntakeError(400, "invalid_bundle") from None

    def submit(
        self, holder: str, bundle: dict[str, Any], leaf_index: int
    ) -> dict[str, object]:
        if not isinstance(holder, str) or not holder:
            raise IntakeError(401, "unauthorized")
        material, incomplete = self._validate(bundle, leaf_index, self._clock())
        verification = material["verification"]
        receipt = verification["receipt"]
        t = receipt["transcript_commitment"]
        statement = build_statement(
            verification["prompt_token_ids"], verification["reply_token_ids"]
        )
        # A private, keyed tag avoids a dictionary oracle over the deterministic proof statement.
        statement_tag = hmac.digest(
            self._tag_key, b"vig/challenge/statement/1" + statement, "sha256"
        )
        owner = hmac.digest(
            self._tag_key, b"vig/challenge/holder/1" + holder.encode(), "sha256"
        )
        handle = str(uuid.uuid4())
        secret = secrets.token_urlsafe(32)
        sealed = self._seal.encrypt(
            json.dumps(material, separators=(",", ":"), allow_nan=False).encode()
        )
        with closing(sqlite3.connect(self.path, isolation_level=None)) as db, db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            now = self._clock()
            served = datetime.fromisoformat(receipt["served_at"].replace("Z", "+00:00"))
            if now < served or now >= served + timedelta(days=30):
                raise IntakeError(400, "expired")
            stamp = _micros(now)
            for field, value, seconds, maximum in (
                ("holder_tag", owner, HOUR, 10),
                ("transcript", t, DAY, 3),
            ):
                count, oldest = db.execute(
                    f"SELECT COUNT(*),MIN(issued_us) FROM challenge_handles WHERE {field}=? AND issued_us>?",
                    (value, stamp - seconds * 1_000_000),
                ).fetchone()
                if count >= maximum:
                    raise IntakeError(
                        429,
                        "rate_limited",
                        max(
                            1,
                            (oldest + seconds * 1_000_000 - stamp + 999_999)
                            // 1_000_000,
                        ),
                    )
            job = str(uuid.uuid4())
            db.execute(
                "INSERT INTO challenge_work VALUES(?,?,?,?,?,?) ON CONFLICT(transcript,statement_tag) DO NOTHING",
                (job, t, statement_tag, sealed, stamp, incomplete),
            )
            row = db.execute(
                "SELECT job_id FROM challenge_work WHERE transcript=? AND statement_tag=?",
                (t, statement_tag),
            ).fetchone()
            db.execute(
                "INSERT INTO challenge_handles VALUES(?,?,?,?,?,?)",
                (
                    handle,
                    row[0],
                    hashlib.sha256(secret.encode("ascii")).digest(),
                    owner,
                    t,
                    stamp,
                ),
            )
        return {"challenge_id": handle, "capability": secret, "status": "pending"}


def _micros(moment: datetime) -> int:
    return (moment - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(
        microseconds=1
    )
