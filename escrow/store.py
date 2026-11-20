"""Private, bounded RFC-0005 escrow and its recipient-encrypted transfer mailbox."""

from __future__ import annotations

import hmac
import json
import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from operations.private_db import private_database_file

from .crypto import seal_record, transfer_record
from .wakeup import Wakeup

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_LIFETIME = timedelta(minutes=5)  # W_escrow, specs/parameters.md
_MILLISECOND = timedelta(milliseconds=1)
_HEX = re.compile(r"[0-9a-f]{64}")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Binding:
    leaf_hash: str
    transcript_commitment: str
    served_at: str
    beacon_round: int
    sampling_mode: str

    def __post_init__(self) -> None:
        if not all(
            isinstance(v, str) and _HEX.fullmatch(v)
            for v in (self.leaf_hash, self.transcript_commitment)
        ):
            raise ValueError("Invalid escrow digest")
        if type(self.beacon_round) is not int or not 1 <= self.beacon_round < 1 << 64:
            raise ValueError("Invalid escrow round")
        if (
            self.sampling_mode not in ("live", "soak")
            or not isinstance(self.served_at, str)
            or not _TIME.fullmatch(self.served_at)
        ):
            raise ValueError("Invalid escrow metadata")
        try:
            self.deadline()
        except (OverflowError, ValueError):
            raise ValueError("Invalid escrow timestamp") from None

    def deadline(self) -> datetime:
        return datetime.fromisoformat(self.served_at[:-1] + "+00:00") + _LIFETIME

    def metadata(self) -> bytes:
        """Canonical AEAD context shared with the auditor, including the hard deadline."""
        return json.dumps(
            [
                "vig/escrow/1",
                self.leaf_hash,
                self.transcript_commitment,
                self.served_at,
                self.beacon_round,
                self.sampling_mode,
                (self.deadline() - _EPOCH) // _MILLISECOND,
            ],
            separators=(",", ":"),
        ).encode("ascii")


@dataclass(frozen=True)
class Transfer:
    binding: Binding
    ciphertext: bytes
    key_slot: bytes

    @property
    def leaf_hash(self) -> str:
        return self.binding.leaf_hash


def _binding(row: sqlite3.Row) -> Binding:
    return Binding(
        row["leaf_hash"], row["t"], row["served_at"], int(row["round"]), row["mode"]
    )


def _find(db: sqlite3.Connection, leaf: str) -> sqlite3.Row | None:
    row = db.execute(
        "SELECT leaf_hash,t,served_at,round,mode,deadline,status,identity_tag FROM records WHERE leaf_hash=?",
        (leaf,),
    ).fetchone()
    return cast("sqlite3.Row | None", row)


def _row(db: sqlite3.Connection, leaf: str) -> sqlite3.Row:
    row = _find(db, leaf)
    if row is None:
        raise KeyError("Unknown escrow leaf")
    return row


_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK(id=1), wrap_identity BLOB NOT NULL, recipient BLOB NOT NULL)",
    """CREATE TABLE IF NOT EXISTS records (
       leaf_hash TEXT PRIMARY KEY, t TEXT NOT NULL, served_at TEXT NOT NULL, round TEXT NOT NULL,
       mode TEXT NOT NULL, deadline INTEGER NOT NULL, identity_tag BLOB,
       status TEXT NOT NULL CHECK(status IN ('pending','transferring','unselected','selected','gap')),
       ciphertext BLOB, key_slot BLOB,
       CHECK ((status='pending')=(ciphertext IS NOT NULL) AND (status='pending')=(key_slot IS NOT NULL)
              AND (status='pending')=(identity_tag IS NOT NULL))
    )""",
    "CREATE INDEX IF NOT EXISTS pending_deadlines ON records(deadline) WHERE status IN ('pending','transferring')",
    """CREATE TABLE IF NOT EXISTS mailbox (
       leaf_hash TEXT PRIMARY KEY REFERENCES records(leaf_hash), ciphertext BLOB NOT NULL, key_slot BLOB NOT NULL
    )""",
)
_DROP = "UPDATE records SET status=?,identity_tag=NULL,ciphertext=NULL,key_slot=NULL WHERE leaf_hash=? AND status='pending'"


class EscrowStore:
    def __init__(
        self,
        path: str | Path,
        *,
        wrapping_key: bytes,
        auditor_public_key: bytes,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        if not all(
            isinstance(k, bytes) and len(k) == 32
            for k in (wrapping_key, auditor_public_key)
        ):
            raise ValueError("Invalid escrow key configuration")
        self._path = Path(path)
        private_database_file(self._path)
        self._wrap = wrapping_key
        self._recipient = auditor_public_key
        self._retry_key = hmac.digest(wrapping_key, b"vig/escrow/1/retry-key", "sha256")
        self.clock = clock
        self.changed = Wakeup(self._path)
        with self._transaction() as db:
            for ddl in _SCHEMA:
                db.execute(ddl)
            identity = hmac.digest(
                wrapping_key, b"vig/escrow/1/wrapping-key-id", "sha256"
            )
            db.execute(
                "INSERT OR IGNORE INTO config VALUES(1,?,?)",
                (identity, auditor_public_key),
            )
            keys = db.execute(
                "SELECT wrap_identity,recipient FROM config WHERE id=1"
            ).fetchone()
            if tuple(keys) != (identity, auditor_public_key):
                raise ValueError(
                    "Escrow key configuration differs from stored identities"
                )
            self._expire(db)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self._path, isolation_level=None)) as db, db:
            db.row_factory = sqlite3.Row
            if db.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise RuntimeError(
                    "Escrow requires rollback journaling with journal removal"
                )
            db.execute("PRAGMA secure_delete=ON")
            db.execute("PRAGMA temp_store=MEMORY")
            db.execute("PRAGMA synchronous=EXTRA")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            yield db

    def _time_ms(self) -> int:
        instant = self.clock()
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("Escrow clock must use a timezone")
        return (instant.astimezone(timezone.utc) - _EPOCH) // _MILLISECOND

    def _expire(self, db: sqlite3.Connection) -> int:
        now = self._time_ms()
        db.execute(
            """DELETE FROM mailbox WHERE leaf_hash IN (
                 SELECT leaf_hash FROM records WHERE status IN ('pending','transferring') AND deadline<=?
            )""",
            (now,),
        )
        return db.execute(
            """UPDATE records SET status='gap',identity_tag=NULL,ciphertext=NULL,key_slot=NULL
               WHERE status IN ('pending','transferring') AND deadline<=?""",
            (now,),
        ).rowcount

    def sweep(self) -> int:
        with self._transaction() as db:
            return self._expire(db)

    def next_expiry(self) -> datetime | None:
        with self._transaction() as db:
            deadline = db.execute(
                "SELECT MIN(deadline) FROM records WHERE status IN ('pending','transferring')"
            ).fetchone()[0]
            return None if deadline is None else _EPOCH + int(deadline) * _MILLISECOND

    def stage(self, binding: Binding, material: bytes) -> str:
        """Durably stage before promise. A retry can never extend the original deadline."""
        if not isinstance(material, bytes):
            raise TypeError("Escrow material must be bytes")
        with self._transaction() as db:
            self._expire(db)
            existing = _find(db, binding.leaf_hash)
        if existing is not None:
            if _binding(existing) != binding:
                raise ValueError("Escrow identity already binds different metadata")
            if existing["status"] != "pending":
                return str(existing["status"])

        deadline = (binding.deadline() - _EPOCH) // _MILLISECOND
        now = self._time_ms()
        if now < deadline - _LIFETIME // _MILLISECOND:
            raise ValueError("Cannot stage an escrow record before its served time")
        tag = ciphertext = slot = None
        if now < deadline:
            metadata = binding.metadata()
            identity = hmac.new(self._retry_key, metadata, "sha256")
            identity.update(material)
            tag = identity.digest()
            if existing is None:
                ciphertext, slot = seal_record(self._wrap, metadata, material)

        with self._transaction() as db:
            inserted = False
            if existing is None:
                pending = tag is not None and self._time_ms() < deadline
                result = db.execute(
                    """INSERT INTO records (leaf_hash,t,served_at,round,mode,deadline,identity_tag,status,ciphertext,key_slot)
                       VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(leaf_hash) DO NOTHING""",
                    (
                        binding.leaf_hash,
                        binding.transcript_commitment,
                        binding.served_at,
                        str(binding.beacon_round),
                        binding.sampling_mode,
                        deadline,
                        tag if pending else None,
                        "pending" if pending else "gap",
                        ciphertext if pending else None,
                        slot if pending else None,
                    ),
                )
                inserted = result.rowcount == 1
            self._expire(db)
            row = _row(db, binding.leaf_hash)
            status = str(row["status"])
            conflict = _binding(row) != binding or (
                status == "pending"
                and (tag is None or not hmac.compare_digest(row["identity_tag"], tag))
            )
            if inserted:
                # The worker takes the SQLite lock before computing its next deadline.
                self.changed.set()
        if conflict:
            raise ValueError("Escrow identity already binds different material")
        return status

    def binding(self, leaf_hash: str) -> Binding:
        with self._transaction() as db:
            self._expire(db)
            return _binding(_row(db, leaf_hash))

    def status(self, leaf_hash: str) -> str:
        with self._transaction() as db:
            self._expire(db)
            return str(_row(db, leaf_hash)["status"])

    def gap(self, leaf_hash: str) -> dict[str, object] | None:
        with self._transaction() as db:
            self._expire(db)
            row = _row(db, leaf_hash)
            if row["status"] != "gap":
                return None
            return {
                "leaf_hash": leaf_hash,
                "beacon_round": int(row["round"]),
                "reason": "escrow_expired",
            }

    def resolve(self, binding: Binding, *, selected: bool) -> str:
        """Commit a verified decision. Build the recipient envelope outside the write lock."""
        if type(selected) is not bool:
            raise TypeError("Escrow selection must be a boolean")
        leaf = binding.leaf_hash
        with self._transaction() as db:
            self._expire(db)
            row = _row(db, leaf)
            if _binding(row) != binding:
                raise ValueError("Decision metadata differs from staged escrow")
            if row["status"] != "pending":
                return str(row["status"])
            if not selected:
                outcome = "gap" if self._time_ms() >= row["deadline"] else "unselected"
                db.execute(_DROP, (outcome, leaf))
                return outcome
            ciphertext, slot = db.execute(
                "SELECT ciphertext,key_slot FROM records WHERE leaf_hash=?", (leaf,)
            ).fetchone()
        prepared = transfer_record(
            self._wrap, self._recipient, binding.metadata(), ciphertext, slot
        )
        with self._transaction() as db:
            self._expire(db)
            row = _row(db, leaf)
            if row["status"] != "pending":
                return str(row["status"])
            db.execute("INSERT INTO mailbox VALUES(?,?,?)", (leaf, *prepared))
            # Time spent preparing or writing a large selected transfer cannot extend custody.
            if self._time_ms() >= row["deadline"]:
                db.execute("DELETE FROM mailbox WHERE leaf_hash=?", (leaf,))
                outcome = "gap"
            else:
                outcome = "transferring"
            db.execute(_DROP, (outcome, leaf))
            return outcome

    def pending_transfers(self, limit: int) -> list[str]:
        if type(limit) is not int or not 1 <= limit < 1 << 63:
            raise ValueError("Invalid transfer page size")
        with self._transaction() as db:
            self._expire(db)
            return [
                str(r[0])
                for r in db.execute(
                    "SELECT leaf_hash FROM mailbox ORDER BY rowid LIMIT ?", (limit,)
                )
            ]

    def transfer(self, leaf_hash: str) -> Transfer | None:
        with self._transaction() as db:
            self._expire(db)
            record = _row(db, leaf_hash)
            row = db.execute(
                "SELECT ciphertext,key_slot FROM mailbox WHERE leaf_hash=?",
                (leaf_hash,),
            ).fetchone()
            if row is None:
                return None
            if self._time_ms() >= record["deadline"]:
                self._expire(db)
                return None
            return Transfer(_binding(record), bytes(row[0]), bytes(row[1]))

    def ack_transfer(self, leaf_hash: str) -> None:
        """Call after durable recipient acceptance; repeating acknowledgement is safe."""
        with self._transaction() as db:
            self._expire(db)
            status = _row(db, leaf_hash)["status"]
            if status == "transferring":
                db.execute("DELETE FROM mailbox WHERE leaf_hash=?", (leaf_hash,))
                self._expire(db)
                db.execute(
                    "UPDATE records SET status='selected' WHERE leaf_hash=? AND status='transferring'",
                    (leaf_hash,),
                )
                status = _row(db, leaf_hash)["status"]
        if status != "selected":
            raise ValueError("Escrow leaf has no timely selected transfer")
