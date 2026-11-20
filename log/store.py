"""Atomic storage of RFC-0004 public leaves, Ed25519 promises and tree checkpoints."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import merkle

# The public preimage in docs/spec/03-data-model.md. No holder or escrow material.
_PREIMAGE_FIELDS = frozenset(
    {
        "log_id",
        "commitment_id",
        "render_profile",
        "params_digest",
        "transcript_commitment",
        "beacon_round",
        "served_at",
        "endpoint_id",
        "request_id",
        "log_key_id",
        "sampling_mode",
    }
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_MAX_SQLITE_INT = (1 << 63) - 1
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), log_id TEXT NOT NULL)",
    """CREATE TABLE IF NOT EXISTS writers (
        generation INTEGER PRIMARY KEY, key_id TEXT UNIQUE NOT NULL, public_key BLOB NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS leaves (
        leaf_index INTEGER PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, preimage TEXT NOT NULL,
        leaf_hash TEXT NOT NULL, promise_sig TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS nodes (
        start INTEGER NOT NULL, width INTEGER NOT NULL, digest BLOB NOT NULL,
        PRIMARY KEY (start, width)
    ) WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS heads (
        seq INTEGER PRIMARY KEY, tree_size INTEGER NOT NULL, timestamp TEXT NOT NULL,
        root_hash BLOB NOT NULL, key_id TEXT NOT NULL, signature BLOB NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS heads_by_size ON heads(tree_size, seq)",
    "CREATE INDEX IF NOT EXISTS heads_by_signer_size ON heads(key_id, tree_size, seq)",
)


class IdentityConflict(ValueError):
    """The request identity already has a promise for different public bytes."""


class WriterMismatch(ValueError):
    """The supplied signer or log identity differs from the authorized writer."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _uint64(value: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError("Expected an unsigned 64-bit integer")


def _read_node(db: sqlite3.Connection, start: int, width: int) -> bytes:
    row = db.execute(
        "SELECT digest FROM nodes WHERE start=? AND width=?", (start, width)
    ).fetchone()
    if row is None:
        raise RuntimeError("Missing stored Merkle node")
    return bytes(row["digest"])


def _head_row(db: sqlite3.Connection, size: int | None = None) -> sqlite3.Row:
    if size is None:
        row = db.execute("SELECT * FROM heads ORDER BY seq DESC LIMIT 1").fetchone()
    else:
        _uint64(size)
        if size > _MAX_SQLITE_INT:
            raise KeyError("Unknown tree size")
        row = db.execute(
            "SELECT * FROM heads WHERE tree_size=? ORDER BY seq DESC LIMIT 1", (size,)
        ).fetchone()
    if row is None:
        raise KeyError("Unknown tree size")
    return cast("sqlite3.Row", row)


def _leaf(row: sqlite3.Row) -> dict[str, object]:
    fields = cast("dict[str, object]", json.loads(row["preimage"]))
    return {**fields, "leaf_hash": row["leaf_hash"], "leaf_index": row["leaf_index"]}


class MerkleLog:
    """A file-backed log. Each operation uses its own SQLite transaction."""

    def __init__(
        self,
        path: str | Path,
        *,
        log_id: str,
        log_key_id: str,
        signing_key: Ed25519PrivateKey,
        leaf_hash: Callable[[Mapping[str, object]], str],
        clock: Callable[[], datetime] = _utc_now,
        checkpoint_seconds: int = 60,
        replaces_key_id: str | None = None,
    ) -> None:
        if not _DIGEST.fullmatch(log_id) or not log_key_id:
            raise ValueError("Invalid configured log identity")
        if str(path) in ("", ":memory:"):
            raise ValueError("A durable log requires a database file")
        if type(checkpoint_seconds) is not int or checkpoint_seconds <= 0:
            raise ValueError("Invalid checkpoint cadence")
        self._path = Path(path)
        self._log_id = log_id
        self._key_id = log_key_id
        self._key = signing_key
        self._public_key = signing_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self._leaf_hash = leaf_hash
        self.clock = clock
        self.checkpoint_seconds = checkpoint_seconds
        with self._transaction(write=True) as db:
            for ddl in _SCHEMA:
                db.execute(ddl)
            self._configure_writer(db, replaces_key_id)

    @contextmanager
    def _transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self._path, isolation_level=None)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db

    def _configure_writer(self, db: sqlite3.Connection, replaces: str | None) -> None:
        identity = db.execute(
            "SELECT log_id FROM identity WHERE singleton=1"
        ).fetchone()
        active = db.execute(
            "SELECT * FROM writers ORDER BY generation DESC LIMIT 1"
        ).fetchone()
        if identity is None:
            if replaces is not None or active is not None:
                raise WriterMismatch("Missing predecessor for log signing key")
            db.execute("INSERT INTO identity VALUES (1, ?)", (self._log_id,))
            timestamp = self._timestamp()
            size, root = 0, merkle.root_hash(0, lambda s, w: _read_node(db, s, w))
        else:
            if identity["log_id"] != self._log_id or active is None:
                raise WriterMismatch("Log identity mismatch")
            if active["key_id"] == self._key_id:
                if active["public_key"] != self._public_key:
                    raise WriterMismatch("Log signing public key mismatch")
                if replaces is not None:
                    previous = db.execute(
                        "SELECT key_id FROM writers WHERE generation < ? ORDER BY generation DESC LIMIT 1",
                        (active["generation"],),
                    ).fetchone()
                    if previous is None or previous["key_id"] != replaces:
                        raise WriterMismatch("Unexpected signing key predecessor")
                return
            if (
                replaces != active["key_id"]
                or db.execute(
                    "SELECT 1 FROM writers WHERE key_id=?", (self._key_id,)
                ).fetchone()
                is not None
            ):
                raise WriterMismatch("Unexpected or retired log signing key")
            head = _head_row(db)
            timestamp = self._timestamp()
            if timestamp < head["timestamp"]:
                raise ValueError("Log clock precedes the last signed checkpoint")
            size, root = int(head["tree_size"]), bytes(head["root_hash"])
        db.execute(
            "INSERT INTO writers(key_id, public_key) VALUES (?,?)",
            (self._key_id, self._public_key),
        )
        self._sign_head(db, size, root, timestamp)

    def _require_writer(self, db: sqlite3.Connection) -> None:
        active = db.execute(
            "SELECT key_id, public_key FROM writers ORDER BY generation DESC LIMIT 1"
        ).fetchone()
        if active is None or (active["key_id"], active["public_key"]) != (
            self._key_id,
            self._public_key,
        ):
            raise WriterMismatch("Inactive log signing key")

    def _timestamp(self) -> str:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Log clock must use a timezone")
        return (
            now.astimezone(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    def _sign_head(
        self, db: sqlite3.Connection, size: int, root: bytes, timestamp: str
    ) -> None:
        preimage = (
            b"STH"
            + bytes.fromhex(self._log_id)
            + size.to_bytes(8, "big")
            + timestamp.encode("ascii")
            + root
        )
        db.execute(
            "INSERT INTO heads(tree_size,timestamp,root_hash,key_id,signature) VALUES (?,?,?,?,?)",
            (size, timestamp, root, self._key_id, self._key.sign(preimage)),
        )

    def _head(self, row: sqlite3.Row) -> dict[str, object]:
        return {
            "version": "vig-log/1",
            "log_id": self._log_id,
            "log_key_id": row["key_id"],
            "tree_size": row["tree_size"],
            "timestamp": row["timestamp"],
            "root_hash": bytes(row["root_hash"]).hex(),
            "signature": bytes(row["signature"]).hex(),
        }

    def head(
        self, size: int | None = None, *, log_key_id: str | None = None
    ) -> dict[str, object]:
        """Latest checkpoint, optionally for a historical size and its signing epoch."""
        with self._transaction() as db:
            if log_key_id is None:
                return self._head(_head_row(db, size))
            if size is None:
                raise ValueError("Specify a tree size for historical signer lookup")
            _uint64(size)
            if size <= _MAX_SQLITE_INT:
                row = db.execute(
                    "SELECT * FROM heads WHERE key_id=? AND tree_size=? ORDER BY seq DESC LIMIT 1",
                    (log_key_id, size),
                ).fetchone()
                if row is not None:
                    return self._head(row)
            raise KeyError("Unknown checkpoint")

    def checkpoint(self) -> dict[str, object]:
        """Sign an idle head only when the cadence elapses; return the latest head."""
        with self._transaction(write=True) as db:
            self._require_writer(db)
            old = _head_row(db)
            now = self._timestamp()
            delta = datetime.fromisoformat(now[:-1]) - datetime.fromisoformat(
                old["timestamp"][:-1]
            )
            if delta.total_seconds() < self.checkpoint_seconds:
                return self._head(old)
            self._sign_head(db, old["tree_size"], old["root_hash"], now)
            return self._head(_head_row(db))

    def append(self, preimage: Mapping[str, object]) -> dict[str, object]:
        """Return the original promise for an identical retry, including after rotation."""
        fields = dict(preimage)
        if fields.keys() not in (_PREIMAGE_FIELDS, _PREIMAGE_FIELDS | {"leaf_hash"}):
            raise ValueError("Invalid public append fields")
        if fields["log_id"] != self._log_id:
            raise WriterMismatch("Log identity mismatch")
        if type(fields["beacon_round"]) is not int or any(
            not isinstance(fields[name], str)
            for name in _PREIMAGE_FIELDS - {"beacon_round"}
        ):
            raise ValueError("Invalid public append field type")
        has_claimed_hash = "leaf_hash" in fields
        claimed_hash = fields.pop("leaf_hash", None)
        digest = self._leaf_hash(fields)
        if not _DIGEST.fullmatch(digest) or (
            has_claimed_hash and claimed_hash != digest
        ):
            raise ValueError("Invalid public leaf hash")
        encoded = json.dumps(
            fields, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        with self._transaction(write=True) as db:
            row = db.execute(
                "SELECT * FROM leaves WHERE request_id=?", (fields["request_id"],)
            ).fetchone()
            if row is not None:
                if row["preimage"] != encoded or row["leaf_hash"] != digest:
                    raise IdentityConflict(
                        "Request identity already has different public bytes"
                    )
                return {**_leaf(row), "promise_sig": row["promise_sig"]}
            self._require_writer(db)
            if fields["log_key_id"] != self._key_id:
                raise WriterMismatch("Append does not use the active signing key")
            head = _head_row(db)
            timestamp = self._timestamp()
            if timestamp < head["timestamp"]:
                raise ValueError("Log clock precedes the last signed checkpoint")
            index = int(head["tree_size"])
            raw_hash = bytes.fromhex(digest)
            signature = self._key.sign(
                b"PromiseReceipt" + bytes.fromhex(self._log_id) + raw_hash
            ).hex()
            db.execute(
                "INSERT INTO leaves VALUES (?,?,?,?,?)",
                (index, fields["request_id"], encoded, digest, signature),
            )

            def read(start: int, width: int) -> bytes:
                return _read_node(db, start, width)

            db.executemany(
                "INSERT INTO nodes VALUES (?,?,?)",
                merkle.append_nodes(index, raw_hash, read),
            )
            self._sign_head(db, index + 1, merkle.root_hash(index + 1, read), timestamp)
            return {
                **fields,
                "leaf_hash": digest,
                "leaf_index": index,
                "promise_sig": signature,
            }

    def receipt(self, index: int) -> dict[str, object]:
        _uint64(index)
        if index <= _MAX_SQLITE_INT:
            with self._transaction() as db:
                row = db.execute(
                    "SELECT * FROM leaves WHERE leaf_index=?", (index,)
                ).fetchone()
                if row is not None:
                    return _leaf(row)
        raise KeyError("Unknown leaf index")

    def receipts(self, start: int, end: int) -> list[dict[str, object]]:
        _uint64(start)
        _uint64(end)
        if not 0 <= end - start <= 10_000:
            raise ValueError("Invalid public leaf range")
        if start > _MAX_SQLITE_INT:
            return []
        with self._transaction() as db:
            rows = db.execute(
                "SELECT * FROM leaves WHERE leaf_index>=? ORDER BY leaf_index LIMIT ?",
                (start, end - start),
            )
            return [_leaf(row) for row in rows]

    def path(self, index: int, size: int) -> tuple[bytes, ...]:
        with self._transaction() as db:
            _head_row(db, size)
            return merkle.inclusion_path(index, size, lambda s, w: _read_node(db, s, w))

    def consistency(self, old_size: int, new_size: int) -> tuple[bytes, ...]:
        with self._transaction() as db:
            _head_row(db, new_size)
            return merkle.consistency_path(
                old_size, new_size, lambda s, w: _read_node(db, s, w)
            )
