"""Independent, durable observation of signed VIG histories and held promises."""

import hashlib
import json
import math
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from typing import Any, cast

from log import merkle
from log.receipt import checked_public_leaf, promise_backdated, verify_promise
from log.verification import verify_consistency, verify_head

Lookup = Callable[[str, str], bytes]
Read = Callable[[str], object]


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _object(data: object) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise TypeError("Expected a log response object")
    return data


class LogMonitor:
    """Pin one descriptor identity. Every persisted public leaf belongs to a checked head."""

    def __init__(
        self,
        path: Path,
        *,
        log_id: str,
        lookup_key: Lookup,
        clock: Callable[[], datetime] = _utc,
    ) -> None:
        self._path, self.log_id, self.lookup_key, self.clock = (
            path,
            log_id,
            lookup_key,
            clock,
        )
        if (
            len(log_id) != 64
            or bytes.fromhex(log_id).hex() != log_id
            or str(path) == ":memory:"
        ):
            raise ValueError("Persistent monitor path and pinned log identity required")
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1), log_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tip (id INTEGER PRIMARY KEY CHECK(id=1), signed TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS nodes (start INTEGER, width INTEGER, digest BLOB NOT NULL, PRIMARY KEY(start,width));
                CREATE TABLE IF NOT EXISTS leaves (idx INTEGER PRIMARY KEY, hash TEXT NOT NULL, metadata TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS leaf_digest ON leaves(hash);
                CREATE TABLE IF NOT EXISTS promises (hash TEXT PRIMARY KEY, due TEXT NOT NULL, witness TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, evidence TEXT NOT NULL, emitted INTEGER NOT NULL DEFAULT 0);
            """)
            db.execute("INSERT OR IGNORE INTO identity VALUES(1,?)", (log_id,))
            if db.execute("SELECT log_id FROM identity").fetchone()[0] != log_id:
                raise ValueError("Monitor database belongs to another log")

    def hold(
        self, receipt: Mapping[str, object], *, observed_at: datetime | None = None
    ) -> None:
        """Retain a verified promise; supply observation time only for a live delivery."""
        key = receipt.get("log_key_id")
        if not isinstance(key, str):
            raise TypeError("Missing promise key identity")
        verify_promise(
            receipt,
            log_id=self.log_id,
            log_key_id=key,
            public_key=self.lookup_key("log", key),
        )
        witness = {k: v for k, v in receipt.items() if k != "salt"}
        served = datetime.fromisoformat(
            str(receipt["served_at"]).replace("Z", "+00:00")
        )
        due = served + timedelta(seconds=10)
        with closing(sqlite3.connect(self._path)) as db, db:
            db.execute(
                "INSERT OR IGNORE INTO promises VALUES(?,?,?)",
                (receipt["leaf_hash"], due.isoformat(), _json(witness)),
            )
            if observed_at is not None and promise_backdated(served, observed_at):
                self._alert(
                    db,
                    "promise_backdated",
                    str(receipt["leaf_hash"]),
                    promise=witness,
                    delivery_observed_at=observed_at.astimezone(timezone.utc).isoformat(),
                )

    def verified_leaf(self, index: int) -> dict[str, object]:
        with closing(sqlite3.connect(self._path)) as db:
            row = db.execute(
                "SELECT metadata FROM leaves WHERE idx=?", (index,)
            ).fetchone()
            if row is None:
                raise KeyError("Leaf outside the authenticated history")
            return cast("dict[str,object]", json.loads(row[0]))

    def root_at(self, size: int) -> str:
        """Return a prefix root from the monitor's already authenticated local nodes."""
        with closing(sqlite3.connect(self._path)) as db:
            db.execute("BEGIN")
            row = db.execute("SELECT signed FROM tip").fetchone()
            if (
                row is None
                or type(size) is not int
                or not 0 <= size <= json.loads(row[0])["tree_size"]
            ):
                raise ValueError("Unknown authenticated prefix")

            def node(start: int, width: int) -> bytes:
                return bytes(
                    db.execute(
                        "SELECT digest FROM nodes WHERE start=? AND width=?",
                        (start, width),
                    ).fetchone()[0]
                )

            return merkle.root_hash(size, node).hex()

    def checkpoint(self) -> dict[str, Any] | None:
        with closing(sqlite3.connect(self._path)) as db:
            row = db.execute("SELECT signed FROM tip").fetchone()
            return _object(json.loads(row[0])) if row else None

    def incidents(self) -> list[dict[str, Any]]:
        with closing(sqlite3.connect(self._path)) as db:
            return [
                _object(json.loads(r[0]))
                for r in db.execute("SELECT evidence FROM alerts ORDER BY rowid")
            ]

    def _alert(
        self, db: sqlite3.Connection, kind: str, identity: str, **witness: object
    ) -> None:
        evidence = {
            "schema_version": 1,
            "kind": kind,
            "log_id": self.log_id,
            "observed_at": self.clock().isoformat(),
            **witness,
        }
        identifier = hashlib.sha256(_json([kind, identity]).encode()).hexdigest()
        db.execute(
            "INSERT OR IGNORE INTO alerts(id,evidence) VALUES(?,?)",
            (identifier, _json(evidence)),
        )

    def observe(self, read: Read, *, head: Mapping[str, object] | None = None) -> None:
        """Authenticate an independent head and correlate held promises. Fetch errors leave the tip intact."""
        signed = verify_head(
            _object(read("sth")) if head is None else head,
            log_id=self.log_id,
            lookup_key=self.lookup_key,
        )
        new = _object(signed)
        size = cast(int, new["tree_size"])
        observed = self.clock()
        if (
            observed.utcoffset() is None
            or datetime.fromisoformat(new["timestamp"].replace("Z", "+00:00"))
            > observed
        ):
            raise ValueError("Signed checkpoint lies beyond observation time")
        with closing(sqlite3.connect(self._path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT signed FROM tip").fetchone()
            old = _object(json.loads(row[0])) if row else None
            n = old["tree_size"] if old else 0

            def node(start: int, width: int) -> bytes:
                return bytes(
                    db.execute(
                        "SELECT digest FROM nodes WHERE start=? AND width=?",
                        (start, width),
                    ).fetchone()[0]
                )

            if old and size <= n:
                if merkle.root_hash(size, node).hex() != new["root_hash"]:
                    self._alert(
                        db,
                        "conflicting_history",
                        new["signature"],
                        previous=old,
                        observed=new,
                    )
                    return
                if size < n and new["timestamp"] > old["timestamp"]:
                    self._alert(
                        db,
                        "tree_size_regression",
                        new["signature"],
                        previous=old,
                        observed=new,
                    )
                    return
                if size < n or new["timestamp"] < old["timestamp"]:
                    new, size = old, n
            elif old:
                if new["timestamp"] < old["timestamp"]:
                    self._alert(
                        db,
                        "checkpoint_time_regression",
                        new["signature"],
                        previous=old,
                        observed=new,
                    )
                    return
                response = read(f"consistency?from={n}&to={size}")
                try:
                    bounds = _object(response)
                    if (
                        bounds.keys() != {"from", "to", "consistency_path"}
                        or type(bounds["from"]) is not int
                        or type(bounds["to"]) is not int
                        or (bounds["from"], bounds["to"]) != (n, size)
                    ):
                        raise ValueError("Wrong consistency bounds")
                    verify_consistency(
                        n,
                        size,
                        old["root_hash"],
                        new["root_hash"],
                        bounds["consistency_path"],
                    )
                except (TypeError, ValueError):
                    self._alert(
                        db,
                        "unverified_consistency",
                        new["signature"],
                        previous=old,
                        observed=new,
                    )
                    return
            db.execute("SAVEPOINT growth")
            try:
                for i in range(n, size):
                    leaf = checked_public_leaf(
                        _object(read(f"receipts/{i}")), index=i, log_id=self.log_id
                    )
                    digest = str(leaf["leaf_hash"])
                    db.executemany(
                        "INSERT INTO nodes VALUES(?,?,?)",
                        merkle.append_nodes(i, bytes.fromhex(digest), node),
                    )
                    db.execute(
                        "INSERT INTO leaves VALUES(?,?,?)", (i, digest, _json(leaf))
                    )
                if merkle.root_hash(size, node).hex() != new["root_hash"]:
                    raise ValueError(
                        "Listed history differs from its authenticated root"
                    )
            except (TypeError, ValueError):
                db.execute("ROLLBACK TO growth")
                self._alert(
                    db,
                    "unverified_leaf_history",
                    new["signature"],
                    previous=old,
                    observed=new,
                )
                return
            db.execute("RELEASE growth")
            db.execute("INSERT OR REPLACE INTO tip VALUES(1,?)", (_json(new),))
            for digest, due, witness in db.execute(
                "SELECT hash,due,witness FROM promises WHERE NOT EXISTS (SELECT 1 FROM leaves WHERE leaves.hash=promises.hash)"
            ):
                deadline = datetime.fromisoformat(due)
                if observed <= deadline:
                    continue
                kind = (
                    "omitted_promise"
                    if datetime.fromisoformat(new["timestamp"].replace("Z", "+00:00"))
                    >= deadline
                    else "overdue_checkpoint"
                )
                self._alert(
                    db, kind, digest, promise=json.loads(witness), checkpoint=new
                )

    def run(
        self,
        read: Read,
        stop: Event,
        *,
        interval: float,
        emit: Callable[[dict[str, Any]], None],
    ) -> None:
        """Retry unavailable observations and deliver durable incident alerts at least once."""
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError("Positive monitor interval required")
        while not stop.is_set():
            try:
                self.observe(read)
            except (OSError, ValueError, TypeError, KeyError):
                with closing(sqlite3.connect(self._path)) as db, db:
                    for digest, due, witness in db.execute(
                        "SELECT hash,due,witness FROM promises WHERE NOT EXISTS "
                        "(SELECT 1 FROM leaves WHERE leaves.hash=promises.hash)"
                    ):
                        if self.clock() > datetime.fromisoformat(due):
                            self._alert(
                                db,
                                "observation_unavailable",
                                digest,
                                promise=json.loads(witness),
                                checkpoint=self.checkpoint(),
                            )
            with closing(sqlite3.connect(self._path)) as db, db:
                for identifier, data in db.execute(
                    "SELECT id,evidence FROM alerts WHERE emitted=0 ORDER BY rowid"
                ):
                    emit(_object(json.loads(data)))
                    db.execute("UPDATE alerts SET emitted=1 WHERE id=?", (identifier,))
            stop.wait(interval)
