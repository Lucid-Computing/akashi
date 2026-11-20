"""Private storage of reserved pickup IDs and immutable, holder-encrypted envelopes."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from operations.private_db import private_database_file
from pickup.crypto import VERSION, PickupError, envelope_parts
from prover.submission import trusted_directory

PICKUP_LIFETIME = timedelta(days=7)  # W_pickup, specs/parameters.md.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_TICK = timedelta(microseconds=1)
_DIGEST = re.compile("[0-9a-f]{64}")


def _time(value: datetime) -> int:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("Expected a timezone-aware pickup timestamp")
    return (value - _EPOCH) // _TICK


def _clock() -> datetime:
    return datetime.now(timezone.utc)


class PickupStore:
    def __init__(
        self, path: str | Path, *, clock: Callable[[], datetime] = _clock
    ) -> None:
        self.path, self.clock = Path(path).absolute(), clock
        with trusted_directory(self.path.parent):
            private_database_file(self.path)
        with self._transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS clock(id INTEGER PRIMARY KEY CHECK(id=1), seen INTEGER NOT NULL)"
            )
            db.execute("INSERT OR IGNORE INTO clock VALUES(1,?)", (_time(clock()),))
            db.execute("""CREATE TABLE IF NOT EXISTS pickups(
                id TEXT PRIMARY KEY, binding TEXT NOT NULL, expires INTEGER NOT NULL,
                nonce BLOB, ciphertext BLOB, CHECK((nonce IS NULL)=(ciphertext IS NULL)))""")
            db.execute("CREATE INDEX IF NOT EXISTS pickup_expiry ON pickups(expires)")
            _, self.purged_on_open = self._expire(db)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path, isolation_level=None)) as db, db:
            if db.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise PickupError("Pickup storage requires a private rollback journal")
            db.execute("PRAGMA secure_delete=ON")
            db.execute("PRAGMA synchronous=EXTRA")
            db.execute("PRAGMA temp_store=MEMORY")
            db.execute("BEGIN IMMEDIATE")
            yield db

    def _expire(self, db: sqlite3.Connection) -> tuple[int, int]:
        db.execute(
            "UPDATE clock SET seen=max(seen,?) WHERE id=1", (_time(self.clock()),)
        )
        now = int(db.execute("SELECT seen FROM clock WHERE id=1").fetchone()[0])
        removed = db.execute("DELETE FROM pickups WHERE expires<=?", (now,)).rowcount
        return now, removed

    def sweep(self) -> int:
        """Remove expired ciphertexts and pending reservations, returning just a count."""
        with self._transaction() as db:
            return self._expire(db)[1]

    @staticmethod
    def _binding(
        pickup_id: str, tag: str, expires_at: datetime
    ) -> tuple[str, str, int]:
        if not all(
            isinstance(v, str) and _DIGEST.fullmatch(v) for v in (pickup_id, tag)
        ):
            raise PickupError("Invalid pickup reservation")
        return pickup_id, tag, _time(expires_at)

    def reserve(self, pickup_id: str, binding_tag: str, expires_at: datetime) -> None:
        """Bind the opaque ID to this private gateway retry tag and original deadline."""
        binding = self._binding(pickup_id, binding_tag, expires_at)
        with self._transaction() as db:
            now, _ = self._expire(db)
            permitted = now < binding[2] <= now + PICKUP_LIFETIME // _TICK
            if permitted:
                db.execute(
                    "INSERT OR IGNORE INTO pickups(id,binding,expires) VALUES(?,?,?)",
                    binding,
                )
                permitted = (
                    db.execute(
                        "SELECT 1 FROM pickups WHERE id=? AND binding=? AND expires=?",
                        binding,
                    ).fetchone()
                    is not None
                )
        if not permitted:
            raise PickupError("Pickup reservation expired or conflicted")

    def publish(
        self,
        pickup_id: str,
        binding_tag: str,
        envelope: dict[str, str],
        expires_at: datetime,
    ) -> None:
        binding = self._binding(pickup_id, binding_tag, expires_at)
        if not isinstance(envelope, dict) or envelope.keys() != {
            "version",
            "nonce",
            "ciphertext",
        }:
            raise PickupError("Invalid sealed pickup")
        nonce, ciphertext = envelope_parts(envelope)
        with self._transaction() as db:
            self._expire(db)
            existing = db.execute(
                "SELECT nonce IS NOT NULL FROM pickups WHERE id=? AND binding=? AND expires=?",
                binding,
            ).fetchone()
            if existing is not None and not existing[0]:
                db.execute(
                    "UPDATE pickups SET nonce=?,ciphertext=? WHERE id=?",
                    (nonce, ciphertext, pickup_id),
                )
        if existing is None:
            raise PickupError("Missing or expired pickup reservation")

    def get(self, pickup_id: str) -> dict[str, str] | None:
        if not isinstance(pickup_id, str) or not _DIGEST.fullmatch(pickup_id):
            return None
        with self._transaction() as db:
            self._expire(db)
            row = db.execute(
                "SELECT nonce,ciphertext FROM pickups WHERE id=? AND nonce IS NOT NULL",
                (pickup_id,),
            ).fetchone()
        if row is None:
            return None
        return {"version": VERSION, "nonce": row[0].hex(), "ciphertext": row[1].hex()}
