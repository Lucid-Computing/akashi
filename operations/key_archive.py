"""Durable Ed25519 public-key history for the log and auditor (RFC-0009)."""

import sqlite3
from contextlib import closing
from pathlib import Path


class PublicKeyArchive:
    """Keep one database per deployment in a directory writable only by its operator."""

    def __init__(self, path: Path) -> None:
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS verification_keys (
                    role TEXT NOT NULL CHECK(role IN ('log', 'auditor')),
                    key_id TEXT NOT NULL,
                    public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
                    active INTEGER NOT NULL CHECK(active IN (0, 1)),
                    PRIMARY KEY(role, key_id)
                )"""
            )
            db.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS current_key_per_role
                   ON verification_keys(role) WHERE active = 1"""
            )

    def rotate(
        self, role: str, key_id: str, public_key: bytes, *, replaces: str | None = None
    ) -> None:
        """Publish a fresh ID and key, retaining all earlier bindings for verification."""
        if role not in ("log", "auditor"):
            raise ValueError("unknown signing role")
        if (
            not isinstance(key_id, str)
            or not key_id.strip()
            or not key_id.isprintable()
        ):
            raise ValueError("expected a printable key ID")
        if type(public_key) is not bytes or len(public_key) != 32:
            raise ValueError("expected 32 raw Ed25519 public-key bytes")
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute(
                "SELECT key_id, public_key FROM verification_keys WHERE role = ? AND active = 1",
                (role,),
            ).fetchone()
            if current == (key_id, public_key):
                return
            if (current[0] if current else None) != replaces:
                raise ValueError("active key differs from the expected predecessor")
            db.execute(
                "UPDATE verification_keys SET active = 0 WHERE role = ? AND active = 1",
                (role,),
            )
            try:
                db.execute(
                    "INSERT INTO verification_keys VALUES (?, ?, ?, 1)",
                    (role, key_id, public_key),
                )
            except sqlite3.IntegrityError:
                raise ValueError(
                    "rotation requires an unused public key and a fresh ID for this role"
                ) from None

    def lookup(self, role: str, key_id: str) -> bytes:
        """Resolve the exact role and ID in historical evidence, including retired keys."""
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute(
                "SELECT public_key FROM verification_keys WHERE role = ? AND key_id = ?",
                (role, key_id),
            ).fetchone()
        if row is None:
            raise ValueError("unrecognized verification key")
        return bytes(row[0])

    def public_keys(self) -> list[dict[str, str | bool]]:
        """Return current and retired identities for publication in the service descriptor."""
        with closing(sqlite3.connect(self.path)) as db:
            return [
                {
                    "role": role,
                    "key_id": key_id,
                    "public_key": public_key.hex(),
                    "active": bool(active),
                }
                for role, key_id, public_key, active in db.execute(
                    "SELECT role, key_id, public_key, active FROM verification_keys ORDER BY role, key_id"
                )
            ]
