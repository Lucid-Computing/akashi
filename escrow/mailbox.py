"""Durable auditor-owned receipt of selected transfers from an authenticated outbox."""

import hashlib
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from nacl.public import PrivateKey

from .crypto import open_transfer
from .store import Binding, Transfer, _private_file


class AuditorInbox:
    """accept() returns the leaf hash after commit. The sender can then acknowledge it.

    The caller authenticates the sending service. A byte-identical redelivery confirms
    prior acceptance even after the transfer deadline. A missed acknowledgment alone
    leaves the sender unable to determine whether the auditor committed the job.
    """

    def __init__(
        self,
        path: Path,
        *,
        auditor_private_key: bytes,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self._key = bytes(PrivateKey(auditor_private_key))
        self._clock = clock if clock is not None else lambda: datetime.now(timezone.utc)
        with self._db() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS selected_jobs (
                    leaf_hash TEXT PRIMARY KEY NOT NULL,
                    transcript_commitment TEXT NOT NULL,
                    served_at TEXT NOT NULL,
                    beacon_round TEXT NOT NULL,
                    sampling_mode TEXT NOT NULL,
                    envelope_digest BLOB NOT NULL,
                    ciphertext BLOB,
                    key_slot BLOB,
                    CHECK ((ciphertext IS NULL) = (key_slot IS NULL))
                )
            """)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        _private_file(self.path)
        with closing(sqlite3.connect(self.path)) as db:
            if db.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise ValueError("auditor inbox requires a private rollback journal")
            db.execute("PRAGMA secure_delete=ON")
            db.execute("PRAGMA synchronous=EXTRA")
            with db:
                yield db

    def accept(self, transfer: Transfer) -> str:
        """Durably acquire a selected job within W_escrow, or confirm the exact retry."""
        binding = transfer.binding
        metadata = binding.metadata()
        leaf = binding.leaf_hash
        # Retain a digest of the encrypted envelope after purge. This permits
        # exact retry confirmation without keeping private material or a plaintext hash.
        envelope_digest = hashlib.sha256(
            hashlib.sha256(metadata).digest()
            + hashlib.sha256(transfer.ciphertext).digest()
            + hashlib.sha256(transfer.key_slot).digest()
        ).digest()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT envelope_digest FROM selected_jobs WHERE leaf_hash=?", (leaf,)
            ).fetchone()
            if existing is not None:
                if existing[0] != envelope_digest:
                    raise ValueError("conflicting auditor transfer")
                return leaf
            deadline = binding.deadline()
            now = self._clock()
            if now < datetime.fromisoformat(binding.served_at[:-1] + "+00:00"):
                raise ValueError("auditor transfer predates delivery")
            if now >= deadline:
                raise ValueError("auditor transfer deadline elapsed")
            open_transfer(self._key, metadata, transfer.ciphertext, transfer.key_slot)
            db.execute(
                "INSERT INTO selected_jobs VALUES (?,?,?,?,?,?,?,?)",
                (
                    leaf,
                    binding.transcript_commitment,
                    binding.served_at,
                    str(binding.beacon_round),
                    binding.sampling_mode,
                    envelope_digest,
                    transfer.ciphertext,
                    transfer.key_slot,
                ),
            )
            if self._clock() >= deadline:
                raise ValueError("auditor transfer deadline elapsed")
        return leaf

    def read(self, binding: Binding | str) -> bytes | None:
        """Recover a retained job by leaf hash, optionally checking the supplied binding."""
        leaf = binding if isinstance(binding, str) else binding.leaf_hash
        with self._db() as db:
            row = db.execute(
                "SELECT transcript_commitment, served_at, beacon_round, sampling_mode, "
                "ciphertext, key_slot FROM selected_jobs WHERE leaf_hash=?",
                (leaf,),
            ).fetchone()
        if row is None or row[4] is None:
            return None
        stored = Binding(leaf, row[0], row[1], int(row[2]), row[3])
        if isinstance(binding, Binding) and stored != binding:
            raise ValueError("auditor job binding mismatch")
        return open_transfer(self._key, stored.metadata(), row[4], row[5])

    def purge(self, leaf_hash: str) -> bool:
        """Erase the private job on handoff or the audit retention deadline (#30)."""
        with self._db() as db:
            cursor = db.execute(
                "UPDATE selected_jobs SET ciphertext=NULL, key_slot=NULL "
                "WHERE leaf_hash=? AND ciphertext IS NOT NULL",
                (leaf_hash,),
            )
            return cursor.rowcount == 1
