"""Durable auditor-owned receipt of selected transfers from an authenticated outbox."""

import hashlib
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from nacl.public import PrivateKey

from operations.private_db import private_database_file

from .crypto import open_transfer
from .store import Binding, Transfer


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
            db.execute("""CREATE TABLE IF NOT EXISTS selected_handoffs(
                leaf_hash TEXT PRIMARY KEY NOT NULL REFERENCES selected_jobs(leaf_hash),
                job_id TEXT)""")

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        private_database_file(self.path)
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
                "ciphertext, key_slot FROM selected_jobs WHERE leaf_hash=? AND NOT EXISTS "
                "(SELECT 1 FROM selected_handoffs WHERE leaf_hash=selected_jobs.leaf_hash)",
                (leaf,),
            ).fetchone()
        if row is None or row[4] is None:
            return None
        stored = Binding(leaf, row[0], row[1], int(row[2]), row[3])
        if isinstance(binding, Binding) and stored != binding:
            raise ValueError("auditor job binding mismatch")
        return open_transfer(self._key, stored.metadata(), row[4], row[5])

    def handoff(
        self, binding: Binding, commit: Callable[[bytes, bytes], str]
    ) -> str | None:
        """Move a selected carrier to idempotent CH custody and keep its durable receipt.

        CH commits the complete private transcript before returning its stable job ID.
        If a process dies between commits, retrying the same leaf confirms CH custody.
        Once the handoff starts, only this operation may read the carrier.
        """
        leaf = binding.leaf_hash
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT s.transcript_commitment,s.served_at,s.beacon_round,s.sampling_mode,
                          s.ciphertext,s.key_slot,h.job_id,s.envelope_digest
                   FROM selected_jobs s LEFT JOIN selected_handoffs h USING(leaf_hash)
                   WHERE s.leaf_hash=?""",
                (leaf,),
            ).fetchone()
            if row is None:
                return None
            stored = Binding(leaf, row[0], row[1], int(row[2]), row[3])
            if stored != binding:
                raise ValueError("auditor job binding mismatch")
            if row[6] is not None:
                return str(row[6])
            if row[4] is None:
                return None
            db.execute(
                "INSERT OR IGNORE INTO selected_handoffs(leaf_hash) VALUES(?)", (leaf,)
            )

        # The destination may use a different SQLite file or the same role database.
        # Never hold an inbox write transaction across the destination's commit.
        payload = open_transfer(self._key, binding.metadata(), row[4], row[5])
        job = commit(payload, row[7])
        if not isinstance(job, str) or not job:
            raise ValueError("missing durable challenge job receipt")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            saved = db.execute(
                "SELECT job_id FROM selected_handoffs WHERE leaf_hash=?", (leaf,)
            ).fetchone()
            if saved is None or saved[0] not in (None, job):
                raise ValueError("conflicting durable challenge job receipt")
            db.execute(
                "UPDATE selected_handoffs SET job_id=? WHERE leaf_hash=?", (job, leaf)
            )
            db.execute(
                "UPDATE selected_jobs SET ciphertext=NULL,key_slot=NULL WHERE leaf_hash=?",
                (leaf,),
            )
        return job

    def purge(self, leaf_hash: str) -> bool:
        """Erase the private job on handoff or the audit retention deadline (#30)."""
        with self._db() as db:
            cursor = db.execute(
                "UPDATE selected_jobs SET ciphertext=NULL, key_slot=NULL "
                "WHERE leaf_hash=? AND ciphertext IS NOT NULL AND NOT EXISTS "
                "(SELECT 1 FROM selected_handoffs WHERE leaf_hash=selected_jobs.leaf_hash "
                "AND job_id IS NULL)",
                (leaf_hash,),
            )
            return cursor.rowcount == 1


def reconcile_handoffs(audit_path: Path, inbox_path: Path) -> int:
    """Finish CH-committed inbox transfers without opening a private envelope."""
    for path in (audit_path, inbox_path):
        if not path.is_file():
            raise ValueError("Missing private handoff database")
        private_database_file(path)
    schema = "main" if audit_path.samefile(inbox_path) else "challenge"
    with closing(sqlite3.connect(inbox_path, isolation_level=None)) as db, db:
        if schema == "challenge":
            db.execute("ATTACH DATABASE ? AS challenge", (str(audit_path),))
        if any(
            db.execute(f"PRAGMA {name}.journal_mode").fetchone()[0] != "delete"
            for name in {"main", schema}
        ):
            raise ValueError(
                "Handoff reconciliation requires private rollback journals"
            )
        db.execute("PRAGMA main.secure_delete=ON")
        db.execute("PRAGMA main.synchronous=EXTRA")
        db.execute("BEGIN IMMEDIATE")
        local = {
            r[0]
            for r in db.execute(
                "SELECT name FROM main.sqlite_schema WHERE type='table'"
            )
        }
        remote = {
            r[0]
            for r in db.execute(
                f"SELECT name FROM {schema}.sqlite_schema WHERE type='table'"
            )
        }
        if "selected_jobs" not in local or "challenge_work" not in remote:
            raise ValueError("Expected the auditor inbox and challenge databases")
        if "selected_handoffs" not in local or "selected_transcripts" not in remote:
            return 0
        columns = {
            r[1]
            for r in db.execute(f"PRAGMA {schema}.table_info(selected_transcripts)")
        }
        if "envelope_digest" not in columns:
            return 0
        db.execute(
            """CREATE TEMP TABLE confirmed(leaf TEXT PRIMARY KEY,job TEXT NOT NULL)"""
        )
        db.execute(f"""INSERT INTO confirmed
            SELECT s.leaf_hash,a.job_id FROM main.selected_jobs s
            JOIN main.selected_handoffs h ON h.leaf_hash=s.leaf_hash
            JOIN {schema}.selected_transcripts p ON p.leaf=s.leaf_hash
            JOIN {schema}.sampled_obligations o ON o.leaf=p.leaf
            JOIN {schema}.audit_jobs a ON a.job_id=o.job_id AND a.t=s.transcript_commitment
            WHERE h.job_id IS NULL AND s.ciphertext IS NOT NULL
            AND length(p.envelope_digest)=32 AND p.envelope_digest=s.envelope_digest""")
        db.execute("""UPDATE main.selected_handoffs SET job_id=(
                      SELECT job FROM confirmed WHERE leaf=leaf_hash)
                      WHERE leaf_hash IN (SELECT leaf FROM confirmed)""")
        result = db.execute("""UPDATE main.selected_jobs SET ciphertext=NULL,key_slot=NULL
                      WHERE leaf_hash IN (SELECT leaf FROM confirmed)""")
        return result.rowcount
