"""Durable one-request submissions to the pinned FlashProve spool (RFC-0006)."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import hmac
import os
import re
import sqlite3
import stat
import struct
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from prover.request import WINDOW, build_spool_request, build_statement

COMMITMENT = "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46"
_MARK = f"cp-folder 1\nkind spool\ncommitment {COMMITMENT}\n".encode("ascii")
_DIR = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY
_FILE = os.O_NOFOLLOW | os.O_NONBLOCK
_WORDS = struct.Struct(f"<{WINDOW + 2}I")


class SpoolError(RuntimeError):
    """Spool permissions, identity, hold or durable publication state is invalid."""


def _ancestors(path: Path, links: int = 0) -> int:
    """Open trusted ancestors. Resolve owner-controlled system links such as macOS /tmp."""
    if links > 40 or ".." in path.parts or not path.is_absolute():
        raise SpoolError("Unsafe private directory ancestry")
    fd = os.open("/", _DIR)
    try:
        parent = Path("/")
        for name in path.parts[1:]:
            about = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if about.st_uid not in (0, os.geteuid()):
                raise SpoolError("Untrusted private directory ancestry")
            if stat.S_ISLNK(about.st_mode):
                target = Path(os.readlink(name, dir_fd=fd))
                child = _ancestors(parent / target, links + 1)
            else:
                child = os.open(name, _DIR, dir_fd=fd)
            os.close(fd)
            fd = child
            about = os.fstat(fd)
            if about.st_uid not in (0, os.geteuid()) or (
                about.st_mode & 0o022 and not about.st_mode & stat.S_ISVTX
            ):
                raise SpoolError("Writable private directory ancestry")
            parent /= name
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def trusted_directory(path: str | Path) -> Iterator[int]:
    """Open a read-only parent that trusted owners control, including its ancestry."""
    fd = _ancestors(Path(path).absolute())
    try:
        yield fd
    finally:
        os.close(fd)


@contextmanager
def private_directory(
    path: str | Path, *, parent_fd: int | None = None, create: bool = False
) -> Iterator[int]:
    """Yield a verified role-owned private directory descriptor; creation is single-level."""
    path = Path(path)
    if parent_fd is None:
        absolute = path.absolute()
        with (
            trusted_directory(absolute.parent) as fd,
            private_directory(absolute.name, parent_fd=fd, create=create) as child,
        ):
            yield child
        return
    if len(path.parts) != 1 or path.name in ("", ".", ".."):
        raise SpoolError("Invalid private subdirectory")
    if create:
        try:
            os.mkdir(path, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        else:
            os.fsync(parent_fd)
    fd = os.open(path, _DIR, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise SpoolError("Directory is not private to this role")
        for forbidden in ("seed.bin", "isk.txt"):
            if _exists(fd, forbidden):
                raise SpoolError("Refusing a secret-key directory")
        yield fd
    finally:
        os.close(fd)


def _exists(fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def check_spool(fd: int) -> None:
    if _exists(fd, "hold"):
        raise SpoolError("Proof spool on hold")
    try:
        mark = os.open("mark.txt", _FILE | os.O_RDONLY, dir_fd=fd)
    except OSError:
        raise SpoolError("Missing or unsafe proof spool mark") from None
    with os.fdopen(mark, "rb") as stream:
        info = os.fstat(mark)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
            or info.st_nlink != 1
            or stream.read(len(_MARK) + 1) != _MARK
        ):
            raise SpoolError("Proof spool does not identify the pinned commitment")


@contextmanager
def guarded_spool(spool_dir: str | Path) -> Iterator[int]:
    with private_directory(spool_dir) as fd:
        check_spool(fd)
        yield fd


@dataclass(frozen=True, repr=False)
class Submission:
    job_id: str
    request_id: str
    statement: bytes
    tag_key: bytes
    deadline_ns: int


def _split(statement: bytes) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if not isinstance(statement, bytes) or len(statement) != _WORDS.size:
        raise ValueError("Invalid proof statement")
    words = _WORDS.unpack(statement)
    r, e = words[-2:]
    if not 0 <= r < e < WINDOW:
        raise ValueError("Invalid proof statement range")
    prompt, reply = words[: r + 1], words[r + 1 : e + 1]
    if build_statement(prompt, reply) != statement:
        raise ValueError("Invalid proof statement padding")
    return prompt, reply


def _rename_once(source: str, src_fd: int, target: str, dst_fd: int) -> None:
    """Atomically consume the private source, without replacing a queued request."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        rename, flag = getattr(libc, "renameat2", None), 1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        rename, flag = getattr(libc, "renameatx_np", None), 4  # RENAME_EXCL
    else:
        rename, flag = None, 0
    if rename is None:
        raise SpoolError("Filesystem requires atomic no-replace rename")
    if rename(src_fd, os.fsencode(source), dst_fd, os.fsencode(target), flag) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise SpoolError("Refusing to replace an existing proof request")
        raise OSError(error, "Atomic proof request publication failed")


def _private_file(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        raise SpoolError("Expected a private single-link regular file")


def _pending_file(fd: int, name: str, data: bytes) -> None:
    # Reserved phase only: a crash during this write can be repaired. A prepared
    # source must never be regenerated because cp_prove may have consumed it.
    raw = os.open(name, _FILE | os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=fd)
    with os.fdopen(raw, "wb") as dest:
        _private_file(raw)
        dest.truncate(0)
        dest.write(data)
        dest.flush()
        os.fsync(raw)
    os.fsync(fd)


def _submission(row: sqlite3.Row) -> Submission:
    return Submission(
        row["job"], row["request"], row["statement"], row["tag"], row["deadline"]
    )


Retirement = Literal["deadline", "handed_off"]


class RetiredSubmission(TimeoutError):
    """Permanent, content-free denial from this job's tombstone."""

    def __init__(self, reason: Retirement) -> None:
        self.reason = reason
        super().__init__("Proof submission is retired")


def _erase_file(directory: int, name: str) -> None:
    """Overwrite private regular files before unlinking. Never follow a link."""
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        os.unlink(name, dir_fd=directory)
    else:
        raw = os.open(name, _FILE | os.O_WRONLY, dir_fd=directory)
        with os.fdopen(raw, "wb", buffering=0) as stream:
            _private_file(raw)
            opened = os.fstat(raw)
            if not os.path.samestat(info, opened):
                raise SpoolError("Proof cleanup entry changed")
            remaining = opened.st_size
            zeros = bytes(min(remaining, 65536))
            while remaining:
                written = stream.write(zeros[:remaining])
                if not written:
                    raise SpoolError("Proof cleanup write failed")
                remaining -= written
            os.fsync(raw)
            if not os.path.samestat(
                opened, os.stat(name, dir_fd=directory, follow_symlinks=False)
            ):
                raise SpoolError("Proof cleanup entry changed")
            os.unlink(name, dir_fd=directory)
    os.fsync(directory)


def _directory(stack: ExitStack, parent: int, name: str) -> int | None:
    try:
        return stack.enter_context(private_directory(name, parent_fd=parent))
    except FileNotFoundError:
        return None


def _lock(fd: int) -> bool:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _clean_spool(state: int, spool: int, request: str) -> bool:
    if not re.fullmatch("[0-9a-f]{64}", request):
        raise SpoolError("Invalid proof cleanup identity")
    _erase_file(state, request + ".pending")
    with ExitStack() as stack:
        # cp_prove holds both locks while live; -clear can hold out independently.
        # First lock the root so a stopped producer cannot start between checking
        # which directories exist and examining this request.
        offline = _lock(spool)
        if offline:
            stack.callback(fcntl.flock, spool, fcntl.LOCK_UN)
        incoming = _directory(stack, spool, "in")
        work = _directory(stack, spool, "work")
        out = _directory(stack, spool, "out")
        if offline and out is not None and not _lock(out):
            return False
        if not offline and (incoming is None or work is None or out is None):
            return False
        name = request + ".req"
        for directory in (incoming, work):
            if directory is not None:
                if not offline and _exists(directory, name):
                    return False
                if offline:
                    _erase_file(directory, name)
        if out is not None:
            for suffix in ("proof", "failed", "tag", "y"):
                _erase_file(out, f"{request}.{suffix}")
            if offline:
                tmp = _directory(stack, out, ".tmp")
                if tmp is not None:
                    staged = _directory(stack, tmp, request)
                    if staged is not None:
                        for part in ("proof", "failed", "y"):
                            _erase_file(staged, part)
                        os.rmdir(request, dir_fd=tmp)
                        os.fsync(tmp)
        return True


class SubmissionStore:
    """Keep one nonce and absolute deadline per private job on a local filesystem."""

    def __init__(
        self,
        state_dir: Path,
        spool_dir: Path,
        *,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        self.state_dir, self.spool_dir = (
            Path(state_dir).absolute(),
            Path(spool_dir).absolute(),
        )
        self._clock = clock_ns
        state_path, spool_path = self.state_dir.resolve(), self.spool_dir.resolve()
        if state_path.is_relative_to(spool_path) or spool_path.is_relative_to(
            state_path
        ):
            raise SpoolError("State and spool require separate private directories")
        with (
            private_directory(self.state_dir, create=True) as state,
            guarded_spool(self.spool_dir) as spool,
        ):
            state_info, spool_info = os.fstat(state), os.fstat(spool)
            if state_info.st_dev != spool_info.st_dev:
                raise SpoolError("State and spool require the same local filesystem")
            self._state_identity = (state_info.st_dev, state_info.st_ino)
            self._spool_identity = (spool_info.st_dev, spool_info.st_ino)
            raw = os.open(
                "submissions.sqlite3",
                _FILE | os.O_RDWR | os.O_CREAT,
                0o600,
                dir_fd=state,
            )
            try:
                _private_file(raw)
                db_info = os.fstat(raw)
                self._db_identity = (db_info.st_dev, db_info.st_ino)
            finally:
                os.close(raw)
            self._db_path = self.state_dir / "submissions.sqlite3"
            with self.transaction() as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS spool_identity (id INTEGER PRIMARY KEY CHECK(id=1), dev TEXT NOT NULL, ino TEXT NOT NULL)"
                )
                identity = tuple(str(i) for i in self._spool_identity)
                db.execute(
                    "INSERT OR IGNORE INTO spool_identity VALUES (1,?,?)", identity
                )
                if (
                    tuple(
                        db.execute(
                            "SELECT dev,ino FROM spool_identity WHERE id=1"
                        ).fetchone()
                    )
                    != identity
                ):
                    raise SpoolError("Spool changed since job reservation")
                db.execute("""CREATE TABLE IF NOT EXISTS jobs (
                    job TEXT PRIMARY KEY, request TEXT UNIQUE NOT NULL, statement BLOB NOT NULL,
                    tag BLOB NOT NULL, deadline INTEGER NOT NULL, nonce BLOB, phase TEXT NOT NULL
                    CHECK(phase IN ('reserved','prepared','sent')))""")
                db.execute("""CREATE TABLE IF NOT EXISTS retired (
                    job TEXT PRIMARY KEY, request TEXT UNIQUE NOT NULL,
                    reason TEXT NOT NULL CHECK(reason IN ('deadline','handed_off')),
                    cleaned INTEGER NOT NULL DEFAULT 0)""")
                db.execute("CREATE INDEX IF NOT EXISTS jobs_deadline ON jobs(deadline)")
                db.execute(
                    "CREATE INDEX IF NOT EXISTS retired_pending ON retired(cleaned) WHERE cleaned=0"
                )
                db.execute(
                    "CREATE TABLE IF NOT EXISTS results (id TEXT PRIMARY KEY, reason TEXT, proof BLOB)"
                )
            os.fsync(state)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Open a serialized transaction on the role-checked private job ledger."""
        with private_directory(self.state_dir) as state:
            info = os.fstat(state)
            if (info.st_dev, info.st_ino) != self._state_identity:
                raise SpoolError("Proof state directory changed")
            raw = os.open("submissions.sqlite3", _FILE | os.O_RDONLY, dir_fd=state)
            try:
                _private_file(raw)
                info = os.fstat(raw)
                if (info.st_dev, info.st_ino) != self._db_identity:
                    raise SpoolError("Proof job database changed")
            finally:
                os.close(raw)
        with closing(sqlite3.connect(self._db_path, isolation_level=None)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA secure_delete=ON")
            db.execute("PRAGMA synchronous=EXTRA")
            db.execute("BEGIN IMMEDIATE")
            yield db

    def _retire(self, db: sqlite3.Connection, job_id: str, reason: Retirement) -> bool:
        row = db.execute("SELECT request FROM jobs WHERE job=?", (job_id,)).fetchone()
        if row is None:
            return False
        db.execute(
            "INSERT INTO retired(job,request,reason) VALUES(?,?,?)",
            (job_id, row[0], reason),
        )
        db.execute("DELETE FROM results WHERE id=?", (row[0],))
        db.execute("DELETE FROM jobs WHERE job=?", (job_id,))
        return True

    def lookup(
        self, db: sqlite3.Connection, job_id: str, *, now_ns: int | None = None
    ) -> Submission | RetiredSubmission:
        """Check retention inside the same transaction used to read a proof."""
        row = db.execute("SELECT * FROM jobs WHERE job=?", (job_id,)).fetchone()
        if row is None:
            retired = db.execute(
                "SELECT reason FROM retired WHERE job=?", (job_id,)
            ).fetchone()
            if retired is None:
                raise KeyError("Unknown proof job")
            return RetiredSubmission(retired[0])
        if self._clock() >= row["deadline"] or (
            now_ns is not None and now_ns >= row["deadline"]
        ):
            self._retire(db, job_id, "deadline")
            return RetiredSubmission("deadline")
        return _submission(row)

    def _clean(self, job_id: str) -> None:
        # The denial is already committed even if filesystem cleanup fails or a
        # native producer is finishing this request. A later sweep retries it.
        with self.transaction() as db:
            row = db.execute(
                "SELECT request FROM retired WHERE job=? AND cleaned=0", (job_id,)
            ).fetchone()
            if row is None:
                return
            with private_directory(self.state_dir) as state, self.spool() as spool:
                info = os.fstat(state)
                if (info.st_dev, info.st_ino) != self._state_identity:
                    raise SpoolError("Proof job directory changed")
                if _clean_spool(state, spool, row[0]):
                    db.execute("UPDATE retired SET cleaned=1 WHERE job=?", (job_id,))

    def handoff(self, job_id: str) -> bool:
        """Immediately retire a job after the auditor durably accepted its result."""
        with self.transaction() as db:
            item = self.lookup(db, job_id)
            changed = isinstance(item, Submission) and self._retire(
                db, job_id, "handed_off"
            )
        self._clean(job_id)
        return changed

    def sweep(self) -> int:
        """Revoke overdue jobs and retry physical cleanup, including after a restart."""
        with self.transaction() as db:
            expired = db.execute(
                "SELECT job FROM jobs WHERE deadline<=?", (self._clock(),)
            ).fetchall()
            for row in expired:
                self._retire(db, row[0], "deadline")
            pending = db.execute("SELECT job FROM retired WHERE cleaned=0").fetchall()
        for row in pending:
            self._clean(row[0])
        return len(expired)

    def pending_cleanup(self) -> int:
        """Private operator count of retired jobs with unfinished disk cleanup."""
        with self.transaction() as db:
            return int(
                db.execute("SELECT count(*) FROM retired WHERE cleaned=0").fetchone()[0]
            )

    @contextmanager
    def spool(self) -> Iterator[int]:
        with guarded_spool(self.spool_dir) as fd:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self._spool_identity:
                raise SpoolError("Proof spool directory changed")
            yield fd

    def _deadline(self, deadline: int) -> None:
        if self._clock() >= deadline:
            raise TimeoutError("Proof job deadline reached")

    def submit(self, job_id: str, statement: bytes, *, deadline_ns: int) -> Submission:
        if (
            not isinstance(job_id, str)
            or not job_id
            or type(deadline_ns) is not int
            or not 0 < deadline_ns < 1 << 63
        ):
            raise ValueError("Invalid durable job identity or deadline")
        prompt, reply = _split(statement)
        with self.spool(), self.transaction() as db:
            previous: Submission | RetiredSubmission | None
            try:
                previous = self.lookup(db, job_id)
            except KeyError:
                previous = None
            if previous is None:
                self._deadline(deadline_ns)
                data = build_spool_request(prompt, reply)
                nonce = data[-32:]
                req = hashlib.sha256(b"p258-spool-req-1" + data).hexdigest()
                tag = hmac.digest(nonce, b"p258-spool-tag-1", "sha256")
                db.execute(
                    "INSERT INTO jobs VALUES (?,?,?,?,?,?,'reserved')",
                    (job_id, req, statement, tag, deadline_ns, nonce),
                )
            elif isinstance(previous, Submission) and (
                previous.statement != statement or previous.deadline_ns != deadline_ns
            ):
                raise ValueError("Durable job already binds different inputs")
        if isinstance(previous, RetiredSubmission):
            raise previous
        return self.resume(job_id)

    def get(self, job_id: str) -> Submission:
        with self.transaction() as db:
            item = self.lookup(db, job_id)
        if isinstance(item, RetiredSubmission):
            raise item
        return item

    def resume(self, job_id: str) -> Submission:
        self.get(job_id)
        with (
            private_directory(self.state_dir) as state,
            guarded_spool(self.spool_dir) as spool,
        ):
            for fd, identity in (
                (state, self._state_identity),
                (spool, self._spool_identity),
            ):
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) != identity:
                    raise SpoolError("Proof job directory changed")
            with private_directory("in", parent_fd=spool, create=True) as incoming:
                with self.transaction() as db:
                    row = db.execute(
                        "SELECT * FROM jobs WHERE job=?", (job_id,)
                    ).fetchone()
                    if row is None:
                        raise TimeoutError("Proof submission is retired")
                    job = _submission(row)
                    self._deadline(job.deadline_ns)
                    if row["phase"] == "sent":
                        return job
                    source = job.request_id + ".pending"
                    if row["phase"] == "reserved":
                        self._deadline(job.deadline_ns)
                        _pending_file(state, source, job.statement + row["nonce"])
                        db.execute(
                            "UPDATE jobs SET phase='prepared' WHERE job=?", (job_id,)
                        )
                # This commit is the fence. If prepared and the source is gone,
                # the atomic rename already happened, even when in/work/out are empty.
                with self.transaction() as db:
                    if not db.execute(
                        "SELECT 1 FROM jobs WHERE job=?", (job_id,)
                    ).fetchone():
                        raise TimeoutError("Proof submission is retired")
                    self._deadline(job.deadline_ns)
                    if _exists(state, source):
                        raw = os.open(source, _FILE | os.O_RDONLY, dir_fd=state)
                        with os.fdopen(raw, "rb") as stream:
                            _private_file(raw)
                            saved = stream.read(_WORDS.size + 33)
                        if (
                            hashlib.sha256(b"p258-spool-req-1" + saved).hexdigest()
                            != job.request_id
                        ):
                            raise SpoolError("Prepared proof request changed")
                        check_spool(spool)
                        self._deadline(job.deadline_ns)
                        _rename_once(source, state, job.request_id + ".req", incoming)
                    os.fsync(incoming)
                    os.fsync(state)
                    db.execute(
                        "UPDATE jobs SET phase='sent',nonce=NULL WHERE job=?", (job_id,)
                    )
                return job
