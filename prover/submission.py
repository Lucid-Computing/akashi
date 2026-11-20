"""Durable one-request submissions to the pinned FlashProve spool (RFC-0006)."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import os
import sqlite3
import stat
import struct
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

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
            db.execute("PRAGMA secure_delete=ON")
            db.execute("PRAGMA synchronous=EXTRA")
            db.execute("BEGIN IMMEDIATE")
            yield db

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
        with guarded_spool(self.spool_dir), self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE job=?", (job_id,)).fetchone()
            if row is None:
                self._deadline(deadline_ns)
                data = build_spool_request(prompt, reply)
                nonce = data[-32:]
                req = hashlib.sha256(b"p258-spool-req-1" + data).hexdigest()
                tag = hmac.digest(nonce, b"p258-spool-tag-1", "sha256")
                db.execute(
                    "INSERT INTO jobs VALUES (?,?,?,?,?,?,'reserved')",
                    (job_id, req, statement, tag, deadline_ns, nonce),
                )
            elif row["statement"] != statement or row["deadline"] != deadline_ns:
                raise ValueError("Durable job already binds different inputs")
        return self.resume(job_id)

    def get(self, job_id: str) -> Submission:
        with self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE job=?", (job_id,)).fetchone()
            if row is None:
                raise KeyError("Unknown proof job")
            return _submission(row)

    def resume(self, job_id: str) -> Submission:
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
                        raise KeyError("Unknown proof job")
                    job = _submission(row)
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
