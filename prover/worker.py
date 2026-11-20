"""Collect private, authenticated FlashProve spool output for independent verification."""

import hashlib
import hmac
import math
import os
import stat
import struct
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Literal

from prover.submission import (
    RetiredSubmission,
    Submission,
    SubmissionStore,
    check_spool,
)


@dataclass(frozen=True)
class CandidateProof:
    """Only the verifier can turn these private bytes into evidence of conformance."""

    statement: bytes = field(repr=False)
    y: bytes = field(repr=False)
    proof: bytes = field(repr=False)


@dataclass(frozen=True)
class Unavailable:
    reason: Literal["spool_failure", "invalid_response", "deadline", "handed_off"]


def _read_response(
    root: int, item: Submission, limit: int
) -> CandidateProof | Unavailable | None:
    # FlashProve publishes y, tag, then proof (or tag, then failed). Open in reverse order.
    with ExitStack() as stack:
        try:
            out = os.open(
                "out", os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY, dir_fd=root
            )
        except FileNotFoundError:
            return None
        stack.callback(os.close, out)
        info = os.fstat(out)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError("Private proof output directory required")
        parts: dict[str, bytes] = {}
        times: set[int] = set()
        for suffix, size in (("failed", 0), ("proof", limit), ("tag", 32), ("y", 4)):
            if suffix == "tag" and not parts:
                return None
            try:
                fd = os.open(
                    f"{item.request_id}.{suffix}",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=out,
                )
            except FileNotFoundError:
                continue
            except OSError:
                return Unavailable("invalid_response")
            stream = stack.enter_context(os.fdopen(fd, "rb"))
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_size > size
            ):
                return Unavailable("invalid_response")
            data = stream.read(info.st_size + 1)
            if len(data) != info.st_size:
                return Unavailable("invalid_response")
            parts[suffix] = data
            times.add(info.st_mtime_ns)
        if len(times) != 1:
            return Unavailable("invalid_response")
        head = bytes.fromhex(item.request_id)
        if parts.keys() == {"failed", "tag"} and not parts["failed"]:
            mac = hmac.digest(item.tag_key, head + bytes(16) + b"failed", "sha256")
            if hmac.compare_digest(mac, parts["tag"]):
                return Unavailable("spool_failure")
        if (
            parts.keys() == {"proof", "tag", "y"}
            and parts["y"] == bytes(4)
            and parts["proof"]
        ):
            proof = parts["proof"]
            digest = hmac.new(
                item.tag_key,
                head + struct.pack("<QQ", 4, len(proof)) + parts["y"],
                hashlib.sha256,
            )
            digest.update(proof)
            if hmac.compare_digest(digest.digest(), parts["tag"]):
                return CandidateProof(item.statement, parts["y"], proof)
        return Unavailable("invalid_response")


class ProofWorker:
    def __init__(
        self,
        store: SubmissionStore,
        *,
        max_proof_bytes: int,
        now_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if type(max_proof_bytes) is not int or max_proof_bytes <= 0:
            raise ValueError("positive operator proof size limit required")
        self.store = store
        self._limit, self._now = max_proof_bytes, now_ns

    def poll(self, job_id: str) -> CandidateProof | Unavailable | None:
        """Snapshot the first terminal result. A missing final marker remains pending."""
        with (
            self.store.spool() as root,
            self.store.transaction() as db,
        ):
            item = self.store.lookup(db, job_id, now_ns=self._now())
            if isinstance(item, RetiredSubmission):
                return Unavailable(item.reason)
            row = db.execute(
                "SELECT reason,proof FROM results WHERE id=?", (item.request_id,)
            ).fetchone()
            result: CandidateProof | Unavailable | None
            if row is not None:
                if row[0] is None:
                    result = CandidateProof(item.statement, bytes(4), row[1])
                else:
                    result = Unavailable(row[0])
            else:
                result = None
                if self._now() < item.deadline_ns:
                    result = _read_response(root, item, self._limit)
                if result is not None:
                    db.execute(
                        "INSERT INTO results VALUES (?,?,?)",
                        (
                            item.request_id,
                            result.reason if isinstance(result, Unavailable) else None,
                            result.proof
                            if isinstance(result, CandidateProof)
                            else None,
                        ),
                    )
            check_spool(root)
            # The result read/authentication may itself have crossed the boundary.
            still_live = self.store.lookup(db, job_id, now_ns=self._now())
            return (
                Unavailable(still_live.reason)
                if isinstance(still_live, RetiredSubmission)
                else result
            )

    def wait(self, job_id: str, *, poll_seconds: float) -> CandidateProof | Unavailable:
        """Resume a previously submitted durable job, using its original absolute deadline."""
        if not math.isfinite(poll_seconds) or poll_seconds <= 0:
            raise ValueError("positive finite proof polling interval required")
        try:
            deadline = self.store.get(job_id).deadline_ns
        except RetiredSubmission as exc:
            return Unavailable(exc.reason)
        while (result := self.poll(job_id)) is None:
            time.sleep(min(poll_seconds, max(0, (deadline - self._now()) / 1e9)))
        return result
