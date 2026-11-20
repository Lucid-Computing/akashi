"""Restart and concurrency tests for the pinned FlashProve spool handoff."""

import hashlib
import hmac
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from prover import submission
from prover.request import build_statement
from prover.submission import COMMITMENT, SpoolError, SubmissionStore

STATEMENT = build_statement((1, 2), (3, 4))
MARK = f"cp-folder 1\nkind spool\ncommitment {COMMITMENT}\n"
CRASH = """
import os, sys
from pathlib import Path
from unittest.mock import patch
from prover import submission
from prover.request import build_statement
root, deadline, point = sys.argv[1:]
store = submission.SubmissionStore(Path(root)/"state", Path(root)/"spool")
original = getattr(submission, point.split(":")[0])
def interrupt(*args):
    if point.endswith(":before"):
        os._exit(70)
    original(*args)
    os._exit(71)
with patch.object(submission, point.split(":")[0], interrupt):
    store.submit("job", build_statement((1,2),(3,4)), deadline_ns=int(deadline))
"""


class SubmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / "state"
        self.spool = self.root / "spool"
        self.spool.mkdir(mode=0o700)
        (self.spool / "mark.txt").write_text(MARK)
        self.deadline = time.time_ns() + 60_000_000_000
        self.store = SubmissionStore(self.state, self.spool)

    def test_wire_bytes_nonce_identity_and_no_terminal_republication(self) -> None:
        nonce = bytes(range(32))
        with patch("prover.request.os.urandom", return_value=nonce) as entropy:
            job = self.store.submit("first", STATEMENT, deadline_ns=self.deadline)
        entropy.assert_called_once_with(32)
        request = STATEMENT + nonce
        # These domains/bytes come from the independent integrations/spool.py protocol.
        self.assertEqual(
            job.request_id, hashlib.sha256(b"p258-spool-req-1" + request).hexdigest()
        )
        self.assertEqual(job.tag_key, hmac.digest(nonce, b"p258-spool-tag-1", "sha256"))
        self.assertEqual(job.statement, STATEMENT)
        self.assertEqual(job.deadline_ns, self.deadline)
        self.assertNotIn(job.request_id, repr(job))
        queued = self.spool / "in" / (job.request_id + ".req")
        self.assertEqual(queued.read_bytes(), request)
        self.assertEqual(stat.S_IMODE(queued.stat().st_mode), 0o600)
        self.assertEqual(
            stat.S_IMODE((self.state / "submissions.sqlite3").stat().st_mode), 0o600
        )
        queued.unlink()
        with patch(
            "prover.request.os.urandom", side_effect=AssertionError("new nonce")
        ):
            fresh = SubmissionStore(self.state, self.spool)
            self.assertEqual(fresh.get("first"), job)
            self.assertEqual(
                fresh.submit("first", STATEMENT, deadline_ns=self.deadline), job
            )
        self.assertEqual(list(queued.parent.iterdir()), [])
        for statement, deadline in (
            (build_statement((2,), (3,)), self.deadline),
            (STATEMENT, self.deadline + 1),
        ):
            with self.assertRaises(ValueError):
                self.store.submit("first", statement, deadline_ns=deadline)

    def test_process_death_on_either_side_of_prepare_and_publish(self) -> None:
        for point in (
            "_pending_file:before",
            "_pending_file:after",
            "_rename_once:before",
            "_rename_once:after",
        ):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as isolated:
                root = Path(isolated)
                spool = root / "spool"
                spool.mkdir(mode=0o700)
                (spool / "mark.txt").write_text(MARK)
                child = subprocess.run(
                    [sys.executable, "-c", CRASH, str(root), str(self.deadline), point],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
                self.assertEqual(
                    child.returncode,
                    70 if point.endswith("before") else 71,
                    child.stderr,
                )
                reopened = SubmissionStore(root / "state", spool)
                reservation = reopened.get("job")
                queued = spool / "in" / (reservation.request_id + ".req")
                if point == "_rename_once:after":
                    self.assertTrue(queued.is_file())
                    # The actual service may already have moved, answered and cleaned it.
                    queued.unlink()
                else:
                    self.assertFalse(queued.exists())
                self.assertEqual(reopened.resume("job"), reservation)
                self.assertEqual(queued.exists(), point != "_rename_once:after")
                self.assertEqual(list((root / "state").glob("*.pending")), [])

    def test_competing_submitters_publish_once_even_when_input_is_consumed(
        self,
    ) -> None:
        second = SubmissionStore(self.state, self.spool)
        barrier = Barrier(8)
        publications = []
        real = submission._rename_once

        def consume(source: str, source_fd: int, target: str, target_fd: int) -> None:
            real(source, source_fd, target, target_fd)
            publications.append(target)
            os.unlink(target, dir_fd=target_fd)

        def attempt(i: int) -> str:
            barrier.wait(timeout=3)
            return (
                (self.store if i % 2 else second)
                .submit("concurrent", STATEMENT, deadline_ns=self.deadline)
                .request_id
            )

        with (
            patch("prover.submission._rename_once", side_effect=consume),
            ThreadPoolExecutor(max_workers=8) as pool,
        ):
            results = list(pool.map(attempt, range(8)))
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(publications, [results[0] + ".req"])
        another = second.submit("other", STATEMENT, deadline_ns=self.deadline)
        self.assertNotEqual(another.request_id, results[0])

    def test_deadline_and_no_replace_on_recovery(self) -> None:
        with (
            patch("prover.submission._rename_once", side_effect=InterruptedError),
            self.assertRaises(InterruptedError),
        ):
            self.store.submit("delayed", STATEMENT, deadline_ns=self.deadline)
        job = self.store.get("delayed")
        entry = self.spool / "in" / (job.request_id + ".req")
        entry.write_bytes(b"already present")
        with self.assertRaises(SpoolError):
            self.store.resume("delayed")
        self.assertEqual(entry.read_bytes(), b"already present")
        entry.unlink()
        late = SubmissionStore(self.state, self.spool, clock_ns=lambda: self.deadline)
        with self.assertRaises(TimeoutError):
            late.resume("delayed")
        with self.assertRaises(TimeoutError):
            late.submit("new", STATEMENT, deadline_ns=self.deadline)
        with self.assertRaises(KeyError):
            late.get("new")
        self.assertFalse(entry.exists())

    def test_wrong_mark_hold_symlink_and_noncanonical_statement(self) -> None:
        for marker in (MARK.replace(COMMITMENT, "0" * 64), MARK + "extra"):
            (self.spool / "mark.txt").write_text(marker)
            with self.assertRaises(SpoolError):
                self.store.submit("private", STATEMENT, deadline_ns=self.deadline)
        (self.spool / "mark.txt").write_text(MARK)
        (self.spool / "hold").touch()
        with self.assertRaises(SpoolError):
            self.store.submit("private", STATEMENT, deadline_ns=self.deadline)
        (self.spool / "hold").unlink()
        link = self.root / "alias"
        link.symlink_to(self.spool, target_is_directory=True)
        with self.assertRaises((OSError, SpoolError)):
            SubmissionStore(self.root / "other-state", link)
        self.spool.chmod(0o755)
        with self.assertRaises(SpoolError):
            self.store.submit("private", STATEMENT, deadline_ns=self.deadline)
        self.spool.chmod(0o700)
        for malformed in (
            STATEMENT[:-1],
            STATEMENT[:40] + b"\xff" + STATEMENT[41:],
            STATEMENT[:-8] + bytes(8),
        ):
            with self.assertRaises(ValueError):
                self.store.submit("private", malformed, deadline_ns=self.deadline)
        with self.assertRaises(KeyError):
            self.store.get("private")
