"""Synthetic procfs and durable journal coverage for the protected cp_prove process."""

import errno
import json
import os
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from collections.abc import Iterator
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock, patch

from soak import fd_probe, ledger, runner
from soak.ledger import (
    DURATION,
    ROLES,
    Journal,
    NativeProcess,
    measurements,
    role_sample,
)


class ResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.proc = self.base / "proc"
        self.proc.mkdir()
        replace_proc = patch.object(ledger, "PROC", self.proc)
        replace_proc.start()
        self.addCleanup(replace_proc.stop)
        self.native = NativeProcess(123, 111, "0::/job/step1")
        self.process(123, 111, [456], 4)
        self.process(456, 222, [], 2)
        iterdir = Path.iterdir
        self.denied = {self.proc / "123/fd"}

        def directories(path: Path) -> Iterator[Path]:
            if path in self.denied:
                raise PermissionError("synthetic procfs denial")
            return iterdir(path)

        replacement = patch.object(Path, "iterdir", directories)
        replacement.start()
        self.addCleanup(replacement.stop)

    def process(self, pid: int, birth: int, children: list[int], fds: int) -> None:
        root = self.proc / str(pid)
        root.mkdir()
        (root / "fd").mkdir()
        for n in range(fds):
            (root / "fd" / str(n)).touch()
        t = root / "task" / str(pid)
        t.mkdir(parents=True)
        (t / "children").write_text(" ".join(map(str, children)))
        (root / "stat").write_text(
            f"{pid} (cp_prove) " + " ".join(["S"] + ["0"] * 18 + [str(birth)])
        )
        (root / "statm").write_text("20 10 0 0")
        (root / "status").write_text(f"Pid:\t{pid}\nFDSize:\t64\n")
        (root / "cgroup").write_text("0::/job/step1")

    def test_only_authenticated_root_uses_slots_and_children_still_count(self) -> None:
        data = role_sample([123], None, native=self.native)
        self.assertEqual(data[1:], [os.sysconf("SC_PAGE_SIZE") * 20, 2, 0, 64, 1])
        with self.assertRaises(PermissionError):
            role_sample([123], None)
        with self.assertRaisesRegex(ValueError, "single authenticated"):
            role_sample([456], None, native=self.native)
        self.denied.add(self.proc / "456/fd")
        with self.assertRaises(PermissionError):
            role_sample([123], None, native=self.native)
        self.denied.clear()
        self.assertEqual(
            role_sample([123], None, native=self.native)[2:], [6, 0, None, 2]
        )

    def test_missing_stats_identity_and_disappearance_fail(self) -> None:
        prot = self.proc / "123"
        (prot / "task/123/children").write_text("")
        self.assertEqual(
            role_sample([123], None, native=self.native)[2:], [None, 0, 64, 0]
        )
        for field in (
            "",
            "FDSize: -1",
            "FDSize: no",
            "FDSize: 0",
            "FDSize: 64\nFDSize: 32",
            "FDSize: 64 32",
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "FDSize"),
            ):
                (prot / "status").write_text(field)
                role_sample([123], None, native=self.native)
        (prot / "status").unlink()
        with self.assertRaises(FileNotFoundError):
            role_sample([123], None, native=self.native)
        (prot / "cgroup").write_text("0::/wrong")
        with self.assertRaisesRegex(ValueError, "changed"):
            role_sample([123], None, native=self.native)
        (prot / "cgroup").write_text(self.native.cgroup)
        (prot / "stat").write_text(
            "123 (reused) " + " ".join(["S"] + ["0"] * 18 + ["999"])
        )
        with self.assertRaisesRegex(ValueError, "changed"):
            role_sample([123], None, native=self.native)
        (prot / "stat").unlink()
        with self.assertRaises(FileNotFoundError):
            role_sample([123], None, native=self.native)

    def test_calibration_requires_counts_including_zero_and_rejects_constant_capacity(
        self,
    ) -> None:
        for counts, expected in (
            ([3, 4, 3, 0], True),
            ([64], False),
            ([3, 3], False),
            ([3, 4, 4], False),
            ([3, 4, 3, 64], False),
        ):
            directory = Mock(spec=Path)
            directory.stat.side_effect = [Mock(st_size=count) for count in counts]
            with self.subTest(counts=counts), patch.object(os, "close") as closer:
                self.assertEqual(fd_probe.probe(directory), expected)
                self.assertEqual(closer.call_count, 3 if len(counts) == 4 else 0)
        with (
            patch("sys.platform", "linux"),
            patch.object(
                subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], fd_probe.UNSUPPORTED),
            ) as run,
        ):
            self.assertFalse(ledger.aggregate_fd_counts(5))
            self.assertTrue(run.call_args.kwargs["close_fds"])
            self.assertEqual(run.call_args.kwargs["timeout"], 5)
            run.return_value = subprocess.CompletedProcess([], 1)
            with self.assertRaisesRegex(ledger.ObservationFailure, "collector"):
                ledger.aggregate_fd_counts(5)

    def test_exact_kernel_count_includes_nondumpable_root_and_descendant(self) -> None:
        self.denied.add(self.proc / "456/fd")
        original = Path.stat

        def count(path: Path) -> os.stat_result:
            info = original(path)
            if path in self.denied:
                fields = list(info)
                fields[6] = 5 if path == self.proc / "123/fd" else 0
                return os.stat_result(fields)
            return info

        with patch.object(Path, "stat", count):
            self.assertEqual(
                role_sample([123], None, native=self.native, aggregate_fds=True)[2:],
                [5, 0, None, 2],
            )
            with self.assertRaises(PermissionError):
                role_sample([123], None, native=self.native)
        with (
            patch.object(
                Path, "stat", side_effect=PermissionError(errno.EACCES, "private path")
            ),
            self.assertRaises(PermissionError),
        ):
            role_sample([123], None, native=self.native, aggregate_fds=True)

    def test_only_gone_tasks_and_optional_children_can_disappear(self) -> None:
        proc = self.proc / "123"
        read = Path.read_text
        vanished = proc / "task/789"
        for error in (ProcessLookupError, FileNotFoundError):
            vanished.mkdir()

            def retreat(path: Path, error: type[OSError] = error) -> str:
                if path == vanished / "children":
                    vanished.rmdir()
                    raise error()
                if path == self.proc / "456/statm":
                    (self.proc / "456").rename(self.proc / "departed")
                    raise error()
                return read(path)

            with self.subTest(error=error), patch.object(Path, "read_text", retreat):
                self.assertEqual(
                    role_sample([123], None, native=self.native)[2:], [None, 0, 64, 0]
                )
            (self.proc / "departed").rename(self.proc / "456")

            def present(path: Path, error: type[OSError] = error) -> str:
                if (
                    path == self.proc / "456/statm"
                    or path == proc / "task/123/children"
                ):
                    raise error()
                return read(path)

            with patch.object(Path, "read_text", present), self.assertRaises(error):
                role_sample([123], None, native=self.native)
            with self.assertRaises(FileNotFoundError):
                role_sample([999], None)

    def test_background_failure_surfaces_bounded_role_class_errno(self) -> None:
        for pid in (201, 202, 203):
            self.process(pid, pid, [], 2)
        roles = {"engine": [201], "prover": [123], "gateway": [202], "auditor": [203]}
        gpus = {"engine": "GPU-engine", "prover": "GPU-prover"}
        journal = Journal(self.base / "failure.db")
        self.denied.add(self.proc / "203/fd")
        reject = PermissionError(errno.EACCES, "sensitive-path-and-filename")
        with patch.object(subprocess, "check_output", return_value="5"):

            def observe() -> None:
                journal.observe(roles, gpus, native=self.native)

            errors: list[ledger.ObservationFailure] = []
            runner._observe_periodically(threading.Event(), 0, observe, errors)
            with self.assertRaisesRegex(
                ledger.ObservationFailure, "role=auditor, class=PermissionError"
            ):
                runner._observation_health(errors)
        for exc, message in (
            (reject, "class=PermissionError, errno=EACCES"),
            (IndexError("private"), "class=IndexError"),
            (SystemExit("private"), "class=Exception"),
            (subprocess.CalledProcessError(3, ["private"]), "class=CalledProcessError"),
        ):
            errors = []
            runner._observe_periodically(
                threading.Event(), 0, Mock(side_effect=exc), errors
            )
            with self.assertRaisesRegex(ledger.ObservationFailure, message) as caught:
                runner._observation_health(errors)
            self.assertNotIn("private", str(caught.exception))
        with closing(sqlite3.connect(journal.path)) as db:
            self.assertEqual(
                db.execute("select count(*) from observations").fetchone(), (0,)
            )

    def test_live_journal_refuses_basis_change_before_another_sample_commits(
        self,
    ) -> None:
        for pid in (201, 202, 203):
            self.process(pid, pid, [], 2)
        roles = {"engine": [201], "prover": [123], "gateway": [202], "auditor": [203]}
        gpus = {"engine": "GPU-engine", "prover": "GPU-prover"}
        journal = Journal(self.base / "live.db")
        with patch("soak.ledger.subprocess.check_output", return_value="5"):
            journal.observe(roles, gpus, native=self.native)
            self.denied.clear()
            with self.assertRaisesRegex(ValueError, "basis changed"):
                journal.observe(roles, gpus, native=self.native)
        with closing(sqlite3.connect(journal.path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM observations").fetchone(), (1,)
            )

    def test_measurements_disclose_coverage_and_reject_changed_basis_or_growth(
        self,
    ) -> None:
        values = {r: [i + 1, 128, 8, 64, None, 1] for i, r in enumerate(ROLES)}
        (self.proc / "123/task/123/children").write_text("")
        values["prover"] = role_sample([123], None, native=self.native)
        start = time.time() - DURATION - 1
        journal = Journal(self.base / "journal.db")
        binding = {"native_prover": asdict(self.native), "processes": {"prover": [123]}}
        with closing(sqlite3.connect(journal.path)) as db, db:
            db.execute(
                "INSERT INTO run VALUES(1,?,'boot',0,?,?,?)",
                (json.dumps(binding), start, DURATION * 10**9, start + DURATION),
            )
            db.executemany(
                "INSERT INTO observations VALUES(?,?,?)",
                [
                    (i * 10**9, start + i, json.dumps(values))
                    for i in range(0, DURATION + 1, 300)
                ],
            )

            def checked() -> dict[str, Any]:
                return cast(
                    dict[str, Any],
                    measurements(db, gap_seconds=300, warmup_end_ns=600 * 10**9)[
                        "resources"
                    ],
                )

            result = checked()
            self.assertEqual(result["prover"]["protected_fd_processes"], 1)
            self.assertEqual(result["prover"]["final_protected_fd_slots"], 64)
            self.assertIsNone(result["prover"]["final_exact_fds_visible"])
            self.assertNotIn("final_fds", result["prover"])
            self.assertEqual(result["gateway"]["final_fds"], 8)
            # Old exact/partial reports remain readable. A new calibrated run binds
            # its exact measurement source and the native birth even without FDSize.
            db.execute(
                "UPDATE run SET config=?",
                (json.dumps(dict(binding, fd_measurement="procfs_fd_count")),),
            )
            with self.assertRaisesRegex(ValueError, "differs from calibration"):
                checked()
            exact_values = dict(values, prover=[*values["prover"][:2], 5, 64, None, 1])
            db.execute("UPDATE observations SET roles=?", (json.dumps(exact_values),))
            self.assertEqual(checked()["prover"]["final_fds"], 5)
            exact_values["prover"][0] = 999
            db.execute("UPDATE observations SET roles=?", (json.dumps(exact_values),))
            with self.assertRaisesRegex(ValueError, "Unbound native"):
                checked()
            db.execute("UPDATE run SET config=?", (json.dumps(binding),))
            db.execute("UPDATE observations SET roles=?", (json.dumps(values),))
            initial = values["prover"]
            for end, message in (
                ([*initial[:4], 128, 0], "growth"),
                ([initial[0], initial[1], 7, 0, None, 1], "basis changed"),
                ([999, initial[1], None, 0, 64, 0], "Unbound"),
                ([*initial[:4], None, 0], "No process"),
                ([*initial[:3], 0, 16, None], "Missing exact"),
            ):
                values["prover"] = end
                db.execute(
                    "UPDATE observations SET roles=? WHERE ns=?",
                    (json.dumps(values), DURATION * 10**9),
                )
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex(ValueError, message),
                ):
                    checked()
