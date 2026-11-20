"""Contracts for the optional upstream Lean cross-check over private, already staged files."""

import fcntl
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prover.submission import COMMITMENT
from verifier.lean import LeanConfig, _pinned_source, check_lean


class LeanVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        tree = root / "tree"
        self.work = root / "staged"
        self.work.mkdir()
        (self.work / "commitment.id").write_text(COMMITMENT + "\n")
        self.cache = tree / "lean/.lake"
        self.cache.mkdir(parents=True)
        self.script = tree / "tools/lean-verify/lean_verify.sh"
        self.script.parent.mkdir(parents=True)
        self.bin = root / "bin"
        self.bin.mkdir()
        self.lake = self.bin / "lake"
        self.lake.write_text(
            "#!/bin/sh\necho 'Lake version 5.0.0 (Lean version 4.29.1)'\n"
        )
        self.lake.chmod(0o700)
        self.scratch = root / "private"
        self.scratch.mkdir(mode=0o700)
        self.conf = LeanConfig(tree, self.lake, self.scratch)
        cpu = patch("verifier.lean.check_verifier_cpu")
        cpu.start()
        self.addCleanup(cpu.stop)

    def run_script(self, body: str, *, timeout: float = 5) -> str:
        self.script.write_text("#!/bin/sh\n" + body)
        self.script.chmod(0o700)
        with patch("verifier.lean._pinned_source", return_value=True):
            result = check_lean(self.conf, self.work, timeout_seconds=timeout)
        self.assertEqual(list(self.scratch.iterdir()), [])
        return result

    def test_positional_inputs_and_private_tool_workspace(self) -> None:
        checks = [
            "set -eu",
            '[ "$#" -eq 6 ]',
            '[ "$HOME" = "$TMPDIR" ]',
            '[ -z "${SENTINEL_PRIVATE_ENV:-}" ]',
            'mkdir "$TMPDIR/proof-work"',
            'echo private-tool-artifact > "$TMPDIR/proof-work/private"',
        ]
        for i, name in enumerate(
            ("config", "ivk", "request.bin", "y.bin", "proof.bin", "commitment.id"), 1
        ):
            checks.append(f'[ "${i}" = "{self.work / name}" ]')
        checks += [
            "echo private-diagnostic >&2",
            "echo 'VERDICT: ACCEPT (exact match)'",
        ]
        with patch.dict(os.environ, SENTINEL_PRIVATE_ENV="test-only"):
            self.assertEqual(self.run_script("\n".join(checks)), "verified")

    def test_verdict_requires_unambiguous_complete_stdout_and_matching_exit(
        self,
    ) -> None:
        for program, expected in (
            ("echo 'VERDICT: REJECT'; exit 1", "rejected"),
            ("echo 'VERDICT: REJECT'; exit 0", "unavailable"),
            ("echo 'VERDICT: ACCEPT (exact match)'; exit 1", "unavailable"),
            ("echo 'VERDICT: ACCEPT (under a tolerance policy)'", "unavailable"),
            (
                "echo 'VERDICT: ACCEPT (exact match)' >&2; echo 'NO VERDICT'; exit 2",
                "unavailable",
            ),
            ("echo 'VERDICT: ACCEPT (exact match)'; echo 'NO VERDICT'", "unavailable"),
        ):
            with self.subTest(program=program):
                self.assertEqual(self.run_script(program), expected)

    def test_wrong_source_commitment_cache_ownership_and_timeout(self) -> None:
        self.assertFalse(_pinned_source(self.conf.checkout))
        self.assertEqual(
            check_lean(self.conf, self.work, timeout_seconds=1), "unavailable"
        )
        directory = os.open(self.cache, os.O_RDONLY)
        try:
            fcntl.flock(directory, fcntl.LOCK_EX)
            self.assertEqual(
                self.run_script("echo 'VERDICT: ACCEPT (exact match)'"), "unavailable"
            )
        finally:
            os.close(directory)
        self.assertEqual(self.run_script("exec sleep 10", timeout=0.1), "unavailable")
        self.lake.write_text("#!/bin/sh\necho 'Lake (Lean version 4.29.0)'\n")
        self.assertEqual(
            self.run_script("echo 'VERDICT: ACCEPT (exact match)'"), "unavailable"
        )
        (self.work / "commitment.id").write_text("00" * 32 + "\n")
        self.assertEqual(
            self.run_script("echo 'VERDICT: ACCEPT (exact match)'"), "unavailable"
        )
