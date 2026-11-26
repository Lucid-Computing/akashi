"""Exercise candidate archive checksums and an unsuccessful ordinary invocation."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from release.check import write_archive


class ReleaseArchiveTests(unittest.TestCase):
    def test_archive_lists_every_member_by_digest_and_is_repeatable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "candidate.zip"
            files = {
                "requirements.txt": b"locked fixture\n",
                "provenance.json": b"{}\n",
            }
            original = write_archive(target, files)
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), original)
            with zipfile.ZipFile(target) as z:
                sums = z.read("SHA256SUMS").decode("ascii").splitlines()
                self.assertEqual(set(z.namelist()), {*files, "SHA256SUMS"})
                self.assertEqual(
                    sums,
                    [
                        f"{hashlib.sha256(payload).hexdigest()}  {name}"
                        for name, payload in sorted(files.items())
                    ],
                )
            self.assertEqual(
                write_archive(target, dict(reversed(list(files.items())))), original
            )
            with self.assertRaises(ValueError):
                write_archive(target, {"../unexpected": b"test"})

    def test_unconfigured_cli_removes_stale_candidate_and_lists_missing_gates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "candidate.zip").write_bytes(b"old")
            (folder / "status.json").write_text('{"status":"passed"}')
            env = {
                k: v for k, v in os.environ.items() if not k.startswith("AKASHI_RELEASE_")
            }
            result = subprocess.run(
                [sys.executable, "-m", "release.check", "--output", str(folder)],
                check=False,
                capture_output=True,
                env=env,
            )
            self.assertEqual(result.returncode, 1)
            report = json.loads((folder / "status.json").read_bytes())
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(
                report["missing_milestones"], ["M0", "M1", "M2", "M3", "M4"]
            )
            self.assertFalse((folder / "candidate.zip").exists())
