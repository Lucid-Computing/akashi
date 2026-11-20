import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from engine import verify_commitment as gate


class CommitmentTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.source = root / "upstream"
        self.weights = root / "weights"
        self.work = root / "private-work"
        example = self.source / gate.EXAMPLE
        example.mkdir(parents=True)
        self.weights.mkdir()
        self.shard = self.weights / "shard.gguf"
        self.shard.write_bytes(b"weights")
        (self.weights / "shard.gguf.weights-are-public").touch()
        calibration = bytes(131200)
        (self.weights / "calibration_set.npy").write_bytes(calibration)
        (example / "public-seed.bin").write_bytes(bytes(32))
        self.digest = hashlib.sha256(b"weights").hexdigest()
        (example / "weights.sha256").write_text(f"{self.digest}  shard.gguf\n")
        (example / "expected.txt").write_text(
            f"{self.digest}  ivk/key.bin\n{gate.COMMITMENT}  commitment-id\n"
        )
        (self.source / ".gitignore").write_text("ignored-build-output\n")
        script = example / "run.sh"
        script.write_text(
            "#!/bin/sh\nset -eu\n"
            'mkdir -p "$2/logs"\nprintf "%s\\n" "$1" >> "$2/stages"\n'
            'if [ "$1" = compare ]; then\n'
            '    cp examples/maverick/expected.txt "$2/logs/made.1.log"\n'
            '    if [ -f "$4/mismatch" ]; then\n'
            '        sed "s/^./0/" examples/maverick/expected.txt > "$2/logs/made.1.log"\n'
            '        echo "PRIVATE LOG MESSAGE" >&2\n'
            "        exit 1\n"
            "    fi\n"
            "fi\n"
        )
        script.chmod(0o755)
        for args in (
            ["init", "-q"],
            ["add", "."],
            [
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "fixture",
            ],
        ):
            gate.git(self.source, *args)
        revision = gate.git(self.source, "rev-parse", "HEAD").decode().strip()
        for key, value in (
            ("REVISION", revision),
            ("CALIBRATION", hashlib.sha256(calibration).hexdigest()),
        ):
            patcher = patch.object(gate, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_stage_order_and_observations(self) -> None:
        observed: dict[str, str] = {}
        gate.rebuild(self.source, self.weights, self.work, observed)
        self.assertEqual(
            (self.work / "run/stages").read_text().splitlines(),
            ["needs", "build", "checksums", "fit", "commit", "compare"],
        )
        self.assertEqual(observed["commitment-id"], gate.COMMITMENT)
        self.assertEqual(observed["shard.gguf"], self.digest)

    def test_failing_comparison_reports_only_public_input(self) -> None:
        (self.weights / "mismatch").touch()
        argv = [
            "verify_commitment",
            "--flashprove",
            str(self.source),
            "--weights",
            str(self.weights),
            "--work",
            str(self.work),
        ]
        buffer = StringIO()
        with patch.object(sys, "argv", argv), redirect_stdout(buffer):
            self.assertEqual(gate.main(), 1)
        evidence = json.loads(buffer.getvalue())
        self.assertFalse(evidence["passed"])
        self.assertEqual(evidence["published_commitment"], gate.COMMITMENT)
        self.assertEqual(evidence["failing_input"], "ivk/key.bin")
        self.assertNotIn("PRIVATE", buffer.getvalue())
        self.assertNotIn(str(self.work), buffer.getvalue())

    def test_rejects_ignored_file_dirty_source_and_wrong_revision(self) -> None:
        for name in ("ignored-build-output", "untracked", ".gitignore"):
            with self.subTest(name=name):
                path = self.source / name
                path.write_text("shadow\n")
                with self.assertRaisesRegex(gate.RebuildFailure, "clean"):
                    gate.rebuild(self.source, self.weights, self.work, {})
                if name != ".gitignore":
                    path.unlink()
        with (
            patch.object(gate, "REVISION", "a" * 40),
            self.assertRaisesRegex(gate.RebuildFailure, "revision"),
        ):
            gate.rebuild(self.source, self.weights, self.work, {})
        self.assertFalse(self.work.exists())

    def test_missing_shard_names_the_failing_input(self) -> None:
        self.shard.unlink()
        with self.assertRaisesRegex(gate.RebuildFailure, "shard.gguf"):
            gate.rebuild(self.source, self.weights, self.work, {})

    def test_cli_requires_inputs_and_prints_published_id(self) -> None:
        result = subprocess.run(
            [sys.executable, gate.__file__], env={}, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            json.loads(result.stdout)["published_commitment"], gate.COMMITMENT
        )
        self.assertEqual(json.loads(result.stdout)["failing_input"], "--flashprove")
