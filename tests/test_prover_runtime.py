"""Pinned process supervision tested with a local subprocess that never builds a proof."""

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from prover.runtime import (
    REVISION,
    SERVING_SETTING,
    ProverProcess,
    RuntimeConfig,
    RuntimeUnavailable,
)
from prover.submission import COMMITMENT

# Reproduce cp_prove's documented behavior of consuming a stale stop marker at startup,
# finishing the current batch, and observing stop again on its next iteration.
CHILD = """
import json, os, signal, sys, time
from pathlib import Path
home = Path(os.environ['HOME'])
if sys.argv[1:] == ['--setting']:
    print((home/'setting').read_text(), end='')
    sys.exit(0)
args = sys.argv[1:]
spool = Path(args[args.index('-spool')+1])
stop = spool/'stop'
(home/'started').write_text(json.dumps({'args': args, 'gpu': os.environ.get('CUDA_VISIBLE_DEVICES'),
    'leak': os.environ.get('VIG_FIXTURE_PRIVATE'), 'loader': os.environ.get('LD_PRELOAD')}))
if (home/'exit').exists(): sys.exit(7)
while not (home/'finish-startup').exists(): time.sleep(0.003)
if stop.exists():
    stop.unlink()
    (home/'consumed-old-stop').touch()
while not (home/'finish-batch').exists(): time.sleep(0.003)
while not stop.exists(): time.sleep(0.003)
if stop.is_symlink() or stop.read_bytes(): sys.exit(8)
stop.unlink()
(home/'finished').touch()
"""


class ProverRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for name in ("isk", "spool", "home", "tmp"):
            (root / name).mkdir(mode=0o700)
        self.cfg = RuntimeConfig(
            root / "cp_prove",
            root / "build.json",
            root / "isk",
            root / "public-seed.bin",
            root / "spool",
            root / "home",
            root / "tmp",
            1,
        )
        # Real ISK names are forbidden as spool/state directories, but required
        # in the original, separately owned prover key folder.
        (self.cfg.secret_key / "seed.bin").write_bytes(b"synthetic test seed")
        (self.cfg.secret_key / "isk.txt").write_text("synthetic test key metadata")
        self.cfg.binary.write_text("#!" + sys.executable + "\n" + CHILD)
        self.cfg.binary.chmod(0o700)
        self.cfg.public_seed.write_bytes(bytes(range(32)))
        (self.cfg.spool / "mark.txt").write_text(
            f"cp-folder 1\nkind spool\ncommitment {COMMITMENT}\n"
        )
        self.manifest = {
            "schema_version": 1,
            "flashprove_revision": REVISION,
            "commitment_id": COMMITMENT,
            "cp_prove_sha256": hashlib.sha256(self.cfg.binary.read_bytes()).hexdigest(),
        }
        self.cfg.build_manifest.write_text(json.dumps(self.manifest))
        (self.cfg.home / "setting").write_bytes(SERVING_SETTING)
        # A Darwin host cannot execute the Linux /proc fd route. Run the same
        # checked fixture from its private pathname for lifecycle assertions here.
        if not Path("/proc/self/fd").is_dir():
            portable = patch(
                "prover.runtime._executable", return_value=str(self.cfg.binary)
            )
            portable.start()
            self.addCleanup(portable.stop)
        host = patch("prover.runtime._host")
        self.checked_host = host.start()
        self.addCleanup(host.stop)

    def wait_for(self, path: Path) -> None:
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if path.exists():
                return
            time.sleep(0.005)
        self.fail("fixture marker was not written: " + path.name)

    def start_fixture(self) -> ProverProcess:
        result = ProverProcess.start(self.cfg)

        def drain() -> None:
            for marker in ("finish-startup", "finish-batch"):
                (self.cfg.home / marker).touch()
            result.stop(timeout=5, poll_seconds=0.01)

        self.addCleanup(drain)
        self.wait_for(self.cfg.home / "started")
        return result

    def test_pinned_command_clean_environment_and_stop_during_startup(self) -> None:
        with patch.dict(
            os.environ, {"VIG_FIXTURE_PRIVATE": "private", "LD_PRELOAD": "private"}
        ):
            process = self.start_fixture()
        self.checked_host.assert_called_once_with(1)
        seen = json.loads((self.cfg.home / "started").read_bytes())
        self.assertEqual(
            seen["args"],
            [
                "-isk",
                str(self.cfg.secret_key),
                "-public-weights",
                str(self.cfg.public_seed),
                "-spool",
                str(self.cfg.spool),
                "-batch",
                "1",
                "-in-step",
                "1",
                "-memory",
                "lean,tensor-rooms=8",
            ],
        )
        self.assertEqual(seen["gpu"], "1")
        self.assertIsNone(seen["leak"])
        self.assertIsNone(seen["loader"])
        self.assertIsNone(process.poll())
        with self.assertRaises(TimeoutError):
            process.stop(timeout=0.04, poll_seconds=0.005)
        stop = self.cfg.spool / "stop"
        self.assertEqual(stop.read_bytes(), b"")
        self.assertEqual(stop.stat().st_mode & 0o777, 0o600)
        self.assertIsNone(process.poll())
        (self.cfg.home / "finish-startup").touch()
        self.wait_for(self.cfg.home / "consumed-old-stop")
        (self.cfg.home / "finish-batch").touch()
        self.assertEqual(process.stop(timeout=5, poll_seconds=0.01), 0)
        self.assertEqual(process.stop(timeout=1, poll_seconds=0.01), 0)
        self.assertTrue((self.cfg.home / "finished").is_file())
        self.assertFalse((self.cfg.spool / "hold").exists())

    def test_unexpected_exit_sets_durable_hold_without_client_polling(self) -> None:
        (self.cfg.home / "exit").touch()
        process = ProverProcess.start(self.cfg)
        self.wait_for(self.cfg.spool / "hold")
        self.assertEqual(process.stop(timeout=5, poll_seconds=0.01), 7)
        self.assertEqual(process.poll(), 7)
        self.assertEqual((self.cfg.spool / "hold").read_bytes(), b"")
        with self.assertRaises(RuntimeUnavailable):
            ProverProcess.start(self.cfg)

    def test_missing_or_mismatched_attestation_and_nonproduction_setting(self) -> None:
        for field, bad in (
            ("flashprove_revision", "0" * 40),
            ("commitment_id", "0" * 64),
            ("cp_prove_sha256", "0" * 64),
            ("schema_version", True),
        ):
            self.cfg.build_manifest.write_text(json.dumps(self.manifest | {field: bad}))
            with self.subTest(field=field), self.assertRaises(RuntimeUnavailable):
                ProverProcess.start(self.cfg)
        self.cfg.build_manifest.unlink()
        with self.assertRaises(RuntimeUnavailable):
            ProverProcess.start(self.cfg)
        self.cfg.build_manifest.write_text(json.dumps(self.manifest))
        (self.cfg.home / "setting").write_bytes(
            SERVING_SETTING.replace(b"a serving build", b"built for tests alone")
        )
        with self.assertRaises(RuntimeUnavailable):
            ProverProcess.start(self.cfg)
        self.assertFalse((self.cfg.home / "started").exists())

    def test_modified_binary_seed_or_spool_marker_cannot_launch(self) -> None:
        for name, p in (
            ("binary", self.cfg.binary),
            ("seed", self.cfg.public_seed),
            ("mark", self.cfg.spool / "mark.txt"),
        ):
            original = p.read_bytes()
            try:
                p.write_bytes(original + b"!")
                with self.subTest(name=name), self.assertRaises(RuntimeUnavailable):
                    ProverProcess.start(self.cfg)
            finally:
                p.write_bytes(original)
        self.assertFalse((self.cfg.home / "started").exists())

    def test_key_directory_requires_private_mode(self) -> None:
        self.cfg.secret_key.chmod(0o750)
        with self.assertRaises(RuntimeUnavailable):
            ProverProcess.start(self.cfg)
        self.assertFalse((self.cfg.home / "started").exists())

    def test_nonempty_user_stop_is_never_truncated_or_replaced(self) -> None:
        process = self.start_fixture()
        marker = self.cfg.spool / "stop"
        marker.write_bytes(b"administrative hold")
        with self.assertRaises(RuntimeUnavailable):
            process.stop(timeout=1, poll_seconds=0.01)
        self.assertEqual(marker.read_bytes(), b"administrative hold")
        marker.unlink()
