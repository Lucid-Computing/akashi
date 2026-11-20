"""Offline launch contract. All test artifacts, measurements and processes are synthetic."""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from engine import launch
from engine.launch import COMMITMENT, FILE_LINE, TENSOR_LINE, LaunchConfig, LaunchError


def write(path: Path, obj: object) -> None:
    path.write_text(json.dumps(obj))


class EngineLaunchTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        top = Path(temp.name)
        for name in ("model", "refs", "work", "source", "venv/bin", "home", "tmp"):
            (top / name).mkdir(mode=0o700, parents=True)
        self.cfg = LaunchConfig(
            top / "model",
            top / "refs",
            top / "report.json",
            top / "work",
            top / "source",
            top / "venv",
            top / "home",
            top / "tmp",
            top / "goldens.json",
            "float32",
            0.2,
        )
        c = self.cfg
        self.rows = [
            {"prompt": [200000, i], "max_tokens": 2, "expected": [i, 200001]}
            for i in range(3)
        ]
        write(
            c.canary_file,
            {"commitment_id": COMMITMENT, "dtype": c.dtype, "canaries": self.rows},
        )
        shards = []
        for i in range(1, 6):
            shard = (
                c.model
                / f"Llama-4-Maverick-17B-128E-Instruct-UD-Q4_K_XL-{i:05d}-of-00005.gguf"
            )
            shard.write_bytes(b"only a stand-in")
            shards.append(str(shard))
        desc = {
            "weights": "blocks",
            "weight_settings": {
                "blocks": "gguf",
                "verify_sums": True,
                "setup_folder": str(c.model),
                "shards": shards,
            },
        }
        write(c.model / "integer_model.json", desc)
        write(
            c.model / "config.json",
            {
                "architectures": ["IntegerModelForCausalLM"],
                "eos_token_id": [200001, 200007, 200008],
                "max_position_embeddings": 1024,
                "vocab_size": 202048,
            },
        )
        fit = c.rebuild_work / "run/fit.1"
        (fit / "model").mkdir(parents=True)
        (fit / "config").mkdir()
        for name in launch.FILES:
            path = c.model / name
            if name != "integer_model.json":
                path.write_bytes(name.encode())
                shutil.copyfile(
                    path,
                    fit
                    / ("config" if name in ("KL.bin", "policy.txt") else "model")
                    / name,
                )
            shutil.copyfile(path, c.references / name)
        ivk = c.rebuild_work / "run/commitment.1/ivk"
        (ivk / "leaf").mkdir(parents=True)
        (ivk / "key.bin").write_bytes(b"test public key")
        (ivk / "leaf/0.bin").write_bytes(b"first public leaf")
        # The tests patch only the large-artifact known-answer values; full comparison stays live.
        expected = {
            name: launch._digest(
                (fit if name.startswith(("model/", "config/")) else ivk.parent) / name
            )
            for name in launch.F4
            if name != "commitment-id"
        }
        expected["commitment-id"] = COMMITMENT
        pins = patch.dict(launch.F4, expected)
        pins.start()
        self.addCleanup(pins.stop)
        write(
            c.rebuild_report,
            {
                "schema_version": 1,
                "passed": True,
                "published_commitment": COMMITMENT,
                "observed": expected,
            },
        )
        (c.venv / "bin/python").symlink_to(sys.executable)
        (c.venv / "bin/vllm").write_text(
            "import sys\nprint(" + repr(FILE_LINE.decode()) + ", flush=True)\n"
            "print(" + repr(TENSOR_LINE.decode()) + ", file=sys.stderr, flush=True)\n"
            "import time\ntime.sleep(60)\n"
        )

    def test_exact_references_and_rebuild_contract(self) -> None:
        c = self.cfg
        launch.verify_artifacts(c)
        self.assertEqual(len(launch.load_canaries(c)), 3)
        for filename in launch.FILES:
            path = c.references / filename
            original = path.read_bytes()
            with self.subTest(name=filename):
                try:
                    path.write_bytes(original + b" ")
                    with self.assertRaises(LaunchError):
                        launch.verify_artifacts(c)
                finally:
                    path.write_bytes(original)
        path = c.references / "policy.txt"
        path.unlink()
        os.link(c.model / "policy.txt", path)
        with self.assertRaises(LaunchError):
            launch.verify_artifacts(c)

    def test_matching_reference_is_insufficient_without_fitted_policy_and_f4(
        self,
    ) -> None:
        c = self.cfg
        for name in ("policy.txt", "fold.txt", "KL.bin", "wsums.txt"):
            with self.subTest(name=name):
                p = c.model / name
                saved = p.read_bytes()
                try:
                    for base in (c.model, c.references):
                        (base / name).write_bytes(b"different from rebuild")
                    with self.assertRaises(LaunchError):
                        launch.verify_artifacts(c)
                finally:
                    for base in (c.model, c.references):
                        (base / name).write_bytes(saved)
        report = json.loads(c.rebuild_report.read_bytes())
        report["passed"] = False
        write(c.rebuild_report, report)
        with self.assertRaises(LaunchError):
            launch.verify_artifacts(c)

    def test_disabled_verification_or_wrong_model_is_rejected(self) -> None:
        c = self.cfg
        p = c.model / "integer_model.json"
        doc = json.loads(p.read_bytes())
        for value in (False, "true", 1):
            doc["weight_settings"]["verify_sums"] = value
            write(p, doc)
            shutil.copyfile(p, c.references / p.name)
            with self.subTest(value=value), self.assertRaises(LaunchError):
                launch.verify_artifacts(c)
        doc["weight_settings"]["verify_sums"] = True
        doc["weights"] = "synthetic"
        write(p, doc)
        with self.assertRaises(LaunchError):
            launch.verify_artifacts(c)

    def test_canaries_require_measured_identity_and_three_unique_prompts(self) -> None:
        c = self.cfg
        base = json.loads(c.canary_file.read_bytes())
        for changes in (
            {"commitment_id": "11" * 32},
            {"dtype": "auto"},
            {"dtype": "float16"},
            {"canaries": self.rows[:2]},
            {"canaries": [self.rows[0]] * 3},
            {
                "canaries": [
                    *self.rows[:2],
                    {"prompt": [True], "max_tokens": 2, "expected": [200001]},
                ]
            },
        ):
            write(c.canary_file, base | changes)
            with (
                self.subTest(field=next(iter(changes))),
                self.assertRaises(LaunchError),
            ):
                launch.load_canaries(c)
        write(c.canary_file, base)
        c.canary_file.chmod(0o666)
        with self.assertRaises(LaunchError):
            launch.load_canaries(c)

    def test_exactness_report_rejects_skips_or_missing_data(self) -> None:
        report = self.cfg.temp / "case.xml"
        with self.assertRaises(LaunchError):
            launch._pytest_passed(report, {"case", "case2"})
        good = '<testcase classname="tests.test_arithmetic_edges" name="case"/>'
        for child in ("<skipped/>", "<failure/>", "<error/>"):
            report.write_text(
                "<testsuite>"
                + good
                + '<testcase classname="tests.test_arithmetic_edges" name="case2">'
                + child
                + "</testcase></testsuite>"
            )
            with self.subTest(child=child), self.assertRaises(LaunchError):
                launch._pytest_passed(report, {"case", "case2"})
        report.write_text("<testsuite/>")
        with self.assertRaises(LaunchError):
            launch._pytest_passed(report, {"case", "case2"})

        report.write_text("<testsuite>" + good + "</testsuite>")
        with self.assertRaises(LaunchError):
            launch._pytest_passed(report, {"case", "case2"})
        launch._pytest_passed(report, {"case"})

    def test_executable_command_environment_and_live_process_evidence(self) -> None:
        c = self.cfg
        marker = {
            "VLLM_SERVER_DEV_MODE": "1",
            "PYTHONPATH": "/untrusted",
            "VLLM_MODEL_REDIRECT_PATH": "redirect",
            "CUBLAS_EMULATION_STRATEGY": "auto",
        }
        with (
            patch.dict(os.environ, marker),
            patch("engine.launch.verify_gpu") as gpu,
            patch(
                "engine.launch.os.statvfs",
                return_value=SimpleNamespace(f_flag=os.ST_RDONLY),
            ),
            patch("engine.launch.os.geteuid", return_value=c.home.stat().st_uid),
        ):
            env = launch._environment(c)
            self.assertFalse(set(marker) & env.keys())
            self.assertEqual(env["CUDA_VISIBLE_DEVICES"], "0")
            args = launch.command(c, c.temp)
            self.assertIn("integer_model", args)
            self.assertEqual(args[args.index("--dtype") + 1], "float32")
            self.assertEqual(args[args.index("--host") + 1], "127.0.0.1")
            self.assertEqual(
                json.loads(args[args.index("--model-loader-extra-config") + 1]),
                {"reference_directory": str(c.references), "reference_files": 5},
            )
            self.assertNotIn("--trust-remote-code", args)
            self.assertNotIn("--middleware", args)
            started = launch.start(c)
            try:
                gpu.assert_called_once()
                assert started.process.stdout is not None
                with self.assertRaises(LaunchError):
                    started.startup.evidence()
                started.startup.observe(started.process.stdout.readline())
                with self.assertRaises(LaunchError):
                    started.startup.evidence()
                started.startup.observe(started.process.stdout.readline())
                self.assertEqual(started.startup.evidence().instance, started.instance)
                second = launch.start(c)
                try:
                    self.assertNotEqual(started.instance, second.instance)
                    with self.assertRaises(LaunchError):
                        second.startup.evidence()
                finally:
                    second.close()
            finally:
                started.close()
        self.assertEqual(list(c.temp.iterdir()), [])

    def test_incomplete_or_unrelated_log_text_never_supplies_evidence(self) -> None:
        tracker = launch.StartupTracker("instance")
        for line in (
            TENSOR_LINE,
            FILE_LINE[:-1],
            b"WARNING unrelated " + FILE_LINE,
            FILE_LINE + b" quoted",
            TENSOR_LINE,
        ):
            tracker.observe(line)
        with self.assertRaises(LaunchError):
            tracker.evidence()
        for line in (FILE_LINE, TENSOR_LINE):
            tracker.observe(
                b"(EngineCore pid=200) INFO 01-01 12:10:22 [loader.py:112] "
                + line
                + b"\n"
            )
        self.assertTrue(tracker.evidence().weight_tensors_verified)

    def test_shutdown_uses_term_then_escalates_only_after_grace(self) -> None:
        for stubborn, expected in ((False, signal.SIGTERM), (True, signal.SIGKILL)):
            policy = (
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)" if stubborn else "pass"
            )
            cmd = [
                sys.executable,
                "-u",
                "-c",
                f"import signal,time; {policy}; print('ready'); time.sleep(60)",
            ]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            started = launch.StartedEngine(
                proc,
                "test",
                launch.StartupTracker("test"),
                (),
                tempfile.TemporaryDirectory(dir=self.cfg.temp),
                0.06,
            )
            try:
                assert proc.stdout is not None
                self.assertEqual(proc.stdout.readline(), b"ready\n")
            finally:
                started.close()
            with self.subTest(stubborn=stubborn):
                self.assertEqual(proc.returncode, -expected)
                started.close()
        self.assertEqual(list(self.cfg.temp.iterdir()), [])

    def test_missing_gpu_gate_aborts_before_process_creation(self) -> None:
        with (
            patch(
                "engine.launch.os.statvfs",
                return_value=SimpleNamespace(f_flag=os.ST_RDONLY),
            ),
            patch(
                "engine.launch.verify_gpu", side_effect=LaunchError("no serving GPU")
            ),
            patch("engine.launch.subprocess.Popen") as spawn,
            self.assertRaises(LaunchError),
        ):
            launch.start(replace(self.cfg, dtype="float32"))
        spawn.assert_not_called()
        self.assertEqual(list(self.cfg.temp.iterdir()), [])
