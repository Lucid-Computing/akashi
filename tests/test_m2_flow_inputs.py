"""The hardware flow exposes bounded diagnostics for malformed private captures."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def run_flow(config: Path, work: Path, result: Path) -> str:
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.m2_flow",
            "--prepare-only",
            "--config",
            str(config),
            "--work",
            str(work),
            "--output",
            str(result),
        ],
        capture_output=True,
        check=False,
    )
    assert process.returncode == 1
    assert process.stdout == process.stderr == b""
    report = json.loads(result.read_bytes())
    assert report.keys() == {"schema_version", "status", "reason"}
    assert report["status"] == "incomplete"
    return str(report["reason"])


class FlowPrivateInputTests(unittest.TestCase):
    def test_bad_case_rows(self) -> None:
        for inputs, candidates in (
            ([], {}),
            ([None], {}),
            ([{"id": "arithmetic-apples"}], {"canaries": []}),
            ([{"id": "arithmetic-apples"}], {"canaries": [0]}),
            ([{"id": "arithmetic-apples"}], {"canaries": {"0": {}}}),
        ):
            with (
                self.subTest(inputs=inputs, candidates=candidates),
                tempfile.TemporaryDirectory() as temp,
            ):
                root = Path(temp)
                config = root / "private-canary-config"
                config.write_text(
                    json.dumps({"schema_version": 1, "capture": str(root)})
                )
                config.chmod(0o600)
                (root / "inputs-16.json").write_text(json.dumps(inputs))
                (root / "unproven-candidates.json").write_text(json.dumps(candidates))
                (root / "ready.json").write_text("{}")
                self.assertEqual(
                    run_flow(config, root / "work", root / "result"), "ValueError"
                )

    def test_direct_flow_requires_private_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "private-canary-config"
            config.write_text("{}")
            config.chmod(0o644)
            self.assertEqual(
                run_flow(config, root / "work", root / "result"), "ValueError"
            )
            config.chmod(0o600)
            alias = root / "alias"
            alias.symlink_to(config)
            self.assertEqual(run_flow(alias, root / "work", root / "result"), "OSError")
