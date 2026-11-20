"""The hardware flow exposes bounded diagnostics for malformed private captures."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from prover.request import build_statement
from prover.worker import CandidateProof
from tests.test_discovery import CONFIG
from tools import m2_flow


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

    def test_retained_receipts_are_rechecked_on_restart(self) -> None:
        prompt, reply = (8, 12), (34,)
        proof = CandidateProof(build_statement(prompt, reply), bytes(4), b"test")
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            config = {
                "proof_source_host": "ad" * 32,
                "assets": temp,
                "service": CONFIG,
                "endpoint_id": "test-endpoint",
            }
            with (
                patch.object(
                    m2_flow,
                    "captured",
                    return_value=(
                        [{"role": "user", "content": "test"}],
                        prompt,
                        reply,
                        proof,
                    ),
                ),
                patch.object(
                    m2_flow,
                    "settings",
                    return_value=({}, Mock(check=Mock(return_value="verified"))),
                ),
                patch.object(m2_flow, "host_id", return_value="53" * 32),
                patch.object(m2_flow, "ChatRenderer") as renderer,
                patch.object(
                    m2_flow, "holder", return_value=(30, "RECEIPT_VERIFIED")
                ) as holder,
            ):
                renderer.return_value.decode.side_effect = lambda tokens: str(tokens[0])
                delivery = m2_flow.prepare(config, work)
                provenance = (delivery / "provenance.json").read_bytes()
                self.assertEqual(m2_flow.prepare(config, work), delivery)
                self.assertEqual(holder.call_count, 2)
                self.assertEqual(
                    (delivery / "provenance.json").read_bytes(), provenance
                )
                holder.return_value = (1, "INVALID")
                with self.assertRaises(ValueError):
                    m2_flow.prepare(config, work)
                (delivery / "provenance.json").write_text("{}")
                with self.assertRaises(KeyError):
                    m2_flow.prepare(config, work)
