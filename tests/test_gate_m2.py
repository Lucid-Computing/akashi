"""M2 promotion checks use fixed evidence and publish only bounded, redacted fields."""

import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

from prover.request import build_statement
from prover.runtime import REVISION
from prover.submission import COMMITMENT
from prover.worker import CandidateProof
from tests.test_discovery import CONFIG
from tools import gate_m1, gate_m2, m2_flow

_AGE = 3 * 24 * 60 * 60
_PRIVATE = "private-content-must-never-appear"
_DIGEST = "53" * 32


def _observed() -> dict[str, object]:
    return {
        "mode": "D",
        "engine": "mock",
        "prover": "mock",
        "fixture_sha256": _DIGEST,
        "logged": 3,
        "promises_verified": 3,
        "selected": 1,
        "unselected": 1,
        "gaps": 1,
        "handed_off": 1,
        "mock_proofs": 1,
        "recomputed": 3,
        "failure_controls": 2,
    }


def _flow() -> dict[str, Any]:
    def observation(outcome: str, code: int) -> dict[str, object]:
        return {
            "outcome": outcome,
            "holder_outcome": outcome,
            "holder_exit": code,
            "signed_verdict_verified": True,
            "receipt_reverified": True,
            "capability_rejected": True,
        }

    return {
        "schema_version": 1,
        "status": "passed",
        "commitment_id": COMMITMENT,
        "flashprove_revision": REVISION,
        "batch_size": 1,
        "distinct_prover_verifier_hosts": True,
        "distinct_rx_verifier_hosts": True,
        "corrected_prefix_matches_proof": True,
        "original_matches_proof": True,
        "reference_trace_bound": True,
        "proof_sha256": _DIGEST,
        "original_statement_sha256": "a8" * 32,
        "substitute_statement_sha256": "74" * 32,
        "challenge_clock": "controlled_plus_three_days",
        "actual_elapsed_seconds": 1.5,
        "challenge_age_seconds": _AGE,
        "original": observation("CONFORMS", 0),
        "substitute": observation("DEVIATES", 21),
    }


class M2GateTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.config = self.root / "private-operator.json"
        self.config.write_text(_PRIVATE)
        self.config.chmod(0o600)
        self.work = self.root / "private-work"
        self.work.mkdir(mode=0o700)
        self.m0, self.m1, self.output = (
            self.root / f"{name}.json" for name in ("m0", "m1", "m2")
        )
        fixtures = self.root / "tests" / "fixtures"
        fixtures.mkdir(parents=True)
        for path in gate_m1.FIXTURES.iterdir():
            if path.name != "m0-workload.jsonl":
                (fixtures / path.name).symlink_to(
                    path, target_is_directory=path.is_dir()
                )
        workload = fixtures / "m0-workload.jsonl"
        checked_workload = gate_m1.FIXTURES / workload.name
        if checked_workload.is_file():
            workload.write_bytes(checked_workload.read_bytes())
        else:
            # M0 and M2 can be developed separately. Bind every row to a fixture
            # file with the same fields emitted by the real M0 workload.
            cases = [
                {
                    "id": f"case-{i}",
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 1,
                    "prompt_tokens": 7,
                }
                for i in range(16)
            ]
            workload.write_text("".join(json.dumps(case) + "\n" for case in cases))
        cases = [json.loads(line) for line in workload.read_bytes().splitlines()]
        self.m0.write_text(
            json.dumps(
                {
                    "gate": "M0",
                    "schema_version": 1,
                    "status": "passed",
                    "commitment_id": COMMITMENT,
                    "batch_size": 1,
                    "proofs_verified": len(cases),
                    "platform": {"flashprove_revision": REVISION},
                    "workload_sha256": hashlib.sha256(
                        workload.read_bytes()
                    ).hexdigest(),
                    "replies": [
                        {
                            "id": case["id"],
                            "caller_budget": case["max_tokens"],
                            "prompt_tokens": case["prompt_tokens"],
                            "reply_tokens": 1,
                            "proof_bytes": 123,
                            "proof_ns": 25,
                            "verify_ns": 12,
                        }
                        for case in cases
                    ],
                }
            )
        )
        # Exercise the actual M1 report writer. Only the model assets, vector
        # execution and toy delivery are stubbed; no downloads or native setup.
        ran = unittest.TestResult()
        ran.testsRun = 1
        with (
            patch.object(gate_m1, "_assets", return_value=fixtures),
            patch.object(
                unittest.defaultTestLoader,
                "loadTestsFromNames",
                return_value=unittest.TestSuite(),
            ),
            patch.object(unittest.TextTestRunner, "run", return_value=ran),
            patch("tests.m1_flow.run_flow", return_value=_observed()),
        ):
            self.assertTrue(gate_m1.gate(self.m1))
        root = patch.object(gate_m2, "ROOT", self.root)
        root.start()
        self.addCleanup(root.stop)

    def run_gate(
        self, flow: dict[str, Any], *, elapsed: bool = False
    ) -> tuple[bool, dict[str, Any]]:
        def publish(
            command: list[str], **settings: object
        ) -> subprocess.CompletedProcess[bytes]:
            self.assertEqual("--elapsed" in command, elapsed)
            self.assertEqual(settings["stdout"], subprocess.DEVNULL)
            self.assertEqual(settings["stderr"], subprocess.DEVNULL)
            Path(command[command.index("--output") + 1]).write_text(json.dumps(flow))
            return subprocess.CompletedProcess(command, 0)

        with (
            patch.object(subprocess, "check_output", return_value="3" * 40),
            patch.object(subprocess, "run", side_effect=publish),
        ):
            passed = gate_m2.gate(
                self.config, self.work, self.m0, self.m1, self.output, elapsed=elapsed
            )
        text = self.output.read_text()
        for secret in (_PRIVATE, str(self.root), self.config.name):
            self.assertNotIn(secret, text)
        return passed, json.loads(text)

    def test_real_m1_report_shape_and_fixed_mock_observations(self) -> None:
        self.assertEqual(
            gate_m2.prerequisite(self.m1, "M1"),
            hashlib.sha256(self.m1.read_bytes()).hexdigest(),
        )
        baseline = json.loads(self.m1.read_bytes())
        for key, wrong in (
            ("engine", "live"),
            ("prover", "live"),
            ("selected", True),
            ("failure_controls", 0),
        ):
            altered = copy.deepcopy(baseline)
            for side in ("expected", "observed"):
                altered["mode_d"][side][key] = wrong
            self.m1.write_text(json.dumps(altered))
            with (
                self.subTest(field=key),
                self.assertRaises((KeyError, TypeError, ValueError)),
            ):
                gate_m2.prerequisite(self.m1, "M1")
        del baseline["vectors"]["beacon"]
        self.m1.write_text(json.dumps(baseline))
        with self.assertRaises((KeyError, TypeError, ValueError)):
            gate_m2.prerequisite(self.m1, "M1")

    def test_malformed_prerequisite_shape_returns_only_public_failure(self) -> None:
        doc = json.loads(self.m1.read_bytes())
        doc["vectors"] = [_PRIVATE]
        self.m1.write_text(json.dumps(doc))
        good, report = self.run_gate(_flow())
        self.assertFalse(good)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["failed_stage"], "previous_milestones")
        self.assertNotIn("checks", report)

    def test_m0_requires_complete_workload_and_exact_integer_measurements(self) -> None:
        self.assertEqual(
            gate_m2.prerequisite(self.m0, "M0"),
            hashlib.sha256(self.m0.read_bytes()).hexdigest(),
        )
        original = json.loads(self.m0.read_bytes())
        for key, value in (
            ("status", "incomplete"),
            ("batch_size", True),
            ("proofs_verified", 15),
            ("workload_sha256", "00" * 32),
            ("commitment_id", "ff" * 32),
        ):
            self.m0.write_text(json.dumps({**original, key: value}))
            with (
                self.subTest(field=key),
                self.assertRaises((KeyError, TypeError, ValueError)),
            ):
                gate_m2.prerequisite(self.m0, "M0")
        for key, value in (
            ("id", original["replies"][0]["id"]),
            ("verify_ns", True),
            ("proof_bytes", 0),
        ):
            altered = copy.deepcopy(original)
            altered["replies"][1][key] = value
            self.m0.write_text(json.dumps(altered))
            with (
                self.subTest(row_field=key),
                self.assertRaises((KeyError, TypeError, ValueError)),
            ):
                gate_m2.prerequisite(self.m0, "M0")

    def test_age_threshold_and_clock_mode_are_independent_safeguards(self) -> None:
        for clock, actual, age, accepted in (
            ("controlled_plus_three_days", 0, _AGE, True),
            ("elapsed_wall_clock", _AGE, _AGE, True),
            ("elapsed_wall_clock", _AGE - 0.001, _AGE, False),
            ("elapsed_wall_clock", _AGE, _AGE - 0.001, False),
            ("controlled_plus_three_days", 0, _AGE - 0.001, False),
            ("elapsed_wall_clock", True, _AGE, False),
            ("elapsed_wall_clock", float("inf"), _AGE, False),
        ):
            proof = {
                **_flow(),
                "challenge_clock": clock,
                "actual_elapsed_seconds": actual,
                "challenge_age_seconds": age,
            }
            with self.subTest(clock=clock, actual=actual, age=age):
                if accepted:
                    checks = gate_m2.checked_flow(proof)
                    self.assertEqual(checks["challenge_clock"], clock)
                    self.assertIs(
                        checks["elapsed_age_verified"], clock == "elapsed_wall_clock"
                    )
                else:
                    with self.assertRaises((KeyError, TypeError, ValueError)):
                        gate_m2.checked_flow(proof)
        good, report = self.run_gate(_flow(), elapsed=True)
        self.assertFalse(good)
        self.assertNotEqual(report["status"], "passed")

    def test_fixed_mock_substitute_creates_a_distinct_signed_delivery(self) -> None:
        prompt = (8, 12)
        config = {
            "proof_source_host": "ac" * 32,
            "assets": str(self.work),
            "service": CONFIG,
            "endpoint_id": "m2-test",
        }
        for served, expected in ((21, False), (34, True)):
            # The real MockEngine's first token for this prefix is 21.
            proof = CandidateProof(
                build_statement(prompt, (served,)), bytes(4), b"synthetic-proof"
            )
            captured = (
                [{"role": "user", "content": "synthetic input"}],
                prompt,
                (served,),
                proof,
            )
            with (
                self.subTest(served=served),
                patch.object(m2_flow, "captured", return_value=captured),
                patch.object(
                    m2_flow,
                    "settings",
                    return_value=({}, Mock(check=Mock(return_value="verified"))),
                ),
                patch.object(m2_flow, "host_id", return_value="99" * 32),
                patch.object(m2_flow, "ChatRenderer") as renderer,
            ):
                renderer.return_value.decode.side_effect = lambda ids: (
                    f"test token {ids[0]}"
                )
                if not expected:
                    with self.assertRaises(ValueError):
                        m2_flow.prepare(config, self.work)
                    self.assertFalse((self.work / "delivery").exists())
                    continue
                delivery = m2_flow.prepare(config, self.work)
                original = json.loads((delivery / "original.json").read_bytes())
                substitute = json.loads((delivery / "substitute.json").read_bytes())
                self.assertEqual(original["verification"]["reply_token_ids"], [34])
                self.assertEqual(substitute["verification"]["reply_token_ids"], [21])
                self.assertNotEqual(
                    original["verification"]["receipt"]["promise_sig"],
                    substitute["verification"]["receipt"]["promise_sig"],
                )

    def test_fixed_conformance_and_substitute_deviation_results(self) -> None:
        baseline = _flow()
        self.assertEqual(gate_m2.checked_flow(baseline)["deviation_exit"], 21)
        for field, value in (
            ("status", "incomplete"),
            ("schema_version", True),
            ("batch_size", True),
            ("distinct_rx_verifier_hosts", 1),
            ("distinct_prover_verifier_hosts", False),
            ("reference_trace_bound", False),
            ("original_matches_proof", False),
            ("corrected_prefix_matches_proof", False),
            ("proof_sha256", "ab" * 31),
            ("substitute_statement_sha256", baseline["original_statement_sha256"]),
        ):
            with (
                self.subTest(field=field),
                self.assertRaises((KeyError, TypeError, ValueError)),
            ):
                gate_m2.checked_flow({**baseline, field: value})
        for name, wrong in (("original", "DEVIATES"), ("substitute", "CONFORMS")):
            for field, value in (
                ("outcome", wrong),
                ("holder_outcome", wrong),
                ("holder_exit", False),
                ("signed_verdict_verified", False),
                ("receipt_reverified", False),
                ("capability_rejected", 1),
            ):
                flow = copy.deepcopy(baseline)
                flow[name][field] = value
                with (
                    self.subTest(name=name, field=field),
                    self.assertRaises((KeyError, TypeError, ValueError)),
                ):
                    gate_m2.checked_flow(flow)

    def test_public_output_redaction_oq6_and_stale_pass_replaced_on_missing_files(
        self,
    ) -> None:
        flow = _flow()
        flow.update(credential=_PRIVATE, prompt_token_ids=[_PRIVATE])
        flow["substitute"]["capability"] = _PRIVATE
        good, report = self.run_gate(flow)
        self.assertTrue(good)
        self.assertEqual(
            (report["schema_version"], report["gate"], report["status"]),
            (1, "M2", "passed"),
        )
        self.assertEqual(
            report["batch_privacy_oq6"], "open_single_request_batches_only"
        )
        self.assertEqual(
            report["checks"]["challenge_clock"], "controlled_plus_three_days"
        )
        self.assertEqual(
            report["milestone_evidence_sha256"],
            {
                "M0": hashlib.sha256(self.m0.read_bytes()).hexdigest(),
                "M1": hashlib.sha256(self.m1.read_bytes()).hexdigest(),
            },
        )
        for missing in (self.m1, self.m0, self.config):
            with self.subTest(path=missing.name):
                existing = missing.read_bytes()
                missing.unlink()
                good, report = self.run_gate(flow)
                self.assertFalse(good)
                self.assertEqual(report["status"], "incomplete")
                self.assertNotIn("checks", report)
                missing.write_bytes(existing)
                missing.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
