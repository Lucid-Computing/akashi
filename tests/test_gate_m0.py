"""M0 accounting controls. Generated proofs in these tests are deliberately synthetic."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from gateway.renderer import ChatRenderer
from prover.request import build_statement
from tools import gate_m0 as m0


def write(path: Path, data: object) -> None:
    path.write_text(json.dumps(data))


def metrics(prompt: int, reply: int) -> dict[str, Any]:
    values = {
        "request_prefill_time_seconds": 0.5,
        "request_decode_time_seconds": 0.0,
        "time_to_first_token_seconds": 0.6,
        "request_prompt_tokens": prompt,
        "request_generation_tokens": reply,
    }
    after = {
        f"vllm:{k}_{field}": (value if field == "sum" else 1)
        for k, value in values.items()
        for field in ("sum", "count")
    }
    return {
        "covered": True,
        "integrity_error": False,
        "observed_request_ns": 1,
        "before": dict.fromkeys(after, 0),
        "after": after,
    }


def stream(directory: Path, ids: list[int] | None, done: bool = True) -> None:
    write(
        directory / "stream.private.jsonl",
        {
            "after_ns": 2,
            "frame": {
                "choices": [{"index": 0, "finish_reason": "length", "token_ids": ids}]
            },
        },
    )
    write(
        directory / "stream-measurement.json",
        {
            "case": "science-rain",
            "done": done,
            "status": 200,
            "content_type": "text/event-stream; charset=utf-8",
            "elapsed_ns": 3,
            "chunks": [
                {
                    "after_ns": 2,
                    "has_token_ids": ids is not None,
                    "n_ids": len(ids) if ids is not None else None,
                    "finish_reason": "length",
                }
            ],
        },
    )


class BaselineGateTests(unittest.TestCase):
    def test_cross_host_mismatch_is_measured_and_excludes_failed_host(self) -> None:
        known = [
            {"prompt": [index + 10], "max_tokens": 1, "expected": [30 + index]}
            for index in range(3)
        ]
        observed = [
            {**row, "expected": [60]} if i == 1 else dict(row)
            for i, row in enumerate(known)
        ]
        ready = {
            "canaries": known,
            "dtype": "bfloat16",
            "commitment_id": m0.COMMITMENT,
            "float64_cases_passed": 51,
        }
        platform = {
            "architecture": "x86_64",
            "vllm": "0.29.0",
            "gpu_model": "NVIDIA H100 NVL",
            "driver": "580.1.0",
            "cuda": "13.2.2",
            "torch": "2.13.0+cu130",
        }
        record = {
            "schema_version": 1,
            "status": "mismatch",
            "primary_host": "ad" * 32,
            "secondary_host": "bc" * 32,
            "primary_ready_sha256": "1f" * 32,
            "canaries": observed,
            "secondary_platform": platform,
            "commitment_id": m0.COMMITMENT,
            "dtype": "bfloat16",
            "same_process_f21": True,
            "float64_cases_passed": 51,
            "gate_failure": "canary_token_mismatch",
            "secondary_eligible": False,
            "startup_refused": True,
            "matched": False,
            "compared_mismatch_indices": [1],
            "startup_mismatch_indices": [1],
            "startup_attempts": observed[:2],
            "prior_attempt": {
                "startup_refused": True,
                "gate_failure": "canary_token_mismatch",
            },
            "same_secondary_replay": True,
            "secondary_repeat_mismatch_indices": [],
        }
        result = m0.cross_platform(record, ready, "1f" * 32)
        self.assertEqual(result["cross_host"], "canary_mismatch")
        self.assertEqual(
            result["cross_host_comparison"],
            {
                "matched": False,
                "startup_refused": True,
                "canaries_compared": 3,
                "canaries_matching": 2,
                "primary_mismatch_indices": [1],
                "startup_mismatch_indices": [1],
                "secondary_repeat_mismatch_indices": [],
                "same_secondary_replay": True,
                "secondary_repeat_cases": 2,
                "startup_refusals": 2,
            },
        )
        public = json.dumps(result)
        for secret in (
            "expected",
            "primary_host",
            "ad" * 32,
            "prompt",
            "prior_attempt",
        ):
            self.assertNotIn(secret, public)
        for change in (
            {"primary_ready_sha256": "3f" * 32},
            {"dtype": "float16"},
            {"commitment_id": "aa" * 32},
            {"canaries": known},
            {"canaries": observed[:2]},
            {"status": "measured"},
            {"secondary_host": "ad" * 32},
            {"gate_failure": "unavailable"},
            {"secondary_eligible": True},
            {"compared_mismatch_indices": [True]},
            {"compared_mismatch_indices": [0]},
            {"startup_mismatch_indices": [0]},
            {"same_process_f21": False},
            {"canaries": [{**observed[0], "prompt": [1]}, *observed[1:]]},
            {"canaries": [{**observed[0], "expected": [True]}, *observed[1:]]},
        ):
            with self.subTest(change=change), self.assertRaises(m0.EvidenceError):
                m0.cross_platform({**record, **change}, ready, "1f" * 32)
        inconsistent = {
            **record,
            "status": "inconsistent_runs",
            "same_secondary_replay": False,
            "secondary_repeat_mismatch_indices": [1],
            "startup_attempts": [observed[0], {**observed[1], "expected": [85]}],
        }
        measured = m0.cross_platform(inconsistent, ready, "1f" * 32)
        self.assertEqual(measured["cross_host"], "inconsistent_runs")
        comparisons = result["cross_host_comparison"]
        assert isinstance(comparisons, dict)
        self.assertEqual(
            measured["cross_host_comparison"],
            {
                **comparisons,
                "same_secondary_replay": False,
                "secondary_repeat_mismatch_indices": [1],
            },
        )
        invalid: dict[str, Any]
        for invalid in (
            {"status": "mismatch"},
            {"secondary_repeat_mismatch_indices": []},
            {"startup_attempts": []},
            {
                "prior_attempt": {
                    "startup_refused": False,
                    "gate_failure": "canary_token_mismatch",
                }
            },
        ):
            with self.subTest(invalid=invalid), self.assertRaises(m0.EvidenceError):
                m0.cross_platform({**inconsistent, **invalid}, ready, "1f" * 32)
        positive = m0.cross_platform(
            {
                **record,
                "status": "measured",
                "canaries": known,
                "matched": True,
                "startup_refused": False,
                "secondary_eligible": True,
            },
            ready,
            "1f" * 32,
        )
        self.assertEqual(positive["cross_host"], "matched_three_canaries")

    def test_rejects_incomplete_gpu_suite_even_when_eligibility_count_matches(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "float64.xml"
            report.write_text(
                '<testsuite tests="1" failures="0" errors="0" skipped="0">'
                '<testcase classname="tests.test_arithmetic_edges" '
                'name="test_clamp_at_its_ends"/></testsuite>'
            )
            with self.assertRaisesRegex(m0.EvidenceError, "arithmetic evidence"):
                m0.float64_suite(report, 1)

    def test_preserves_measured_engine_startup_origin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp)
            record = capture / "startup-measurement.json"
            origins = (
                "supervisor_start_to_both_markers_and_health",
                "after_popen_to_both_markers_and_health",
            )
            for origin in origins:
                write(record, {origin + "_ns": 17})
                result = m0.engine_startup(capture, 19)
                self.assertEqual(result["engine_startup_to_health_ns"], 17)
                self.assertEqual(result["engine_startup_to_health_interval"], origin)
                self.assertEqual(result["engine_startup_to_eligible_ns"], 19)
            write(record, {origins[0] + "_ns": 17})
            self.assertEqual(
                m0.engine_startup(capture, 19)["engine_startup_to_eligible_interval"],
                "supervisor_start_to_eligible",
            )
            with self.assertRaisesRegex(m0.EvidenceError, "eligibility preceded"):
                m0.engine_startup(capture, 15)
            for values in ({}, {origin + "_ns": 17 for origin in origins}):
                write(record, values)
                with self.assertRaisesRegex(m0.EvidenceError, "startup interval"):
                    m0.engine_startup(capture, 19)

    def test_missing_configuration_replaces_previous_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            write(out, {"status": "passed", "private": "never republish"})
            self.assertFalse(m0.gate(None, out))
            report = m0.document(out)
            self.assertEqual(
                (report["status"], report["proofs_verified"]), ("incomplete", 0)
            )
            self.assertNotIn("private", report)
            self.assertFalse(m0.gate(Path(tmp) / "sensitive-operator-file", out))
            self.assertNotIn("sensitive", out.read_text())

    def test_rejects_mixed_missing_and_nonfinite_counter_intervals(self) -> None:
        for field, value in (
            ("request_decode_time_seconds_count", 2),
            ("request_prefill_time_seconds_sum", float("nan")),
            ("request_generation_tokens_sum", 2),
            ("request_prompt_tokens_count", 0),
        ):
            with self.subTest(field=field):
                item = metrics(20, 1)
                item["after"]["vllm:" + field] = value
                with self.assertRaises(m0.EvidenceError):
                    m0.engine_times(item, 20, 1)
        self.assertEqual(
            m0.engine_times(metrics(20, 1), 20, 1)["request_decode_time_seconds"], 0
        )

    def test_stream_distinguishes_absent_and_disagreeing_ids_from_matching(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for ids, support in ((None, "absent"), ([1], "different"), ([2], "match")):
                stream(root, ids)
                self.assertEqual(m0.stream_support(root, [2])["token_ids"], support)
            stream(root, [2], done=False)
            with self.assertRaises(m0.EvidenceError):
                m0.stream_support(root, [2])

    @unittest.skipUnless(
        os.environ.get("VIG_RENDER_ASSETS"), "requires pinned tokenizer assets"
    )
    def test_each_original_reply_is_rebuilt_and_checked(self) -> None:
        assets = Path(os.environ["VIG_RENDER_ASSETS"])
        renderer = ChatRenderer(assets)
        cases = m0.rows(m0.WORKLOAD)
        self.assertEqual(len({case["id"] for case in cases}), 16)
        self.assertEqual(
            {case["prompt_tokens"] for case in cases if case["prompt_tokens"] >= 200},
            {200, 256, 320, 384, 448, 512, 640, 768},
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            captured, intervals, originals = [], [], []
            for case in cases:
                prompt = renderer.render(case["messages"])
                self.assertEqual(len(prompt), case["prompt_tokens"])
                budget = case["max_tokens"]
                reply = [2] * budget
                statement = build_statement(prompt, reply)
                originals.append(statement)
                ident = case["id"]
                (root / f"{ident}.request").write_bytes(statement)
                folder = root / ident
                folder.mkdir()
                (folder / "example.proof").write_bytes(b"fixture")
                (folder / "example.y").write_bytes(bytes(4))
                write(folder / "timing.json", {"batch_size": 1, "proof_ns": 1})
                captured.append(
                    {"prompt": prompt, "max_tokens": budget, "expected": reply}
                )
                intervals.append(
                    {
                        "id": ident,
                        "caller_budget": budget,
                        "prompt_length": len(prompt),
                        "reply_length": len(reply),
                        **metrics(len(prompt), len(reply)),
                    }
                )
            write(
                root / "unproven-candidates.json",
                {
                    "commitment_id": m0.COMMITMENT,
                    "dtype": "float32",
                    "canaries": captured,
                },
            )
            (root / "per-case-metrics.jsonl").write_text(
                "".join(json.dumps(r) + "\n" for r in intervals)
            )
            stream(root, captured[2]["expected"])
            seen: list[bytes] = []

            def check(statement: bytes, y: bytes, proof: bytes) -> str:
                self.assertEqual((y, proof), (bytes(4), b"fixture"))
                seen.append(statement)
                return "verified"

            public: list[dict[str, object]] = []
            self.assertEqual(
                m0.measure_cases(root, root, assets, 7, check, public)["token_ids"],
                "match",
            )
            self.assertEqual(seen, originals)
            self.assertEqual(len(public), 16)
            self.assertTrue(
                all("prompt" not in r and "expected" not in r for r in public)
            )
            with self.assertRaisesRegex(m0.EvidenceError, "native verification"):
                m0.measure_cases(root, root, assets, 7, lambda *_: "rejected", [])
            (root / f"{cases[1]['id']}.request").write_bytes(originals[0])
            partial: list[dict[str, object]] = []
            with self.assertRaisesRegex(m0.EvidenceError, "statement mismatch"):
                m0.measure_cases(root, root, assets, 7, check, partial)
            self.assertEqual(len(partial), 1)
