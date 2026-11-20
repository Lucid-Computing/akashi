"""Reconstruct and CPU-verify all 16 private Maverick whole-reply measurements."""

import argparse
import hashlib
import importlib
import json
import math
import os
import platform
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from gateway.renderer import ChatRenderer
from prover.request import VOCABULARY_SIZE, build_statement, reply_complete
from tools.gate_m1 import ROOT, _write

WORKLOAD = ROOT / "tests/fixtures/m0-workload.jsonl"
COMMITMENT = "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46"

# SHA-256 of the sorted testcase names, one ASCII name and LF per line, from the
# F4 integer_model/tests/test_arithmetic_edges.py with pytest 9.0.3 --collect-only.
FLOAT64_NAMES_SHA256 = (
    "879e0ef9ed58cc915b0081e37f1a2ab494771826364a62812e15016713b9d51a"
)


class EvidenceError(ValueError):
    """A fixed, public reason for an incomplete baseline."""


def require(value: bool, reason: str) -> None:
    if not value:
        raise EvidenceError(reason)


def document(path: Path) -> Any:
    return json.loads(path.read_bytes())


def rows(path: Path) -> list[Any]:
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def positive_ns(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise EvidenceError("missing monotonic duration")
    return value


def interval(m: dict[str, Any], name: str, field: str) -> float:
    key = f"vllm:{name}_{field}"
    a, b = m["before"][key], m["after"][key]
    require(
        all(type(v) in (float, int) and math.isfinite(v) for v in (a, b))
        and 0 <= a <= b,
        "invalid engine counter interval",
    )
    return float(b - a)


def engine_times(m: dict[str, Any], prompt: int, reply: int) -> dict[str, object]:
    require(
        m["covered"] is True and m["integrity_error"] is False,
        "uncovered engine request",
    )
    for key, n in (
        ("request_prompt_tokens", prompt),
        ("request_generation_tokens", reply),
    ):
        require(
            interval(m, key, "sum") == n and interval(m, key, "count") == 1,
            "engine counter interval covers a different request",
        )
    result: dict[str, object] = {"request_ns": positive_ns(m["observed_request_ns"])}
    for name in (
        "request_prefill_time_seconds",
        "request_decode_time_seconds",
        "time_to_first_token_seconds",
    ):
        require(interval(m, name, "count") == 1, "missing per-request engine timing")
        result[name] = interval(m, name, "sum")
    return result


def stream_support(capture: Path, expected: list[int]) -> dict[str, object]:
    measured = document(capture / "stream-measurement.json")
    require(
        measured["case"] == "science-rain"
        and measured["done"] is True
        and measured["status"] == 200
        and measured["content_type"].split(";")[0].strip() == "text/event-stream",
        "incomplete streaming observation",
    )
    ids: list[int] = []
    chunks: list[dict[str, object]] = []
    finished = False
    previous = 0
    for item in rows(capture / "stream.private.jsonl"):
        choices = item["frame"]["choices"]
        require(
            len(choices) == 1 and choices[0]["index"] == 0 and not finished,
            "invalid streaming choices",
        )
        choice = choices[0]
        tokens = choice.get("token_ids")
        require(
            tokens is None
            or isinstance(tokens, list)
            and all(type(t) is int for t in tokens),
            "invalid streamed token IDs",
        )
        if tokens is not None:
            ids.extend(tokens)
        offset = positive_ns(item["after_ns"])
        require(offset >= previous, "out-of-order streamed frames")
        previous = offset
        require(
            choice.get("finish_reason") in (None, "length", "stop"),
            "invalid stream finish reason",
        )
        finished = choice.get("finish_reason") is not None
        chunks.append(
            {
                "after_ns": offset,
                "has_token_ids": tokens is not None,
                "n_ids": None if tokens is None else len(tokens),
                "finish_reason": choice.get("finish_reason"),
            }
        )
    duration = positive_ns(measured["elapsed_ns"])
    require(
        finished and chunks == measured["chunks"] and previous <= duration,
        "stream summary differs from captured frames",
    )
    return {
        "case": measured["case"],
        "frames": len(chunks),
        "elapsed_ns": duration,
        "token_ids": "match" if ids == expected else "different" if ids else "absent",
    }


def measure_cases(
    capture: Path,
    proofs: Path,
    assets: Path,
    limit: int,
    check: Callable[[bytes, bytes, bytes], str],
    verified: list[dict[str, object]],
) -> dict[str, object]:
    workload = rows(WORKLOAD)
    captured = document(capture / "unproven-candidates.json")
    candidates = captured["canaries"]
    metrics = rows(capture / "per-case-metrics.jsonl")
    require(
        captured["commitment_id"] == COMMITMENT
        and captured["dtype"] in ("float32", "bfloat16", "float16")
        and len(workload) == len(candidates) == len(metrics) == 16,
        "incomplete real-model corpus",
    )
    renderer = ChatRenderer(assets)
    for case, candidate, metric in zip(workload, candidates, metrics, strict=True):
        ident, budget = case["id"], case["max_tokens"]
        prompt, reply = renderer.render(case["messages"]), candidate["expected"]
        require(
            list(prompt) == candidate["prompt"]
            and len(prompt) == case["prompt_tokens"]
            and type(candidate["max_tokens"]) is int
            and type(metric["caller_budget"]) is int
            and candidate["max_tokens"] == metric["caller_budget"] == budget
            and metric["id"] == ident
            and metric["prompt_length"] == len(prompt)
            and metric["reply_length"] == len(reply)
            and reply_complete(reply, budget),
            "captured reply differs from fixed workload or is incomplete",
        )
        statement = build_statement(prompt, reply)
        require(
            (capture / f"{ident}.request").read_bytes() == statement,
            "served statement mismatch",
        )
        timing = engine_times(metric, len(prompt), len(reply))
        folder = proofs / ident
        generation = document(folder / "timing.json")
        require(
            type(generation["batch_size"]) is int and generation["batch_size"] == 1,
            "proof generation did not isolate one request",
        )
        proof_ns = positive_ns(generation["proof_ns"])
        if "request_sha256" in generation:
            require(
                generation["request_sha256"] == hashlib.sha256(statement).hexdigest(),
                "proof timing belongs to a different statement",
            )
        require(
            (folder / "example.y").read_bytes() == bytes(4),
            "unexpected whole-reply output",
        )
        with (folder / "example.proof").open("rb") as f:
            proof = f.read(limit + 1)
        require(0 < len(proof) <= limit, "proof outside configured size limit")
        start = time.monotonic_ns()
        require(
            check(statement, bytes(4), proof) == "verified",
            "native verification did not verify",
        )
        verify_ns = time.monotonic_ns() - start
        verified.append(
            {
                "id": ident,
                "prompt_tokens": len(prompt),
                "caller_budget": budget,
                "reply_tokens": len(reply),
                "proof_bytes": len(proof),
                "evidence_sha256": hashlib.sha256(
                    b"vig/m0/whole-reply/1"
                    + hashlib.sha256(statement).digest()
                    + hashlib.sha256(proof).digest()
                ).hexdigest(),
                "proof_ns": proof_ns,
                "verify_ns": verify_ns,
                **timing,
            }
        )
    return stream_support(capture, candidates[2]["expected"])


def float64_suite(path: Path, claimed_count: object) -> tuple[int, str]:
    xml = path.read_bytes()
    root = ElementTree.fromstring(xml)
    suites = list(root.iter("testsuite"))
    cases = list(root.iter("testcase"))
    names = sorted(case.get("name", "") for case in cases)
    digest = hashlib.sha256(("\n".join(names) + "\n").encode("ascii")).hexdigest()
    require(
        len(suites) == 1
        and suites[0].get("tests") == str(len(cases))
        and all(suites[0].get(key) == "0" for key in ("errors", "failures", "skipped"))
        and type(claimed_count) is int
        and len(cases) == claimed_count
        and digest == FLOAT64_NAMES_SHA256
        and all(
            case.get("classname", "").rsplit(".", 1)[-1] == "test_arithmetic_edges"
            and all(case.find(tag) is None for tag in ("skipped", "failure", "error"))
            for case in cases
        ),
        "serving GPU arithmetic evidence is incomplete",
    )
    return len(cases), hashlib.sha256(xml).hexdigest()


def engine_startup(capture: Path, eligible: object) -> dict[str, object]:
    record = document(capture / "startup-measurement.json")
    fields = (
        "after_popen_to_both_markers_and_health_ns",
        "supervisor_start_to_both_markers_and_health_ns",
    )
    matches = [field for field in fields if field in record]
    require(len(matches) == 1, "missing or ambiguous engine startup interval")
    field = matches[0]
    health_ns = positive_ns(record[field])
    eligible_ns = positive_ns(eligible)
    durations: dict[str, object] = {
        "engine_startup_to_eligible_ns": eligible_ns,
        "engine_startup_to_health_ns": health_ns,
        "engine_startup_to_health_interval": field.removesuffix("_ns"),
    }
    if field == "supervisor_start_to_both_markers_and_health_ns":
        require(health_ns <= eligible_ns, "eligibility preceded observed engine health")
        durations["engine_startup_to_eligible_interval"] = (
            "supervisor_start_to_eligible"
        )
    return durations


def engine_platform(observed: dict[str, Any]) -> dict[str, str]:
    require(
        observed["architecture"] == "x86_64"
        and observed["vllm"] == "0.29.0"
        and "H100" in observed["gpu_model"],
        "unexpected engine platform",
    )
    require(
        bool(re.fullmatch(r"[A-Za-z0-9 ._-]{1,64}", observed["gpu_model"]))
        and all(
            re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:\+cu[0-9]+)?", observed[k])
            for k in ("driver", "cuda", "torch")
        ),
        "invalid platform descriptor",
    )
    return {
        k: observed[k]
        for k in ("architecture", "gpu_model", "driver", "cuda", "torch", "vllm")
    }


def cross_platform(
    record: dict[str, Any], ready: dict[str, Any], ready_sha256: str
) -> dict[str, object]:
    require(
        type(record["schema_version"]) is int and record["schema_version"] == 1,
        "unknown cross-host record version",
    )
    if record["status"] == "unavailable":
        require(
            record["reason"]
            in (
                "insufficient_memory",
                "insufficient_storage",
                "no_second_h100",
                "unavailable_model_assets",
                "allocation_unavailable",
            )
            and bool(record["resource_evidence"]),
            "second host assessment missing",
        )
        return {"cross_host": record["reason"]}
    require(
        record["status"] in ("measured", "mismatch", "inconsistent_runs")
        and all(
            isinstance(record[k], str) and re.fullmatch(r"[a-f0-9]{64}", record[k])
            for k in ("primary_host", "secondary_host")
        )
        and record["primary_host"] != record["secondary_host"]
        and isinstance(record["canaries"], list)
        and len(record["canaries"]) == len(ready["canaries"]) == 3,
        "invalid cross-host observations",
    )

    def matches(expected: dict[str, Any], observed: dict[str, Any]) -> bool:
        tokens = observed["expected"]
        require(
            expected["prompt"] == observed["prompt"]
            and type(observed["max_tokens"]) is int
            and expected["max_tokens"] == observed["max_tokens"]
            and isinstance(tokens, list)
            and all(
                type(token) is int and 0 <= token < VOCABULARY_SIZE for token in tokens
            )
            and reply_complete(tokens, observed["max_tokens"]),
            "secondary canary differs from canonical request or is incomplete",
        )
        return bool(tokens == expected["expected"])

    gold = ready["canaries"]
    observed = record["canaries"]
    mismatches = [i for i in range(3) if not matches(gold[i], observed[i])]
    matched = 3 - len(mismatches)
    mismatch = record["status"] in ("mismatch", "inconsistent_runs")
    require(
        (matched < 3) == mismatch, "cross-host outcome contradicts observed replies"
    )
    comparison: dict[str, object] = {
        "matched": not mismatch,
        "startup_refused": mismatch,
        "canaries_compared": 3,
        "canaries_matching": matched,
    }
    label = {
        "measured": "matched_three_canaries",
        "mismatch": "canary_mismatch",
        "inconsistent_runs": "inconsistent_runs",
    }[record["status"]]
    result: dict[str, object] = {
        "cross_host": label,
        "cross_host_comparison": comparison,
    }
    if mismatch:
        attempts = record["startup_attempts"]
        require(
            isinstance(attempts, list) and 1 <= len(attempts) <= 3,
            "missing refused startup canary observations",
        )
        startup_mismatches = [
            i for i, row in enumerate(attempts) if not matches(gold[i], row)
        ]
        repeat_mismatches = [
            i for i, row in enumerate(attempts) if not matches(observed[i], row)
        ]
        prior = record["prior_attempt"]
        require(
            startup_mismatches == [len(attempts) - 1]
            and record["startup_mismatch_indices"] == startup_mismatches
            and prior["startup_refused"] is True
            and prior["gate_failure"] == "canary_token_mismatch"
            and bool(repeat_mismatches) == (record["status"] == "inconsistent_runs")
            and record["same_secondary_replay"] is (not repeat_mismatches)
            and record["secondary_repeat_mismatch_indices"] == repeat_mismatches,
            "normal startup refusals and secondary replay observations disagree with reported outcome",
        )
        comparison.update(
            primary_mismatch_indices=mismatches,
            startup_mismatch_indices=startup_mismatches,
            secondary_repeat_mismatch_indices=repeat_mismatches,
            same_secondary_replay=not repeat_mismatches,
            secondary_repeat_cases=len(attempts),
            startup_refusals=2,
        )

        require(
            record["commitment_id"] == ready["commitment_id"] == COMMITMENT
            and record["dtype"] == ready["dtype"]
            and record["primary_ready_sha256"] == ready_sha256
            and record["matched"] is False
            and record["startup_refused"] is True
            and record["secondary_eligible"] is False
            and all(
                type(index) is int
                for key in (
                    "compared_mismatch_indices",
                    "startup_mismatch_indices",
                    "secondary_repeat_mismatch_indices",
                )
                for index in record[key]
            )
            and record["compared_mismatch_indices"] == mismatches
            and record["gate_failure"] == "canary_token_mismatch"
            and record["same_process_f21"] is True
            and type(record["float64_cases_passed"]) is int
            and record["float64_cases_passed"] == ready["float64_cases_passed"]
            and "secondary_platform" in record,
            "secondary failure lacks its observed startup gate",
        )
    else:
        require(
            record.get("matched", True) is True
            and record.get("startup_refused", False) is False
            and record.get("secondary_eligible", True) is True,
            "secondary match contradicts its startup gate",
        )
    if "secondary_platform" in record:
        result["secondary_engine"] = engine_platform(record["secondary_platform"])
    return result


def environment(config: dict[str, Any], capture: Path) -> dict[str, object]:
    # Runtime imports keep the CPU mock gates usable without the real-model host components.
    launch = importlib.import_module("engine.launch")
    rebuild = document(Path(config["rebuild_report"]))
    require(
        rebuild["schema_version"] == 1
        and rebuild["passed"] is True
        and rebuild["published_commitment"] == COMMITMENT
        and all(rebuild["observed"].get(k) == v for k, v in launch.F4.items()),
        "published commitment rebuild did not match",
    )
    ready_bytes = Path(config["ready"]).read_bytes()
    ready = json.loads(ready_bytes)
    candidates = document(capture / "unproven-candidates.json")
    require(
        ready["schema_version"] == 1
        and ready["phase"] == "eligible"
        and ready["commitment_id"] == COMMITMENT
        and ready["dtype"] == candidates["dtype"]
        and ready["same_process_f21"] is True
        and len(ready["canaries"]) == 3
        and ready["canaries"] == candidates["canaries"][:3],
        "eligible startup or golden canaries missing",
    )
    count, junit_sha256 = float64_suite(
        Path(config["float64_junit"]), ready["float64_cases_passed"]
    )
    ready_sha256 = hashlib.sha256(ready_bytes).hexdigest()
    comparison = cross_platform(
        document(Path(config["cross_host"])), ready, ready_sha256
    )
    proving = document(Path(config["prover_startup"]))
    require(
        proving["measurement"] in ("launch_to_ready", "launch_to_first_request")
        and type(proving["batch_size"]) is int
        and proving["batch_size"] == 1,
        "missing prover startup interval",
    )
    return {
        "flashprove_revision": launch.REVISION,
        "engine": engine_platform(ready["platform"]),
        "dtype": ready["dtype"],
        **engine_startup(capture, ready["startup_ns"]),
        "prover_startup_ns": positive_ns(proving["startup_ns"]),
        "prover_startup_interval": proving["measurement"],
        "float64_cases": count,
        "float64_junit_sha256": junit_sha256,
        "serving_eligibility_scope": "primary_engine_only",
        "eligible_startup_sha256": ready_sha256,
        **comparison,
        "verifier_architecture": platform.machine(),
        "verifier_os": platform.system(),
        "verifier_python": platform.python_version(),
    }


def gate(config_path: Path | None, output: Path) -> bool:
    report: dict[str, object] = {
        "schema_version": 1,
        "gate": "M0",
        "status": "incomplete",
        "commitment_id": COMMITMENT,
        "proofs_verified": 0,
    }
    _write(output, report)
    measured: list[dict[str, object]] = []
    stage = "configuration"
    try:
        if config_path is None:
            raise EvidenceError("set VIG_M0_CONFIG to the private run configuration")
        config = document(config_path)
        require(
            type(config["schema_version"]) is int and config["schema_version"] == 1,
            "unknown configuration version",
        )
        report["source_revision"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        report["workload_sha256"] = hashlib.sha256(WORKLOAD.read_bytes()).hexdigest()
        stage = "platform and startup evidence"
        capture = Path(config["capture"])
        report["platform"] = environment(config, capture)
        stage = "independent verification"
        v = config["verifier"]
        checker = importlib.import_module("verifier.proof").NativeVerifier(
            *(
                Path(v[k]).absolute()
                for k in ("binary", "manifest", "config_dir", "public_key_dir")
            ),
            v["timeout_seconds"],
            v["memory_bytes"],
            v["max_proof_bytes"],
        )
        streaming = measure_cases(
            capture,
            Path(config["proofs"]),
            Path(config["assets"]),
            checker.max_proof_bytes,
            checker.check,
            measured,
        )
        report.update(
            status="passed",
            batch_size=1,
            streaming=streaming,
        )
    except EvidenceError as error:
        report.update(failed_stage=stage, reason=str(error))
    except (
        ElementTree.ParseError,
        AttributeError,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        ArithmeticError,
        OSError,
        ImportError,
        subprocess.SubprocessError,
    ) as error:
        # Private paths, captured model text, operator configuration and verifier stderr stay local.
        report.update(failed_stage=stage, reason=type(error).__name__)
    report.update(proofs_verified=len(measured), replies=measured)
    _write(output, report)
    return report["status"] == "passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=os.environ.get("VIG_M0_CONFIG"))
    parser.add_argument("--output", type=Path, default=Path("build/gate-m0.json"))
    args = parser.parse_args()
    return 0 if gate(args.config, args.output) else 1


if __name__ == "__main__":
    raise SystemExit(main())
