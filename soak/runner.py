"""Drive one continuous live trial using a separate opaque-router holder."""

from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import sqlite3
import subprocess
import sys
import threading
from contextlib import closing
from pathlib import Path
from typing import Any

from gateway.renderer import ChatRenderer
from soak.gateway_service import quicknet
from soak.ledger import CASES, DURATION, GOOD, WORKLOAD, Journal, require
from soak.settings import digest, primary_host_matches, private, response
from tools.gate_m1 import ROOT, _write

CORPUS = ROOT / "tests/fixtures/m4-chat.jsonl"


def workload(assets: Path) -> dict[str, dict[str, Any]]:
    renderer = ChatRenderer(assets)
    rows = [json.loads(line) for line in CORPUS.read_bytes().splitlines()]
    require([r["id"] for r in rows] == list(CASES), "Unexpected soak corpus")
    for row in rows:
        length, budget = WORKLOAD[row["id"]]
        require(
            len(renderer.render(row["messages"])) == row["prompt_length"] == length
            and row["max_tokens"] == budget,
            "Pinned soak inputs differ from renderer",
        )
    return {r["id"]: r for r in rows}


def _get(origin: str, route: str, config: dict[str, Any]) -> Any:
    code, data = response(
        origin, route, timeout=config["network_timeout"], cap=config["response_cap"]
    )
    require(code == 200, "Expected public evidence unavailable")
    return data


def archive(
    config: dict[str, Any], journal: Journal, corpus: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    head = _get(config["log_origin"], "/log/v1/sth", config)

    def beacon(route: str) -> dict[str, Any]:
        return quicknet(
            route, timeout=config["network_timeout"], cap=config["response_cap"]
        )

    cache = {}
    pages = {}
    with closing(sqlite3.connect(journal.path)) as db:
        shapes = {
            json.loads(raw)["leaf_index"]: shape
            for shape, raw in db.execute("SELECT shape,record FROM attempts")
            if json.loads(raw)["status"] in GOOD
        }
    size = head["tree_size"]
    require(len(shapes) == size, "Issued attempts do not match the full isolated log")
    leaves = []
    for index in range(size):
        leaf = _get(config["log_origin"], f"/log/v1/receipts/{index}", config)
        inclusion = _get(
            config["log_origin"], f"/log/v1/proof/{index}?size={size}", config
        )
        require(
            inclusion["leaf_index"] == index and inclusion["tree_size"] == size,
            "Unexpected inclusion checkpoint",
        )
        if index not in pages:
            page = _get(
                config["audit_origin"], f"/audit/v1/selections?cursor={index}", config
            )
            require(
                page["log_id"] == head["log_id"]
                and page["indexed_size"] == size
                and page["epochs"]
                == [{"first_leaf_index": 0, "sampling_mode": "soak", "divisor": 1}],
                "Incomplete or mixed sampling epoch",
            )
            for selection in page["selections"]:
                pages[selection["leaf_index"]] = selection
        selection = pages.pop(index)
        n = leaf["beacon_round"]
        if n not in cache:
            cache[n] = beacon(f"public/{n}")
        verdict = _get(
            config["audit_socket"], f"/internal/sampled/{leaf['leaf_hash']}", config
        )
        shape = corpus[shapes[index]]
        leaves.append(
            {
                "leaf": leaf,
                "audit_path": inclusion["audit_path"],
                "selection": selection,
                "beacon": cache[n],
                "sample_verdict": verdict,
                "prompt_length": shape["prompt_length"],
                "budget": shape["max_tokens"],
            }
        )
    return {"head": head, "chain": beacon("info"), "leaves": leaves}


def collect(config: dict[str, Any]) -> None:
    os.umask(0o077)
    state = Path(config["state"])
    journal = Journal(state / "journal.db")
    corpus = workload(Path(config["assets"]))
    period, gap = config["resource_poll_seconds"], config["max_observation_gap_seconds"]
    require(
        all(type(v) in (int, float) and math.isfinite(v) for v in (period, gap))
        and 0 < period < gap <= 300
        and 0 < config["poll_seconds"] < gap,
        "Unobserved escrow window possible",
    )
    for name in ("active_startup", "primary_startup", "descriptor", "holder_config"):
        require(Path(config[name]).is_file(), "Missing deployment input")
    holder_cmd = config.get(
        "holder_command", [sys.executable, "-m", "router.soak_holder"]
    )
    require(
        isinstance(holder_cmd, list)
        and bool(holder_cmd)
        and all(type(arg) is str and arg and "\0" not in arg for arg in holder_cmd),
        "Invalid holder command",
    )
    case_path = Path(config.get("holder_case_path", state / "holder-case.json"))
    require(case_path.is_absolute(), "Absolute private holder case path required")
    binding = {
        "fixture_sha256": digest(CORPUS),
        "primary_startup_sha256": digest(Path(config["primary_startup"])),
        "active_startup_sha256": digest(Path(config["active_startup"])),
        "descriptor_sha256": digest(Path(config["descriptor"])),
        "holder_config_sha256": digest(Path(config["holder_config"])),
        "max_observation_gap_seconds": gap,
        "processes": config["processes"],
        "gpus": config["gpus"],
        "holder_command": holder_cmd,
        "holder_case_path": str(case_path),
        "source_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
    }
    active = json.loads(Path(config["active_startup"]).read_bytes())
    primary = json.loads(Path(config["primary_startup"]).read_bytes())
    for key in (
        "phase",
        "commitment_id",
        "dtype",
        "same_process_f21",
        "float64_cases_passed",
        "platform",
        "canaries",
    ):
        require(
            active[key] == primary[key],
            "Current physical gateway did not reproduce the primary startup evidence",
        )
    require(
        active["phase"] == "eligible"
        and active["same_process_f21"] is True
        and len(active["canaries"]) == 3,
        "Unqualified soak engine",
    )
    require(
        primary_host_matches(Path(config["original_host_identity"])),
        "Soak host differs from qualified primary",
    )
    binding["same_physical_primary"] = True
    journal.begin(binding)
    stop = threading.Event()
    errors = []

    def sample() -> None:
        while not stop.is_set():
            try:
                journal.observe(config["processes"], config["gpus"])
            except (OSError, ValueError, sqlite3.Error) as exc:
                errors.append(type(exc).__name__)
                return
            stop.wait(period)

    thread = threading.Thread(target=sample)
    thread.start()
    try:
        while journal.elapsed() < DURATION or journal.in_flight():
            require(not errors, "Role resource monitoring stopped")
            seq, shape = journal.reserve()
            row = corpus[shape]
            _write(
                case_path,
                {
                    "case_id": f"soak-{seq}",
                    "messages": row["messages"],
                    "max_tokens": row["max_tokens"],
                    "challenge": seq < len(CASES),
                },
            )
            proc = subprocess.run(
                [
                    *holder_cmd,
                    "--config",
                    config["holder_config"],
                    "--case",
                    str(case_path),
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            reply = json.loads(proc.stdout)
            expected_exit = {
                "conforms": 0,
                "recovered": 0,
                "unwarranted": 0,
                "excused_range": 0,
                "deviates": 1,
                "failed": 1,
                "pending": 2,
                "uncertain": 3,
            }
            require(
                reply["schema_version"] == 1
                and expected_exit.get(reply["status"]) == proc.returncode,
                "Holder process and result disagree",
            )
            if reply["status"] == "pending":
                stop.wait(config["poll_seconds"])
                continue
            if reply["status"] in GOOD:
                try:
                    code, _ = response(
                        config["audit_socket"],
                        f"/internal/sampled/{reply['leaf_hash']}",
                        timeout=config["network_timeout"],
                        cap=config["response_cap"],
                    )
                except (OSError, http.client.HTTPException):
                    # Only repeat this read. The holder saved the delivery before this point.
                    stop.wait(config["poll_seconds"])
                    continue
                if code in (202, 404):
                    stop.wait(config["poll_seconds"])
                    continue
                require(code == 200, "Sample evidence is unavailable")
            journal.record(seq, reply)
            require(
                reply["status"] in GOOD | {"unwarranted"},
                "Unexplained or ambiguous traffic event",
            )
        require(not errors, "Role resource monitoring stopped")
        journal.observe(config["processes"], config["gpus"])
        journal.finish()
    finally:
        stop.set()
        thread.join()
    _write(state / "archive.json", archive(config, journal, corpus))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    collect(private(parser.parse_args().config))
