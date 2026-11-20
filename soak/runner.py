"""Drive one continuous live trial using a separate opaque-router holder."""

from __future__ import annotations

import argparse
import errno
import fcntl
import http.client
import json
import math
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

from auditor.beacon import verify_round
from gateway.renderer import ChatRenderer
from log.receipt import checked_public_leaf
from log.verification import verify_head, verify_inclusion
from soak.evidence import verified_record
from soak.gateway_service import quicknet
from soak.ledger import (
    CASES,
    DURATION,
    GOOD,
    WORKLOAD,
    Journal,
    NativeProcess,
    jcs,
    require,
)
from soak.settings import digest, primary_host_matches, private, public_keys, response
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


class ArchiveExpired(RuntimeError):
    """The operator-supplied archive budget elapsed after traffic stopped."""


def _get(origin: str, route: str, *, timeout: float, cap: int) -> Any:
    code, data = response(origin, route, timeout=timeout, cap=cap, decode_only_ok=True)
    if code in {408, 429, 500, 502, 503, 504} or code == 202:
        raise ConnectionError("Evidence temporarily unavailable")
    require(code == 200, "Permanent public evidence read failure")
    return data


def _retry(get: Callable[[float], Any], end: float, cfg: dict[str, Any]) -> Any:
    while True:
        left = end - time.monotonic()
        if left <= 0:
            raise ArchiveExpired("Archive drain deadline elapsed")
        try:
            return get(min(left, cfg["network_timeout"]))
        except (
            ConnectionError,
            TimeoutError,
            socket.gaierror,
            http.client.IncompleteRead,
        ):
            pass
        except OSError as exc:
            if exc.errno not in {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENOENT}:
                raise
        time.sleep(max(0, min(cfg["poll_seconds"], end - time.monotonic())))


@contextmanager
def _archive_timer(end: float) -> Iterator[None]:
    """Bound a slow response body, TLS handshake, or blocked DNS lookup in this CLI process."""
    left = end - time.monotonic()
    if left <= 0:
        raise ArchiveExpired("Archive drain deadline elapsed")

    def expire(_signal: int, _frame: object) -> NoReturn:
        raise ArchiveExpired("Archive drain deadline elapsed")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, left)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _export_archive(
    db: sqlite3.Connection, target: Path, head: dict[str, Any], chain: dict[str, Any]
) -> str:
    """Stream committed rows in leaf order and atomically expose the complete archive."""
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=target.parent, delete=False
    ) as data:
        path = Path(data.name)
        try:
            data.write(
                b'{"head":'
                + jcs(head).encode()
                + b',"chain":'
                + jcs(chain).encode()
                + b',"leaves":['
            )
            for n, (row,) in enumerate(
                db.execute("SELECT row_json FROM archive_leaves ORDER BY idx")
            ):
                if n:
                    data.write(b",")
                data.write(row.encode())
            data.write(b"]}\n")
            data.flush()
            os.fsync(data.fileno())
            checksum = digest(path)
            os.replace(path, target)
            return checksum
        finally:
            path.unlink(missing_ok=True)


def archive(config: dict[str, Any], journal: Journal) -> None:
    """Resume GET-only evidence collection from a finished, immutable traffic journal."""
    target = Path(config["state"]) / "archive.json"
    with (
        (target.parent / ".archive.lock").open("ab") as lock,
        closing(sqlite3.connect(journal.path)) as db,
    ):
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        config_raw, boot, finished = db.execute(
            "SELECT config,boot,end_ns FROM run WHERE id=1"
        ).fetchone()
        binding = json.loads(config_raw)
        require(
            type(finished) is int
            and boot == Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "Archive requires the original completed traffic interval",
        )
        require(
            config["archive_drain_seconds"] == binding["archive_drain_seconds"]
            and math.isfinite(config["archive_drain_seconds"])
            and config["archive_drain_seconds"] > 0
            and digest(Path(config["descriptor"])) == binding["descriptor_sha256"]
            and digest(CORPUS) == binding["fixture_sha256"],
            "Archive trust binding changed",
        )
        db.executescript("""
            CREATE TABLE IF NOT EXISTS archive_pin(id INTEGER PRIMARY KEY CHECK(id=1),head TEXT NOT NULL,chain TEXT,archive_sha256 TEXT);
            CREATE TABLE IF NOT EXISTS archive_leaves(idx INTEGER PRIMARY KEY,transcript TEXT NOT NULL UNIQUE,
                subject TEXT NOT NULL UNIQUE,row_json TEXT NOT NULL);
        """)
        pinned = db.execute(
            "SELECT head,chain,archive_sha256 FROM archive_pin WHERE id=1"
        ).fetchone()
        if pinned and pinned[2]:
            require(
                target.is_file() and digest(target) == pinned[2],
                "Completed archive digest mismatch",
            )
            return
        end = finished / 1e9 + config["archive_drain_seconds"]
        with _archive_timer(end):
            _archive_rows(db, target, pinned, config, end)


def _archive_rows(
    db: sqlite3.Connection,
    target: Path,
    pinned: tuple[str, str | None, str | None] | None,
    cfg: dict[str, Any],
    end: float,
) -> None:
    desc = private(Path(cfg["descriptor"]))
    keys = public_keys(desc)

    def lookup(role: str, key: str) -> bytes:
        return keys[role, key]

    def get(origin: str, route: str) -> Any:
        return _retry(
            lambda timeout: _get(
                origin, route, timeout=timeout, cap=cfg["response_cap"]
            ),
            end,
            cfg,
        )

    def drand(route: str) -> Any:
        return _retry(
            lambda timeout: quicknet(route, timeout=timeout, cap=cfg["response_cap"]),
            end,
            cfg,
        )

    def live_head() -> dict[str, object]:
        return verify_head(
            get(cfg["log_origin"], "/log/v1/sth"),
            log_id=desc["log"]["log_id"],
            lookup_key=lookup,
        )

    head = (
        live_head()
        if pinned is None
        else verify_head(
            json.loads(pinned[0]), log_id=desc["log"]["log_id"], lookup_key=lookup
        )
    )
    size = head["tree_size"]
    (count,) = db.execute(
        "SELECT count(*) FROM attempts WHERE json_extract(record,'$.status') IN (?,?,?)",
        tuple(sorted(GOOD)),
    ).fetchone()
    require(
        type(size) is int and size == count and count > 0,
        "Unexpected terminal tree size",
    )
    if pinned is None:
        with db:
            db.execute("INSERT INTO archive_pin(id,head) VALUES(1,?)", (jcs(head),))
    chain = drand("info") if not pinned or pinned[1] is None else json.loads(pinned[1])
    saved, last = db.execute("SELECT count(*),max(idx) FROM archive_leaves").fetchone()
    require(
        0 <= saved <= count and (0 if last is None else last + 1) == saved,
        "Archive progress is discontinuous",
    )
    pages = {}
    last_beacon: dict[str, Any] = {}
    rows = db.execute(
        "SELECT shape,record FROM attempts WHERE json_extract(record,'$.status') IN (?,?,?) ORDER BY seq",
        tuple(sorted(GOOD)),
    )
    for index, (shape, record) in enumerate(rows):
        holder = json.loads(record)
        require(holder["leaf_index"] == index, "Incorrect holder leaf order")
        if index < saved:
            continue
        leaf = get(cfg["log_origin"], f"/log/v1/receipts/{index}")
        inclusion = get(cfg["log_origin"], f"/log/v1/proof/{index}?size={size}")
        require(
            inclusion["leaf_index"] == index and inclusion["tree_size"] == size,
            "Unexpected inclusion checkpoint",
        )
        leaf = checked_public_leaf(leaf, index=index, log_id=desc["log"]["log_id"])
        require(
            leaf["leaf_hash"] == holder["leaf_hash"]
            and leaf["transcript_commitment"] == holder["transcript_commitment"],
            "Holder and archived leaf disagree",
        )
        verify_inclusion(
            str(leaf["leaf_hash"]),
            index,
            count,
            str(head["root_hash"]),
            inclusion["audit_path"],
        )
        if index not in pages:
            page = get(cfg["audit_origin"], f"/audit/v1/selections?cursor={index}")
            require(
                page["log_id"] == head["log_id"]
                and page["indexed_size"] == size
                and page["epochs"]
                == [{"first_leaf_index": 0, "sampling_mode": "soak", "divisor": 1}],
                "Incomplete or mixed sampling epoch",
            )
            entries = page["selections"]
            require(
                isinstance(entries, list)
                and entries
                and [r["leaf_index"] for r in entries]
                == list(range(index, index + len(entries))),
                "Unexpected selection page",
            )
            pages = {r["leaf_index"]: r for r in entries}
        number = leaf["beacon_round"]
        if type(number) is not int:
            raise ValueError("Invalid signed beacon round")
        if last_beacon.get("round") != number:
            last_beacon = drand(f"public/{number}")
            verify_round(number, chain, last_beacon)
        verdict = get(cfg["audit_socket"], f"/internal/sampled/{leaf['leaf_hash']}")
        prompt, budget = WORKLOAD[shape]
        row = {
            "leaf": leaf,
            "audit_path": inclusion["audit_path"],
            "selection": pages.pop(index),
            "beacon": last_beacon,
            "sample_verdict": verdict,
            "prompt_length": prompt,
            "budget": budget,
        }
        transcript, subject, _, _, _ = verified_record(
            index,
            shape,
            holder,
            row,
            head=head,
            chain=chain,
            lookup=lookup,
            now=datetime.now(timezone.utc),
        )
        with db:
            db.execute(
                "UPDATE archive_pin SET chain=? WHERE id=1 AND chain IS NULL",
                (jcs(chain),),
            )
            db.execute(
                "INSERT INTO archive_leaves VALUES(?,?,?,?)",
                (index, transcript, subject, jcs(row)),
            )
    latest = live_head()
    require(
        (latest["tree_size"], latest["root_hash"]) == (size, head["root_hash"]),
        "Terminal tree changed during archive",
    )
    checksum = _export_archive(db, target, head, chain)
    with db:
        db.execute("UPDATE archive_pin SET archive_sha256=? WHERE id=1", (checksum,))


def collect(config: dict[str, Any], *, archive_only: bool = False) -> None:
    os.umask(0o077)
    state = Path(config["state"])
    if archive_only:
        require((state / "journal.db").is_file(), "No recorded traffic journal")
    journal = Journal(state / "journal.db")
    with closing(sqlite3.connect(journal.path)) as db:
        run = db.execute("SELECT end_ns FROM run WHERE id=1").fetchone()
    if archive_only or (run and run[0] is not None):
        archive(config, journal)
        return
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
    native = NativeProcess(**config["native_prover"])
    native.check()
    require(config["processes"]["prover"] == [native.pid], "Unbound native prover role")
    binding = {
        "archive_drain_seconds": config["archive_drain_seconds"],
        "native_prover": config["native_prover"],
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

    def observe() -> None:
        journal.observe(config["processes"], config["gpus"], native=native)

    def sample() -> None:
        while not stop.wait(period):
            try:
                observe()
            except (OSError, ValueError, sqlite3.Error) as exc:
                errors.append(type(exc).__name__)
                return

    observe()
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
        observe()
        journal.finish()
    finally:
        stop.set()
        thread.join()
    archive(config, journal)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--archive-only", action="store_true")
    args = parser.parse_args()
    collect(private(args.config), archive_only=args.archive_only)
