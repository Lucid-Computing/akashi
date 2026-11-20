"""Persist run timing, bounded resource observations and every issued request."""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import subprocess
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from operations.private_db import private_database_file

DURATION = 72 * 3600
ROLES = ("engine", "prover", "gateway", "auditor")
WORKLOAD = {
    "empty_system": (50, 10),
    "long_single": (768, 256),
    "multi_turn": (200, 64),
    "system_user": (512, 128),
}
CASES = tuple(WORKLOAD)
GOOD = {"recovered", "conforms", "excused_range"}


def require(ok: object, text: str) -> None:
    if not ok:
        raise ValueError(text)


def jcs(data: object) -> str:
    return json.dumps(
        data, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def role_sample(roots: list[int], gpu: str | None) -> list[int]:
    """Sum Linux RSS/FDs across the role process tree and measure its reserved GPU."""
    require(
        isinstance(roots, list)
        and bool(roots)
        and all(type(pid) is int and pid > 0 for pid in roots),
        "Missing role root",
    )
    seen: set[int] = set()
    births: list[tuple[int, int]] = []
    rss = fds = 0

    def inspect(pid: int, *, required: bool) -> None:
        nonlocal rss, fds
        if pid in seen:
            return
        seen.add(pid)
        root = Path("/proc") / str(pid)
        try:
            birth = int((root / "stat").read_text().rsplit(")", 1)[1].split()[19])
            memory = int((root / "statm").read_text().split()[1]) * os.sysconf(
                "SC_PAGE_SIZE"
            )
            opened = len(list((root / "fd").iterdir()))
            children: set[int] = set()
            for task in (root / "task").iterdir():
                try:
                    children.update(
                        int(v) for v in (task / "children").read_text().split()
                    )
                except FileNotFoundError:
                    continue
            same = (
                int((root / "stat").read_text().rsplit(")", 1)[1].split()[19]) == birth
            )
        except FileNotFoundError:
            if required:
                raise
            return
        require(same, "Process changed during observation")
        if required:
            require(memory > 0 and opened > 0, "Role root is unavailable")
            births.append((pid, birth))
        rss += memory
        fds += opened
        for child in children:
            inspect(child, required=False)

    for pid in roots:
        inspect(pid, required=True)
    require(len(births) == len(roots), "Overlapping role roots")
    gpu_bytes = 0
    if gpu is not None:
        require(
            isinstance(gpu, str) and gpu.startswith("GPU-"),
            "Dedicated GPU identity required",
        )
        raw = subprocess.check_output(
            [
                "nvidia-smi",
                "--id=" + gpu,
                "--query-gpu=memory.used",
                "--format=csv,noheader,nounits",
            ],
            text=True,
        ).strip()
        require(raw.isdecimal(), "Cannot obtain reserved GPU memory usage")
        gpu_bytes = int(raw) * (1 << 20)
    identity = int.from_bytes(hashlib.sha256(jcs(births).encode()).digest(), "big")
    return [identity, rss, fds, gpu_bytes]


class Journal:
    def __init__(self, path: Path) -> None:
        self.path = path
        private_database_file(path)
        with closing(sqlite3.connect(path)) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS run (id INTEGER PRIMARY KEY CHECK(id=1), config TEXT NOT NULL, boot TEXT NOT NULL,
                        start_ns INTEGER NOT NULL, start_utc REAL NOT NULL, end_ns INTEGER, end_utc REAL);
                CREATE TABLE IF NOT EXISTS observations (ns INTEGER PRIMARY KEY, utc REAL NOT NULL, roles TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts (seq INTEGER PRIMARY KEY, shape TEXT NOT NULL, started_ns INTEGER NOT NULL,
                      ended_ns INTEGER, record TEXT);
            """)

    def begin(self, binding: dict[str, object]) -> None:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR IGNORE INTO run VALUES(1,?,?,?,?,NULL,NULL)",
                (jcs(binding), boot, time.monotonic_ns(), time.time()),
            )
            require(
                db.execute("SELECT config,boot FROM run").fetchone()
                == (jcs(binding), boot),
                "Run deployment or boot changed",
            )

    def observe(self, processes: dict[str, list[int]], gpus: dict[str, str]) -> None:
        require(
            set(processes) == set(ROLES)
            and set(gpus) == {"engine", "prover"}
            and len(set(gpus.values())) == 2,
            "Missing role or dedicated GPU",
        )
        all_roots = [pid for roots in processes.values() for pid in roots]
        require(len(set(all_roots)) == len(all_roots), "Role process is shared")
        values = {
            role: role_sample(roots, gpus.get(role))
            for role, roots in processes.items()
        }
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "INSERT INTO observations VALUES(?,?,?)",
                (time.monotonic_ns(), time.time(), jcs(values)),
            )

    def reserve(self) -> tuple[int, str]:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            require(
                db.execute("SELECT end_ns FROM run WHERE id=1").fetchone() == (None,),
                "Run is not active",
            )
            row = db.execute(
                "SELECT seq,shape,record FROM attempts ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if row and row[2] is None:
                return int(row[0]), str(row[1])
            seq = (row[0] + 1) if row else 0
            shape = CASES[seq % len(CASES)]
            db.execute(
                "INSERT INTO attempts VALUES(?,?,?,NULL,NULL)",
                (seq, shape, time.monotonic_ns()),
            )
            return seq, shape

    def record(self, seq: int, record: dict[str, Any]) -> None:
        encoded = jcs(record)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT record FROM attempts WHERE seq=?", (seq,)
            ).fetchone()
            require(
                row is not None and row[0] in (None, encoded),
                "Missing or conflicting attempt",
            )
            db.execute(
                "UPDATE attempts SET record=?,ended_ns=? WHERE seq=? AND record IS NULL",
                (encoded, time.monotonic_ns(), seq),
            )

    def in_flight(self) -> bool:
        with closing(sqlite3.connect(self.path)) as db:
            return (
                db.execute(
                    "SELECT 1 FROM attempts WHERE record IS NULL LIMIT 1"
                ).fetchone()
                is not None
            )

    def elapsed(self) -> float:
        with closing(sqlite3.connect(self.path)) as db:
            start, stop = db.execute("SELECT start_ns,end_ns FROM run").fetchone()
            return float((stop or time.monotonic_ns()) - start) / 1e9

    def finish(self) -> None:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            start, stamp, stop = db.execute(
                "SELECT start_ns,start_utc,end_ns FROM run"
            ).fetchone()
            ns, now = time.monotonic_ns(), time.time()
            if stop is not None:
                return
            require(
                (ns - start) / 1e9 >= DURATION and now - stamp >= DURATION,
                "Wall-clock run has not reached 72 hours",
            )
            require(
                not db.execute(
                    "SELECT 1 FROM attempts WHERE record IS NULL"
                ).fetchone(),
                "In-flight attempt remains",
            )
            db.execute("UPDATE run SET end_ns=?,end_utc=? WHERE id=1", (ns, now))


def measurements(
    db: sqlite3.Connection, *, gap_seconds: float, warmup_end_ns: int
) -> dict[str, object]:
    require(
        type(gap_seconds) in (int, float)
        and math.isfinite(gap_seconds)
        and gap_seconds > 0,
        "Invalid configured observation gap",
    )
    start, utc, stop, end = db.execute(
        "SELECT start_ns,start_utc,end_ns,end_utc FROM run"
    ).fetchone()
    require(
        type(stop) is int
        and (stop - start) / 1e9 >= DURATION
        and end - utc >= DURATION
        and end <= time.time(),
        "Incomplete elapsed soak",
    )
    require(start < warmup_end_ns < stop, "Incomplete warm workload")
    prior, wall = start, utc
    born: dict[str, int] = {}
    peaks = {role: [0, 0, 0] for role in ROLES}
    warm = {role: [0, 0, 0] for role in ROLES}
    last: dict[str, list[int]] = {}
    count = 0
    for ns, stamp, raw in db.execute(
        "SELECT ns,utc,roles FROM observations WHERE ns BETWEEN ? AND ? ORDER BY ns",
        (start, stop),
    ):
        require(
            0 <= ns - prior <= gap_seconds * 1e9 and 0 <= stamp - wall <= gap_seconds,
            "Missing continuous resource observation",
        )
        parsed = json.loads(raw)
        require(
            isinstance(parsed, dict) and parsed.keys() == set(ROLES),
            "Missing resource role",
        )
        for role in ROLES:
            row = parsed[role]
            require(
                isinstance(row, list)
                and len(row) == 4
                and all(type(i) is int and i > 0 for i in row[:3])
                and type(row[3]) is int
                and row[3] >= 0,
                "Invalid role observation",
            )
            birth, rss, fds, gpu = row
            require(
                born.setdefault(role, birth) == birth,
                "Role process restarted during soak",
            )
            last[role] = [rss, fds, gpu]
            for i, value in enumerate((rss, fds, gpu)):
                peaks[role][i] = max(peaks[role][i], value)
                if ns <= warmup_end_ns:
                    warm[role][i] = max(warm[role][i], value)
        count += 1
        prior, wall = ns, stamp
    require(
        count >= 2
        and (stop - prior) / 1e9 <= gap_seconds
        and end - wall <= gap_seconds
        and wall <= end,
        "Resource observations do not span the run",
    )
    resources = {}
    for role in ROLES:
        require(
            all(
                value <= limit
                for value, limit in zip(last[role], warm[role], strict=True)
            ),
            "Quiescent role retained growth beyond measured warm high-water",
        )
        resources[role] = {
            "warm_peak_rss_bytes": warm[role][0],
            "peak_rss_bytes": peaks[role][0],
            "final_rss_bytes": last[role][0],
            "warm_peak_fds": warm[role][1],
            "peak_fds": peaks[role][1],
            "final_fds": last[role][1],
            "warm_peak_gpu_bytes": warm[role][2],
            "peak_gpu_bytes": peaks[role][2],
            "final_gpu_bytes": last[role][2],
        }
    return {
        "elapsed_seconds": (stop - start) / 1e9,
        "start_utc": datetime.fromtimestamp(utc, timezone.utc).isoformat(),
        "end_utc": datetime.fromtimestamp(end, timezone.utc).isoformat(),
        "resource_observations": count,
        "resources": resources,
    }
