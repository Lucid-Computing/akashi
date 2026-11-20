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
from dataclasses import dataclass
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


PROC = Path("/proc")


def _birth(root: Path) -> int:
    return int((root / "stat").read_text().rsplit(")", 1)[1].split()[19])


@dataclass(frozen=True)
class NativeProcess:
    pid: int
    start_ticks: int
    cgroup: str

    def __post_init__(self) -> None:
        require(
            type(self.pid) is int
            and self.pid > 1
            and type(self.start_ticks) is int
            and self.start_ticks > 0
            and isinstance(self.cgroup, str)
            and self.cgroup.strip(),
            "Invalid protected prover identity",
        )

    def check(self) -> None:
        proc = PROC / str(self.pid)
        require(
            _birth(proc) == self.start_ticks
            and (proc / "cgroup").read_text().strip() == self.cgroup,
            "Protected prover process changed",
        )


def _fd_slots(root: Path) -> int:
    rows = [
        r.split()
        for r in (root / "status").read_text().splitlines()
        if r.startswith("FDSize:")
    ]
    require(
        len(rows) == 1
        and len(rows[0]) == 2
        and rows[0][1].isascii()
        and rows[0][1].isdecimal()
        and int(rows[0][1]) > 0,
        "Protected prover FDSize unavailable",
    )
    return int(rows[0][1])


def _identity(births: list[tuple[int, int]]) -> int:
    return int.from_bytes(hashlib.sha256(jcs(births).encode()).digest(), "big")


def role_sample(
    roots: list[int], gpu: str | None, *, native: NativeProcess | None = None
) -> list[int | None]:
    """Sample exact open descriptors wherever observable and the protected native table separately."""
    require(
        isinstance(roots, list)
        and bool(roots)
        and all(type(pid) is int and pid > 0 for pid in roots),
        "Missing role root",
    )
    if native is not None:
        require(
            roots == [native.pid],
            "Expected the single authenticated native prover root",
        )
        native.check()
    seen: set[int] = set()
    births: list[tuple[int, int]] = []
    rss = fds = exact_processes = 0
    protected_slots: int | None = None

    def inspect(pid: int, *, required: bool) -> None:
        nonlocal rss, fds, exact_processes, protected_slots
        if pid in seen:
            return
        seen.add(pid)
        proc = PROC / str(pid)
        try:
            birth = _birth(proc)
            memory = int((proc / "statm").read_text().split()[1]) * os.sysconf(
                "SC_PAGE_SIZE"
            )
            opened: int | None
            try:
                opened = len(list((proc / "fd").iterdir()))
            except PermissionError:
                if native is None or pid != native.pid or birth != native.start_ticks:
                    raise
                protected_slots = _fd_slots(proc)
                opened = None
            children: set[int] = set()
            for task in (proc / "task").iterdir():
                try:
                    children.update(
                        int(v) for v in (task / "children").read_text().split()
                    )
                except FileNotFoundError:
                    if task.exists():
                        raise
            same = _birth(proc) == birth
        except FileNotFoundError:
            if required or proc.exists():
                raise
            return
        require(same, "Process changed during observation")
        if required:
            require(
                memory > 0 and (opened is None or opened > 0),
                "Role root is unavailable",
            )
            births.append((pid, birth))
        rss += memory
        if opened is not None:
            fds += opened
            exact_processes += 1
        for child in children:
            inspect(child, required=False)

    for pid in roots:
        inspect(pid, required=True)
    require(len(births) == len(roots), "Overlapping role roots")
    if native is not None:
        native.check()
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
    return [
        _identity(births),
        rss,
        fds if exact_processes else None,
        gpu_bytes,
        protected_slots,
        exact_processes,
    ]


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

    def observe(
        self,
        processes: dict[str, list[int]],
        gpus: dict[str, str],
        *,
        native: NativeProcess | None = None,
    ) -> None:
        require(
            set(processes) == set(ROLES)
            and set(gpus) == {"engine", "prover"}
            and len(set(gpus.values())) == 2,
            "Missing role or dedicated GPU",
        )
        all_roots = [pid for roots in processes.values() for pid in roots]
        require(len(set(all_roots)) == len(all_roots), "Role process is shared")
        values = {
            role: role_sample(
                roots, gpus.get(role), native=native if role == "prover" else None
            )
            for role, roots in processes.items()
        }
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT roles FROM observations ORDER BY ns DESC LIMIT 1"
            ).fetchone()
            if prior is not None:
                previous = json.loads(prior[0])
                for role, row in values.items():
                    old = previous[role]
                    require(
                        len(old) == len(row)
                        and old[0] == row[0]
                        and (old[4] is None) == (row[4] is None),
                        "Role identity or descriptor measurement basis changed",
                    )
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
    start, utc, stop, end, binding_json = db.execute(
        "SELECT start_ns,start_utc,end_ns,end_utc,config FROM run"
    ).fetchone()
    binding = json.loads(binding_json)
    native = (
        NativeProcess(**binding["native_prover"])
        if "native_prover" in binding
        else None
    )
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
    peaks: dict[str, list[int | None]] = {role: [None] * 4 for role in ROLES}
    warm: dict[str, list[int | None]] = {role: [None] * 4 for role in ROLES}
    last: dict[str, list[int | None]] = {}
    basis: dict[str, tuple[int, bool]] = {}
    process_counts: dict[str, list[int]] = {}
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
                isinstance(row, list) and len(row) in (4, 6), "Invalid role observation"
            )
            birth, rss, fds, gpu = row[:4]
            protected, visible = (None, None) if len(row) == 4 else row[4:]
            require(
                all(type(i) is int and i > 0 for i in (birth, rss))
                and type(gpu) is int
                and gpu >= 0,
                "Invalid role observation",
            )
            if len(row) == 6:
                if type(visible) is not int:
                    raise ValueError("Missing exact descriptor coverage")
                require(
                    visible >= 0
                    and (
                        (visible == 0 and fds is None)
                        or (visible > 0 and type(fds) is int and fds >= 0)
                    ),
                    "Missing exact descriptor coverage",
                )
                if protected is None:
                    require(visible > 0, "No process descriptor measurements")
                else:
                    require(
                        type(protected) is int
                        and protected > 0
                        and role == "prover"
                        and native is not None
                        and binding["processes"]["prover"] == [native.pid]
                        and birth == _identity([(native.pid, native.start_ticks)]),
                        "Unbound protected descriptor measurement",
                    )
                counts = process_counts.setdefault(role, [visible, visible, visible])
                counts[:] = [min(counts[0], visible), max(counts[1], visible), visible]
            else:
                require(
                    type(fds) is int and fds > 0,
                    "Invalid legacy descriptor measurement",
                )
            require(
                basis.setdefault(role, (len(row), protected is not None))
                == (len(row), protected is not None),
                "Descriptor measurement basis changed",
            )
            require(
                born.setdefault(role, birth) == birth,
                "Role process restarted during soak",
            )
            last[role] = [rss, fds, gpu, protected]
            for i, value in enumerate(last[role]):
                if value is not None:
                    peak = peaks[role][i]
                    peaks[role][i] = value if peak is None else max(peak, value)
                    if ns <= warmup_end_ns:
                        prior_peak = warm[role][i]
                        warm[role][i] = (
                            value if prior_peak is None else max(prior_peak, value)
                        )
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
                value is None or (limit is not None and value <= limit)
                for value, limit in zip(last[role], warm[role], strict=True)
            ),
            "Quiescent role retained growth beyond measured warm high-water",
        )
        partial = basis[role][1]
        metrics = ["rss_bytes", "exact_fds_visible" if partial else "fds", "gpu_bytes"]
        if partial:
            metrics.append("protected_fd_slots")
        report: dict[str, object] = {
            "fd_basis": "exact_visible_plus_native_fdsize"
            if partial
            else "exact_open_descriptors"
        }
        if role in process_counts:
            counts = process_counts[role]
            report.update(
                min_exact_fd_processes=counts[0],
                peak_exact_fd_processes=counts[1],
                final_exact_fd_processes=counts[2],
                protected_fd_processes=int(partial),
            )
        for i, name in enumerate(metrics):
            for prefix, series in (
                ("warm_peak", warm),
                ("peak", peaks),
                ("final", last),
            ):
                report[prefix + "_" + name] = series[role][i]
        resources[role] = report
    return {
        "elapsed_seconds": (stop - start) / 1e9,
        "start_utc": datetime.fromtimestamp(utc, timezone.utc).isoformat(),
        "end_utc": datetime.fromtimestamp(end, timezone.utc).isoformat(),
        "resource_observations": count,
        "resources": resources,
    }
