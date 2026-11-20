"""Persistent public selection records over authenticated log checkpoints and advertised epochs."""

import json
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs

from auditor.beacon import round_is_open, verify_round
from auditor.selection_record import evaluate
from log.monitor import LogMonitor

Beacon = Callable[[int], Mapping[str, object] | None]
Custody = Callable[[str], str | None]


class Selections:
    def __init__(
        self,
        path: Path,
        *,
        log_id: str,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if (
            len(log_id) != 64
            or bytes.fromhex(log_id).hex() != log_id
            or str(path) == ":memory:"
        ):
            raise ValueError("Expected persistent sampling history for a pinned log")
        self.path, self.log_id, self.clock = path, log_id, clock
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS identity(id INTEGER PRIMARY KEY CHECK(id=1),log_id TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS epochs(start INTEGER PRIMARY KEY,mode TEXT NOT NULL CHECK(mode IN ('live','soak')));
              CREATE TABLE IF NOT EXISTS records(idx INTEGER PRIMARY KEY,leaf TEXT NOT NULL UNIQUE,
                  status TEXT NOT NULL,signature TEXT,public TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS chain(id INTEGER PRIMARY KEY CHECK(id=1), info TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS progress(id INTEGER PRIMARY KEY CHECK(id=1), checkpoint TEXT NOT NULL, pending_cursor INTEGER NOT NULL);
            """)
            db.execute("INSERT OR IGNORE INTO identity VALUES(1,?)", (log_id,))
            if db.execute("SELECT log_id FROM identity").fetchone()[0] != log_id:
                raise ValueError("Selection history belongs to another log")

    def activate(self, first_index: int, mode: str) -> None:
        """Advertise a prospective mode. A processed index never changes epochs."""
        if (
            type(first_index) is not int
            or not 0 <= first_index < 1 << 63
            or mode not in ("live", "soak")
        ):
            raise ValueError("Invalid selection epoch")
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT mode FROM epochs WHERE start=?", (first_index,)
            ).fetchone()
            if existing and existing[0] == mode:
                return
            observed = db.execute("SELECT checkpoint FROM progress").fetchone()
            last = db.execute("SELECT MAX(start) FROM epochs").fetchone()[0]
            indexed = db.execute("SELECT MAX(idx) FROM records").fetchone()[0]
            if (
                existing
                or (last is None and first_index != 0)
                or (last is not None and first_index <= last)
                or (indexed is not None and first_index <= indexed)
                or (
                    observed is not None
                    and first_index < json.loads(observed[0])["tree_size"]
                )
            ):
                raise ValueError("Cannot insert or rewrite a historical sampling epoch")
            db.execute("INSERT INTO epochs VALUES(?,?)", (first_index, mode))

    def sync(
        self,
        history: LogMonitor,
        *,
        custody: Custody,
        chain_info: Mapping[str, object] | None,
        read_beacon: Beacon,
        limit: int,
    ) -> None:
        """Read at most limit new and limit unsettled rows. Signed mode must agree with the announced epoch."""
        if (
            type(limit) is not int
            or limit < 1
            or limit >= 1 << 63
            or self.log_id != history.log_id
        ):
            raise ValueError("Invalid selection source or batch size")
        head = history.checkpoint()
        if head is None:
            return
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            progress = db.execute(
                "SELECT checkpoint, pending_cursor FROM progress"
            ).fetchone()
            if progress:
                old = json.loads(progress[0])
                if (
                    head["tree_size"] < old["tree_size"]
                    or history.root_at(old["tree_size"]) != old["root_hash"]
                ):
                    raise ValueError(
                        "Selection source differs from the recorded signed history"
                    )
            first = db.execute("SELECT COALESCE(MAX(idx)+1,0) FROM records").fetchone()[
                0
            ]
            cursor = progress[1] if progress else 0
            pending = [
                i
                for (i,) in db.execute(
                    "SELECT idx FROM records WHERE status='pending' OR (status='gap' AND signature IS NULL) "
                    "ORDER BY idx<? ,idx LIMIT ?",
                    (cursor, limit),
                )
            ]
            chain_row = db.execute("SELECT info FROM chain").fetchone()
            info: Mapping[str, object] | None = (
                json.loads(chain_row[0]) if chain_row else chain_info
            )
            round_cache: dict[int, Mapping[str, object] | None] = {}
            for index in [
                *range(first, min(first + limit, head["tree_size"])),
                *pending,
            ]:
                leaf = history.verified_leaf(index)
                digest = str(leaf["leaf_hash"])
                epoch = db.execute(
                    "SELECT start,mode FROM epochs WHERE start<=? ORDER BY start DESC LIMIT 1",
                    (index,),
                ).fetchone()
                if epoch is None:
                    raise ValueError("Advertise the initial sampling epoch first")
                cached = db.execute(
                    "SELECT leaf,status,signature FROM records WHERE idx=?", (index,)
                ).fetchone()
                if cached and cached[0] != digest:
                    raise ValueError("Previously indexed leaf changed")
                now = self.clock()
                number = cast(int, leaf["beacon_round"])
                evidence: Mapping[str, object] | None = None
                if cached and cached[2]:
                    evidence = {"round": number, "signature": cached[2]}
                elif info is not None and round_is_open(number, now):
                    if number not in round_cache:
                        try:
                            supplied = read_beacon(number)
                            if supplied is not None:
                                verify_round(number, info, supplied)
                            round_cache[number] = supplied
                        except (OSError, ValueError, KeyError):
                            round_cache[number] = None
                    evidence = round_cache[number]
                try:
                    state = custody(digest)
                except (KeyError, OSError):
                    state = None
                if cached and cached[1] == "gap":
                    state = "gap"
                result = evaluate(
                    index,
                    leaf,
                    mode=epoch[1],
                    now=now,
                    chain_info=info,
                    beacon=evidence,
                    escrow_status=state,
                )
                if (
                    result["beacon_signature"] is not None
                    and not chain_row
                    and info is not None
                ):
                    public_info = {
                        k: info[k]
                        for k in (
                            "hash",
                            "public_key",
                            "groupHash",
                            "schemeID",
                            "genesis_time",
                            "period",
                        )
                    }
                    public_info["metadata"] = {"beaconID": "quicknet"}
                    db.execute(
                        "INSERT OR IGNORE INTO chain VALUES(1,?)",
                        (json.dumps(public_info),),
                    )
                    chain_row = (True,)
                result["epoch_start_index"] = epoch[0]
                db.execute(
                    "INSERT INTO records VALUES(?,?,?,?,?) ON CONFLICT(idx) DO UPDATE SET status=excluded.status,signature=excluded.signature,public=excluded.public",
                    (
                        index,
                        digest,
                        result["status"],
                        result["beacon_signature"],
                        json.dumps(result, allow_nan=False),
                    ),
                )
            db.execute(
                "INSERT OR REPLACE INTO progress VALUES(1,?,?)",
                (json.dumps(head), pending[-1] + 1 if pending else 0),
            )

    def page(self, cursor: int, limit: int) -> dict[str, Any]:
        if (
            type(cursor) is not int
            or not 0 <= cursor < 1 << 63
            or type(limit) is not int
            or not 0 < limit < (1 << 63) - 1
        ):
            raise ValueError("Invalid selection cursor or page size")
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("BEGIN")
            head = db.execute("SELECT checkpoint FROM progress").fetchone()
            indexed = db.execute(
                "SELECT COALESCE(MAX(idx)+1,0) FROM records"
            ).fetchone()[0]
            rows = db.execute(
                "SELECT idx,public FROM records WHERE idx>=? ORDER BY idx LIMIT ?",
                (cursor, limit + 1),
            ).fetchall()
            epochs = [
                {
                    "first_leaf_index": i,
                    "sampling_mode": m,
                    "divisor": 1 if m == "soak" else 20,
                }
                for i, m in db.execute("SELECT start,mode FROM epochs ORDER BY start")
            ]
        return {
            "schema_version": 1,
            "log_id": self.log_id,
            "checkpoint": json.loads(head[0]) if head else None,
            "indexed_size": indexed,
            "epochs": epochs,
            "selections": [json.loads(row[1]) for row in rows[:limit]],
            "next_cursor": rows[-1][0] if len(rows) > limit else None,
        }


class SelectionsApp:
    def __init__(self, records: Selections, *, page_size: int) -> None:
        if type(page_size) is not int or not 0 < page_size < (1 << 63) - 1:
            raise ValueError("Invalid selection page size")
        self.records, self.page_size = records, page_size

    def __call__(
        self,
        env: Mapping[str, object],
        start_response: Callable[[str, list[tuple[str, str]]], object],
    ) -> list[bytes]:
        headers = []
        if env.get("PATH_INFO") != "/audit/v1/selections":
            status, body = "404 Not Found", b""
        elif env.get("REQUEST_METHOD") != "GET":
            status, body = "405 Method Not Allowed", b""
            headers.append(("Allow", "GET"))
        else:
            try:
                params = parse_qs(
                    str(env.get("QUERY_STRING", "")),
                    keep_blank_values=True,
                    strict_parsing=True,
                )
                values = params.get("cursor", ["0"])
                raw = values[0]
                if (
                    params.keys() - {"cursor"}
                    or len(values) != 1
                    or not (raw.isascii() and raw.isdecimal() and len(raw) <= 19)
                ):
                    raise ValueError("Invalid cursor")
                body = json.dumps(
                    self.records.page(int(raw), self.page_size), separators=(",", ":")
                ).encode()
                status = "200 OK"
            except ValueError:
                status, body = "400 Bad Request", b'{"error":"invalid_cursor"}'
        start_response(
            status,
            [
                *headers,
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]
