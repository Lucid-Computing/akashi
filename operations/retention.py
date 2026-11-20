"""Run private retention under the account that owns each store (RFC-0009)."""

import argparse
import json
import math
import sqlite3
import sys
import time
from pathlib import Path

from auditor.retention import sweep as sweep_auditor
from operations.engine_logs import EngineLogs
from pickup.store import PickupStore
from prover.submission import SubmissionStore


def _sweep(args: argparse.Namespace) -> dict[str, int]:
    if args.role == "prover":
        if not (args.state / "submissions.sqlite3").is_file():
            raise ValueError("Expected an existing proof ledger")
        store = SubmissionStore(args.state, args.spool)
        return {"expired": store.sweep(), "pending_cleanup": store.pending_cleanup()}
    if not args.database.is_file():
        raise ValueError("Expected an existing service database")
    if args.role == "auditor":
        return {"expired": sweep_auditor(args.database)}
    if args.role == "engine":
        return {"expired": EngineLogs(args.database).purged_on_open}
    return {"expired": PickupStore(args.database).purged_on_open}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--interval-seconds", type=float, help="repeat under a service supervisor"
    )
    roles = parser.add_subparsers(required=True, dest="role")
    for role in ("auditor", "engine", "pickup"):
        roles.add_parser(role).add_argument("database", type=Path)
    prover = roles.add_parser("prover")
    prover.add_argument("state", type=Path)
    prover.add_argument("spool", type=Path)
    args = parser.parse_args()
    interval = args.interval_seconds
    if interval is not None and (not math.isfinite(interval) or interval <= 0):
        parser.error("the sweep interval must be positive and finite")
    try:
        while True:
            print(json.dumps({"role": args.role, **_sweep(args)}), flush=True)
            if interval is None:
                return 0
            time.sleep(interval)
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        print(
            "Private retention failed. Check the role's store and service configuration.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
