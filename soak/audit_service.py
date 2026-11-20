"""Run the soak auditor's signed selection, private proof and holder services."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hmac
import importlib
import io
import ipaddress
import json
import math
import os
import re
import signal
import socket
import sqlite3
import stat
import struct
import sys
import threading
import time
from collections.abc import Mapping
from contextlib import closing
from datetime import timedelta
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import UnixStreamServer
from typing import Any, BinaryIO, TextIO, cast
from urllib.parse import urlsplit
from wsgiref.simple_server import WSGIRequestHandler, make_server

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from auditor.beacon import CHAIN_HASH
from auditor.challenge_http import ChallengeApp
from auditor.intake import ChallengeIntake
from auditor.selections import Selections, SelectionsApp
from escrow.mailbox import AuditorInbox
from escrow.store import Binding, Transfer
from gateway.renderer import ChatRenderer
from log.monitor import LogMonitor
from log.reader import LogReader
from prover.reference import ReferenceScorer, ReferenceTrace
from prover.request import build_statement
from prover.scoring import Assessment, assess
from prover.submission import SubmissionStore
from prover.worker import ProofWorker, Unavailable
from soak.settings import response
from verifier.proof import NativeVerifier

_DIGEST = re.compile(r"[a-f0-9]{64}")


def require(condition: object) -> None:
    if not condition:
        raise ValueError("Invalid soak auditor input")


def private_file(path: str | Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and not info.st_mode & 0o077
        )
        return f.read()


def private_dir(path: str | Path) -> Path:
    folder = Path(path)
    info = folder.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and not info.st_mode & 0o077
    )
    return folder


def read_body(stream: BinaryIO, count: int, limit: int) -> Any:
    require(0 < count <= limit)
    body = stream.read(count)
    require(len(body) == count)
    return json.loads(body)


def accept_carrier(inbox: AuditorInbox, doc: dict[str, Any]) -> str:
    require(
        isinstance(doc, dict) and doc.keys() == {"binding", "ciphertext", "key_slot"}
    )
    item = Transfer(
        Binding(**doc["binding"]),
        base64.b64decode(doc["ciphertext"], validate=True),
        base64.b64decode(doc["key_slot"], validate=True),
    )
    return inbox.accept(item)


def escrow_status(path: str, leaf: str, timeout: float, limit: int) -> str | None:
    require(_DIGEST.fullmatch(leaf))
    code, doc = response(
        "unix://" + path, "/internal/escrow/status/" + leaf, timeout=timeout, cap=limit
    )
    if code == 404:
        return None
    if code != 200:
        raise OSError("Custody unavailable")
    value = doc["status"]
    require(value in ("pending", "transferring", "selected", "unselected", "gap"))
    return cast(str, value)


class PublicReader:
    """Use the pinned HTTPS reader, or numeric loopback for the private single-host harness."""

    def __init__(self, url: str, timeout: float, limit: int):
        self.timeout, self.limit = timeout, limit
        self.url = urlsplit(url)
        self.tls = (
            LogReader(url, timeout=timeout, max_response_bytes=limit)
            if self.url.scheme == "https"
            else None
        )
        if self.tls is None:
            require(
                self.url.scheme == "http"
                and self.url.hostname is not None
                and self.url.hostname in ("127.0.0.1", "::1")
                and self.url.username is None
                and self.url.password is None
                and not self.url.query
                and not self.url.fragment
            )

    def __call__(self, route: str) -> Any:
        if self.tls:
            return self.tls(route)
        require(
            bool(route)
            and not route.startswith("/")
            and ".." not in route
            and "#" not in route
            and all(ord(c) > 32 for c in route)
        )
        code, doc = response(
            "http://" + self.url.netloc,
            self.url.path.rstrip("/") + "/" + route,
            timeout=self.timeout,
            cap=self.limit,
        )
        if code != 200:
            raise OSError("Public log unavailable")
        return doc


class LazyScorer:
    """Load the protected F4 CPU reference only for actual authenticated spool failures."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.model: ReferenceScorer | None = None
        self.last: tuple[tuple[int, ...], ReferenceTrace] | None = None

    def score(self, tokens: tuple[int, ...]) -> ReferenceTrace:
        if self.last is not None and self.last[0] == tokens:
            return self.last[1]
        if self.model is None:
            self.model = ReferenceScorer.load(
                Path(self.config["model"]),
                Path(self.config["manifest"]),
                rebuild_report=Path(self.config["rebuild_report"]),
            )
        result = self.model.score(tokens)
        self.last = (tokens, result)
        return result


class SpoolReceipts:
    """Retire a private spool copy only after its CH job's durable terminal outcome."""

    def __init__(self, jobs: Any, spool: Any):
        self.jobs, self.spool = jobs, spool
        if not callable(getattr(spool, "handoff", None)):
            raise TypeError("Spool retention implementation required")
        with jobs._tx() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS soak_spool_receipts(dispatch TEXT PRIMARY KEY, job TEXT NOT NULL)"
            )

    def remember(self, job: str, dispatch: str) -> None:
        with self.jobs._tx() as db:
            db.execute(
                "INSERT OR IGNORE INTO soak_spool_receipts VALUES(?,?)", (dispatch, job)
            )
            require(
                db.execute(
                    "SELECT job FROM soak_spool_receipts WHERE dispatch=?", (dispatch,)
                ).fetchone()[0]
                == job
            )

    def recover(self, limit: int) -> None:
        with self.jobs._tx() as db:
            ready = db.execute(
                """SELECT r.dispatch FROM soak_spool_receipts r JOIN audit_jobs a
                ON a.job_id=r.job WHERE a.state='completed' ORDER BY r.dispatch LIMIT ?""",
                (limit,),
            ).fetchall()
        for (dispatch,) in ready:
            self.spool.handoff(dispatch)
            with self.jobs._tx() as db:
                db.execute(
                    "DELETE FROM soak_spool_receipts WHERE dispatch=?", (dispatch,)
                )


def settle_one(
    jobs: Any,
    verdicts: Any,
    spool: SubmissionStore,
    worker: ProofWorker,
    scorer: LazyScorer,
    receipts: SpoolReceipts,
    *,
    lease: float,
    deadline: float,
    poll: float,
) -> bool:
    claim = jobs.claim(lease_time=timedelta(seconds=lease))
    if claim is None:
        return False
    try:
        if claim.incomplete:
            verdicts.settle(claim, None)
            return True
        original = build_statement(claim.prompt, claim.reply)
        active = jobs.dispatch(
            claim,
            Assessment("conformance", original),
            spool,
            deadline_ns=time.time_ns() + int(deadline * 1e9),
        )
        receipts.remember(claim.job_id, active.job_id)
        candidate = worker.wait(active.job_id, poll_seconds=poll)
        if isinstance(candidate, Unavailable) and candidate.reason == "spool_failure":
            diagnosis = assess(
                claim.prompt, claim.reply, claim.budget, scorer, failure=candidate
            )
            if (
                diagnosis.kind == "deviation"
                and diagnosis.statement is not None
                and time.time_ns() < active.deadline_ns
            ):
                # The original authenticated failure and its deadline never change.
                corrected = spool.submit(
                    active.job_id + "/corrected",
                    diagnosis.statement,
                    deadline_ns=active.deadline_ns,
                )
                receipts.remember(claim.job_id, corrected.job_id)
                candidate = worker.wait(corrected.job_id, poll_seconds=poll)
        verdicts.settle(claim, candidate)
        return True
    except TimeoutError as exc:
        # The retention-capable spool authenticates retirement from its persisted job.
        retired = getattr(
            importlib.import_module("prover.submission"), "RetiredSubmission", ()
        )
        if not isinstance(exc, retired) or getattr(exc, "reason", None) != "deadline":
            raise
        verdicts.settle(claim, Unavailable("deadline"))
        return True
    finally:
        scorer.last = None


def sampled_verdict(
    jobs: Any, verdicts: Any, leaf: str, selections: Selections | None = None
) -> tuple[int, dict[str, object]]:
    require(_DIGEST.fullmatch(leaf))
    if jobs.sample_status(leaf) is None:
        if selections is not None:
            with closing(sqlite3.connect(selections.path)) as db:
                known = db.execute(
                    "SELECT public FROM records WHERE leaf=?", (leaf,)
                ).fetchone()
            if known is not None and json.loads(known[0])["selected"] is not False:
                return 202, {}
        return 404, {}
    verdicts.stats()  # Publish any due sampled terminal outcomes in CH.
    with jobs._tx() as db:
        row = db.execute(
            """SELECT s.subject,a.t,v.document FROM sampled_verdict_ids s
               JOIN sampled_obligations o ON s.leaf=o.leaf JOIN audit_jobs a ON a.job_id=o.job_id
               JOIN signed_verdicts v ON v.challenge_id=s.subject WHERE s.leaf=?""",
            (leaf,),
        ).fetchone()
        if row is None:
            return 202, {}
        signed = cast(dict[str, object], verdicts._public(db, row[2]))
        require(
            signed["challenge_id"] == row[0]
            and signed["transcript_commitment"] == row[1]
        )
        return 200, signed


class QuietUnixServer(UnixStreamServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        print("Soak auditor private request failed", file=sys.stderr)


class QuietWSGI(WSGIRequestHandler):
    def get_stderr(self) -> TextIO:
        return io.StringIO()

    def log_message(self, format: str, *args: object) -> None:
        pass


def private_handler(
    inbox: AuditorInbox,
    jobs: Any,
    verdicts: Any,
    config: dict[str, Any],
    selections: Selections | None = None,
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(config["io_timeout_seconds"])

        def handle_one_request(self) -> None:
            option = getattr(socket, "SO_PEERCRED", None)
            if option is None:
                raise RuntimeError("Linux peer credential support is required")
            credentials = self.connection.getsockopt(
                socket.SOL_SOCKET, option, struct.calcsize("3i")
            )
            if struct.unpack("3i", credentials)[1] != config["custody_peer_uid"]:
                self.close_connection = True
                return
            super().handle_one_request()

        def log_message(self, format: str, *args: object) -> None:
            pass

        def respond(self, status: int, data: object) -> None:
            body = json.dumps(data, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_error(
            self, code: int, message: str | None = None, explain: str | None = None
        ) -> None:
            self.respond(code, {})

        def do_POST(self) -> None:
            if self.path != "/internal/escrow/accept":
                self.respond(404, {})
                return
            try:
                require(self.headers.get("Transfer-Encoding") is None)
                lengths = self.headers.get_all("Content-Length") or []
                require(len(lengths) == 1 and re.fullmatch(r"[0-9]+", lengths[0]))
                doc = read_body(
                    cast(BinaryIO, self.rfile),
                    int(lengths[0]),
                    config["carrier_limit_bytes"],
                )
                receipt = accept_carrier(inbox, doc)
            except (ValueError, KeyError, TypeError, OverflowError, RecursionError):
                self.respond(400, {})
                return
            self.respond(200, {"leaf_hash": receipt})

        def do_GET(self) -> None:
            match = re.fullmatch(r"/internal/sampled/([0-9a-f]{64})", self.path)
            if match is None:
                self.respond(404, {})
                return
            status, doc = sampled_verdict(jobs, verdicts, match[1], selections)
            self.respond(status, doc)

    return Handler


def assembly(c: dict[str, Any], mode: str) -> None:
    require(
        sys.platform == "linux"
        and type(c["schema_version"]) is int
        and c["schema_version"] == 1
    )
    state = private_dir(c["state"])
    for name in (
        "poll_seconds",
        "io_timeout_seconds",
        "lease_seconds",
        "proof_deadline_seconds",
    ):
        require(
            type(c[name]) in (int, float) and math.isfinite(c[name]) and c[name] > 0
        )
    for name in (
        "page_size",
        "read_limit_bytes",
        "challenge_limit_bytes",
        "carrier_limit_bytes",
    ):
        require(type(c[name]) is int and c[name] > 0)
    require(c["lease_seconds"] > c["proof_deadline_seconds"])
    descriptor = json.loads(private_file(c["descriptor"]))
    log_identity = descriptor["log"]
    public = bytes.fromhex(log_identity["log_public_key"])

    def lookup(role: str, kid: str) -> bytes:
        if role == "log" and kid == log_identity["log_key_id"]:
            return public
        raise KeyError("unknown log key")

    key = PrivateKey(private_file(c["recipient_key"]))
    hmac_key = private_file(c["holder_hmac_key"])
    assets = Path(c["assets"])
    intake = ChallengeIntake(
        state / "challenge.sqlite",
        descriptor=descriptor,
        assets=assets,
        auditor_public_key=bytes(key.public_key),
        holder_hmac_key=hmac_key,
    )
    jobs = importlib.import_module("auditor.jobs").AuditJobs(
        state / "challenge.sqlite",
        auditor_private_key=bytes(key),
        holder_hmac_key=hmac_key,
    )
    inbox = AuditorInbox(state / "inbox.sqlite", auditor_private_key=bytes(key))
    selections = Selections(state / "selections.sqlite", log_id=log_identity["log_id"])
    selections.activate(0, "soak")
    poll = c["poll_seconds"]
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    with (state / (mode + ".lock")).open("ab") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if mode == "index":
            history = LogMonitor(
                state / "monitor.sqlite",
                log_id=log_identity["log_id"],
                lookup_key=lookup,
            )
            observed = PublicReader(
                c["log_url"], c["io_timeout_seconds"], c["read_limit_bytes"]
            )
            beacon = descriptor["beacon"]
            require(
                beacon["url"] == "https://api.drand.sh"
                and beacon["chain_hash"] == CHAIN_HASH
            )
            drand = LogReader(
                beacon["url"] + "/" + CHAIN_HASH,
                timeout=c["io_timeout_seconds"],
                max_response_bytes=c["read_limit_bytes"],
            )

            def read_drand(route: str) -> Mapping[str, object]:
                result = drand(route)
                if not isinstance(result, dict):
                    raise TypeError("Invalid drand response")
                return result

            bridge = importlib.import_module("auditor.sampled_jobs").SampleBridge(
                selections, history, inbox, jobs, renderer=ChatRenderer(assets)
            )
            cursor = None
            while not stopped.is_set():
                try:
                    history.observe(observed)
                    if history.incidents():
                        raise RuntimeError("Log monitor recorded an incident")
                    try:
                        chain = read_drand("info")
                    except OSError:
                        chain = None
                    selections.sync(
                        history,
                        custody=lambda leaf: escrow_status(
                            c["escrow_socket"],
                            leaf,
                            c["io_timeout_seconds"],
                            c["read_limit_bytes"],
                        ),
                        chain_info=chain,
                        read_beacon=lambda number: read_drand(f"public/{number}"),
                        limit=c["page_size"],
                    )
                    cursor = bridge.poll(cursor, limit=c["page_size"])
                except (OSError, HTTPException):
                    pass
                stopped.wait(poll)
            return
        v = c["native_runtime"]
        checker = NativeVerifier(
            Path(v["binary"]),
            Path(v["manifest"]),
            Path(v["config_dir"]),
            Path(v["public_key_dir"]),
            v["timeout_seconds"],
            v["memory_bytes"],
            v["max_proof_bytes"],
        )
        signer = Ed25519PrivateKey.from_private_bytes(
            private_file(c["verdict_signing_key"])
        )
        require(
            signer.public_key().public_bytes_raw().hex()
            == descriptor["auditor_public_key"]
        )
        scorer = LazyScorer(c["reference"])
        verdicts = importlib.import_module("auditor.verdicts").VerdictStore(
            jobs,
            key_id=descriptor["auditor_key_id"],
            signer=signer,
            primary=checker,
            scorer=scorer,
        )
        if mode == "worker":
            spool = SubmissionStore(Path(c["submission_state"]), Path(c["spool"]))
            worker = ProofWorker(spool, max_proof_bytes=v["max_proof_bytes"])
            receipts = SpoolReceipts(jobs, spool)
            while not stopped.is_set():
                receipts.recover(c["page_size"])
                if not settle_one(
                    jobs,
                    verdicts,
                    spool,
                    worker,
                    scorer,
                    receipts,
                    lease=c["lease_seconds"],
                    deadline=c["proof_deadline_seconds"],
                    poll=poll,
                ):
                    stopped.wait(poll)
            return
        if mode == "custody":
            endpoint = Path(c["auditor_socket"])
            private_dir(endpoint.parent)
            if endpoint.exists():
                info = endpoint.lstat()
                require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid())
                endpoint.unlink()
            with QuietUnixServer(
                str(endpoint), private_handler(inbox, jobs, verdicts, c, selections)
            ) as listener:
                os.chmod(endpoint, 0o600)
                listener.timeout = poll
                try:
                    while not stopped.is_set():
                        listener.handle_request()
                finally:
                    endpoint.unlink(missing_ok=True)
            return
        require(mode == "http" and ipaddress.ip_address(c["http_host"]).is_loopback)
        token = private_file(c["holder_bearer_file"]).decode("ascii").rstrip("\n")
        require(bool(token))

        def authenticate(supplied: str) -> str | None:
            return "soak-holder" if hmac.compare_digest(supplied, token) else None

        challenge = ChallengeApp(
            intake.submit,
            authenticate=authenticate,
            body_limit=c["challenge_limit_bytes"],
        )
        api = importlib.import_module("auditor.verdict_http").VerdictApp(
            verdicts,
            intake=challenge,
            selections=SelectionsApp(selections, page_size=c["page_size"]),
        )
        with make_server(
            c["http_host"], c["http_port"], api, handler_class=QuietWSGI
        ) as server:
            server.timeout = poll
            while not stopped.is_set():
                server.handle_request()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--role", choices=("index", "worker", "custody", "http"), required=True
    )
    args = parser.parse_args()
    os.umask(0o077)
    try:
        assembly(json.loads(private_file(args.config)), args.role)
    except Exception as exc:  # noqa: BLE001 -- this CLI exposes only the bounded failure class.
        print("Soak auditor stopped:", type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
