"""Start the soak gateway on an already-qualified physical engine."""

from __future__ import annotations

import argparse
import base64
import hmac
import http.client
import json
import os
import signal
import socketserver
import threading
from contextlib import ExitStack
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from wsgiref.simple_server import make_server

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auditor.beacon import CHAIN_HASH, round_for, round_is_open, select_round
from engine.control import ControlClient
from engine.service import attach_engine
from engine.transport import EngineClient
from escrow.sampler import ExpiryWorker, deliver_selected, resolve_logged_leaf
from escrow.store import EscrowStore, Transfer
from gateway.commit_delivery import DeliveryCommitter
from gateway.discovery import ServiceConfig
from gateway.http import ServingApp
from gateway.renderer import ChatRenderer
from gateway.serving import Serving
from log.http import LogApp, run_checkpoints
from log.monitor import LogMonitor
from log.receipt import leaf_hash
from log.store import MerkleLog
from pickup.http import (
    PerIPLimit,
    PickupApp,
    _QuietHandler,
    _QuietServer,
    make_pickup_server,
)
from pickup.store import PickupStore
from soak.ledger import require
from soak.settings import private, response
from tools.gate_m1 import _write


def quicknet(route: str, *, timeout: float, cap: int) -> dict[str, Any]:
    require(
        route == "info" or (route.startswith("public/") and route[7:].isdecimal()),
        "Unknown beacon observation",
    )
    conn = http.client.HTTPSConnection("api.drand.sh", timeout=timeout)
    try:
        conn.request("GET", f"/{CHAIN_HASH}/{route}")
        resp = conn.getresponse()
        if resp.status in {408, 429, 500, 502, 503, 504}:
            raise ConnectionError("Beacon temporarily unavailable")
        data = resp.read(cap + 1)
        require(resp.status == 200 and len(data) <= cap, "Beacon response unavailable")
        doc = json.loads(data)
        if not isinstance(doc, dict):
            raise TypeError("Invalid beacon response")
        return doc
    finally:
        conn.close()


class _EscrowStatus(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        from soak.evidence import HEX

        prefix = "/internal/escrow/status/"
        key = self.path.removeprefix(prefix)
        code = 404
        result = {}
        if self.path.startswith(prefix) and HEX.fullmatch(key):
            try:
                result = {"status": self.server.store.status(key)}  # type: ignore[attr-defined]
                code = 200
            except KeyError:
                pass
        body = json.dumps(result).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class StatusServer(socketserver.UnixStreamServer):
    def __init__(self, path: Path, store: EscrowStore) -> None:
        self.store = store
        require(
            path.parent.stat().st_mode & 0o077 == 0
            and path.parent.stat().st_uid == os.geteuid(),
            "Private escrow socket directory required",
        )
        super().__init__(str(path), _EscrowStatus)

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


def _custody(
    config: dict[str, Any],
    store: EscrowStore,
    history: LogMonitor,
    stop: threading.Event,
) -> None:
    net = {"timeout": config["network_timeout"], "cap": config["response_cap"]}

    def read(route: str) -> Any:
        code, doc = response(config["log_origin"], "/log/v1/" + route, **net)
        require(code == 200, "Log read failed")
        return doc

    def accept(transfer: Transfer) -> str:
        data = {
            "binding": asdict(transfer.binding),
            "ciphertext": base64.b64encode(transfer.ciphertext).decode(),
            "key_slot": base64.b64encode(transfer.key_slot).decode(),
        }
        code, doc = response(
            config["audit_socket"], "/internal/escrow/accept", data=data, **net
        )
        require(
            code == 200 and doc["leaf_hash"] == transfer.leaf_hash,
            "Auditor handoff unconfirmed",
        )
        return transfer.leaf_hash

    cursor = 0
    info = None
    while not stop.is_set():
        try:
            history.observe(read)
            head = history.checkpoint()
            if head is not None:
                while cursor < head["tree_size"]:
                    entry = history.verified_leaf(cursor)
                    key = str(entry["leaf_hash"])
                    state = store.status(key)
                    if state == "pending":
                        number = entry["beacon_round"]
                        if type(number) is not int:
                            raise ValueError("Invalid signed round")
                        if not round_is_open(number, datetime.now(timezone.utc)):
                            break
                        if info is None:
                            info = quicknet("info", **net)
                        beacon = quicknet(f"public/{number}", **net)
                        state = resolve_logged_leaf(
                            store,
                            cursor,
                            read_verified_leaf=history.verified_leaf,
                            chain_info=info,
                            beacon=beacon,
                            leaf_hash=leaf_hash,
                            round_for=round_for,
                            round_is_open=round_is_open,
                            select_round=select_round,
                        )
                    if state == "transferring":
                        deliver_selected(store, key, accept)
                    if store.status(key) == "pending":
                        break
                    cursor += 1
        except (OSError, TypeError, ValueError, KeyError, http.client.HTTPException):
            # The expiry worker independently enforces the original signed deadline.
            pass
        stop.wait(config["poll_seconds"])


def run(config: dict[str, Any]) -> None:
    os.umask(0o077)
    state = Path(config["state"])
    require(
        state.is_dir()
        and state.stat().st_mode & 0o077 == 0
        and state.stat().st_uid == os.geteuid(),
        "Private gateway state required",
    )
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    service = ServiceConfig(**config["service"])
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(config["log_signer"]))
    require(
        signer.public_key().public_bytes_raw().hex() == service.log_public_key,
        "Log signing identity differs",
    )
    log = MerkleLog(
        state / "log.db",
        log_id=service.log_id,
        log_key_id=service.log_key_id,
        signing_key=signer,
        leaf_hash=leaf_hash,
    )

    def lookup(role: str, key: str) -> bytes:
        require(role == "log" and key == service.log_key_id, "Unknown log signer")
        return bytes.fromhex(service.log_public_key)

    history = LogMonitor(state / "history.db", log_id=service.log_id, lookup_key=lookup)
    escrow = EscrowStore(
        state / "escrow.db",
        wrapping_key=bytes.fromhex(config["escrow_key"]),
        auditor_public_key=bytes.fromhex(config["auditor_recipient"]),
    )
    pickup = PickupStore(state / "pickup.db")
    model = config["provider"]
    client = EngineClient(
        model["host"],
        model["port"],
        model=model["model"],
        ca=Path(model["ca"]),
        cert=Path(model["cert"]),
        key=Path(model["key"]),
        margin_seconds=config["request_timeout"],
        max_response_bytes=config["response_cap"],
    )
    control = ControlClient(
        Path(model["control"]),
        provider_uid=model["uid"],
        timeout=config["network_timeout"],
    )
    engine = attach_engine(
        client,
        control,
        startup_timeout=config["startup_timeout"],
        health_poll_seconds=config["poll_seconds"],
    )
    require(
        engine.ready and engine.gates.host_passed and engine.gates.canaries_verified,
        "Eligible physical engine required",
    )
    commit = DeliveryCommitter(
        service,
        endpoint_id="soak",
        sampling_mode="soak",
        stage=escrow.stage,
        append=log.append,
        pickup=pickup,
    )
    serving = Serving(
        service,
        ChatRenderer(Path(config["assets"])),
        engine,
        commit,
        lambda value: hmac.compare_digest(value, config["inference_bearer"]),
    )
    app = ServingApp(
        serving,
        request_timeout=config["request_timeout"],
        retry_after_seconds=config["retry_after"],
    )
    expiry = ExpiryWorker(escrow)
    with ExitStack() as stack:
        servers = [
            make_server(
                "127.0.0.1",
                config["gateway_port"],
                app,
                server_class=_QuietServer,
                handler_class=_QuietHandler,
            ),
            make_server(
                "127.0.0.1",
                config["log_port"],
                LogApp(log, gateway_identity="soak"),
                server_class=_QuietServer,
                handler_class=_QuietHandler,
            ),
            make_pickup_server(
                PickupApp(pickup, limiter=PerIPLimit(**config["pickup_limit"])),
                port=config["pickup_port"],
            ),
            StatusServer(Path(config["escrow_status_socket"]), escrow),
        ]
        for server in servers:
            stack.callback(server.server_close)
            th = threading.Thread(target=server.serve_forever, daemon=True)
            th.start()
            stack.callback(server.shutdown)
        threads = [
            threading.Thread(target=run_checkpoints, args=(log, stop)),
            threading.Thread(target=expiry.run),
            threading.Thread(target=_custody, args=(config, escrow, history, stop)),
        ]
        for thread in threads:
            thread.start()
        try:
            _write(
                state / "service-ready.json",
                {
                    "pid": os.getpid(),
                    "physical_engine_eligible": True,
                    "sampling_mode": "soak",
                },
            )
            while not stop.wait(config["poll_seconds"]):
                pickup.sweep()
                require(
                    engine.ready and all(t.is_alive() for t in threads),
                    "Required serving role stopped",
                )
        finally:
            stop.set()
            expiry.stop()
            for thread in threads:
                thread.join()
            (state / "service-ready.json").unlink(missing_ok=True)


if __name__ == "__main__":
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--config", required=True, type=Path)
    run(private(args.parse_args().config))
