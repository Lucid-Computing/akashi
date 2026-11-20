"""Isolated Mode D milestone fixture. All requests, salts, identities and proofs are toys."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread
from typing import Any, cast
from unittest.mock import Mock, patch
from wsgiref.simple_server import WSGIRequestHandler, make_server

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from auditor.beacon import round_for, round_is_open, select_round
from auditor.selections import Selections, SelectionsApp
from engine.mock import MockEngine
from escrow.mailbox import AuditorInbox
from escrow.sampler import deliver_selected, resolve_logged_leaf
from escrow.store import EscrowStore
from gateway.commit_delivery import DeliveryCommitter
from gateway.discovery import ServiceConfig
from gateway.http import ServingApp
from gateway.renderer import ChatRenderer
from gateway.serving import Serving
from log.http import LogApp
from log.monitor import LogMonitor
from log.receipt import (
    checked_public_leaf,
    leaf_hash,
    transcript_commitment,
    verify_promise,
)
from log.store import MerkleLog
from log.verification import verify_head, verify_inclusion
from prover.mock import MockProver
from prover.request import build_statement
from tests.test_beacon import GENESIS, INFO, LATER, LATER_SIG
from tests.test_discovery import CONFIG, MODEL

_ROUND = 1_000_000
_OPENS = GENESIS + timedelta(seconds=3 * (_ROUND - 1))
_SERVED = _OPENS - timedelta(seconds=15)
_CASES: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("live-raw", "live", {"prompt": [17, 4], "max_tokens": 2}),
    (
        "soak-chat",
        "soak",
        {
            "messages": [{"role": "user", "content": "Synthetic M1 fixture."}],
            "max_tokens": 3,
        },
    ),
    ("soak-outage", "soak", {"prompt": [13], "max_tokens": 1}),
)


class GateFlowError(RuntimeError):
    """A bounded, public-safe milestone failure."""


def _require(ok: bool) -> None:
    if not ok:
        raise GateFlowError("M1 fixture correlation failed")


class _Quiet(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


@contextmanager
def _loopback(app: object) -> Iterator[int]:
    with make_server("127.0.0.1", 0, cast(Any, app), handler_class=_Quiet) as server:
        thread = Thread(target=lambda: server.serve_forever(poll_interval=0.02))
        thread.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            thread.join()


def _http(
    port: int, route: str, body: dict[str, Any] | None = None
) -> tuple[int, str | None, dict[str, Any]]:
    with closing(HTTPConnection("127.0.0.1", port, timeout=5)) as client:
        if body is None:
            client.request("GET", route)
        else:
            client.request(
                "POST",
                route,
                json.dumps(body),
                {"Authorization": "Bearer m1-toy", "Content-Type": "application/json"},
            )
        with client.getresponse() as response:
            return (
                response.status,
                response.getheader("x-vig-receipt"),
                json.loads(response.read()),
            )


def _public(port: int, route: str) -> dict[str, Any]:
    status, _, response = _http(port, route)
    _require(status == 200)
    return response


def _lookup(public_key: bytes) -> Callable[[str, str], bytes]:
    def lookup(role: str, key_id: str) -> bytes:
        _require(role == "log" and key_id == CONFIG["log_key_id"])
        return public_key

    return lookup


def _public_client(log_port: int, audit_port: int, key: bytes) -> dict[str, int]:
    """Independent process receives two public HTTP ports and the pinned log verification key."""
    log_id = CONFIG["log_id"]
    head = _public(log_port, "/log/v1/sth")
    verify_head(head, log_id=log_id, lookup_key=_lookup(key))
    size = head["tree_size"]
    _require(size == len(_CASES))
    counts: Counter[str] = Counter()
    for index, (_, mode, _) in enumerate(_CASES):
        page = _public(audit_port, f"/audit/v1/selections?cursor={index}")
        _require(
            page["log_id"] == log_id
            and page["checkpoint"] == head
            and page["indexed_size"] == size
        )
        _require(page["next_cursor"] == (index + 1 if index + 1 < size else None))
        _require(len(page["selections"]) == 1)
        row = page["selections"][0]
        raw = _public(log_port, f"/log/v1/receipts/{index}")
        checked_public_leaf(raw, index=index, log_id=log_id)
        proof = _public(log_port, f"/log/v1/proof/{index}?size={size}")
        verify_inclusion(
            raw["leaf_hash"], index, size, head["root_hash"], proof["audit_path"]
        )
        for field in (
            "leaf_index",
            "leaf_hash",
            "transcript_commitment",
            "sampling_mode",
            "beacon_round",
        ):
            _require(raw[field] == row[field])
        epoch = max(
            (epoch for epoch in page["epochs"] if epoch["first_leaf_index"] <= index),
            key=lambda epoch: epoch["first_leaf_index"],
        )
        divisor = 20 if mode == "live" else 1
        _require(
            epoch["sampling_mode"] == mode == raw["sampling_mode"]
            and epoch["divisor"] == divisor == row["divisor"]
        )
        _require(epoch["first_leaf_index"] == row["epoch_start_index"])
        # Compute the original round and selection word directly from the public
        # contract. LATER_SIG was separately authenticated by drand-client.
        served = datetime.fromisoformat(raw["served_at"].replace("Z", "+00:00"))
        number = (served + timedelta(seconds=13) - GENESIS) // timedelta(seconds=3) + 2
        _require(
            number == raw["beacon_round"] == _ROUND
            and row["beacon_signature"] == LATER_SIG
        )
        word = hashlib.sha256(
            bytes.fromhex(raw["transcript_commitment"])
            + number.to_bytes(8, "big")
            + bytes.fromhex(LATER_SIG)
        ).digest()
        k = int.from_bytes(word[:4], "big")
        _require(
            row["selected"] is (k % divisor == 0)
            and row["shadow_selected"] is (k % 1000 == 0)
        )
        if index == 2:
            _require(row["status"] == "gap" and row["reason"] == "escrow_expired")
            counts["gaps"] += 1
        else:
            expected = "selected" if k % divisor == 0 else "unselected"
            _require(row["status"] == expected)
            counts[expected] += 1
        counts["recomputed"] += 1
    return dict(counts)


@dataclass
class _Clock:
    now: datetime = _SERVED

    def __call__(self) -> datetime:
        return self.now


def _serve_case(
    app: ServingApp,
    name: str,
    body: dict[str, Any],
    config: ServiceConfig,
    renderer: ChatRenderer,
    public: bytes,
) -> dict[str, Any]:
    chat = "messages" in body
    salt = hashlib.sha256(("vig/m1/toy/1/" + name).encode("ascii")).hexdigest()
    # Pin the synthetic fixture salt only in this test module's process.
    with (
        _loopback(app) as port,
        patch(
            "gateway.commit_delivery.secrets",
            Mock(token_hex=Mock(return_value=salt)),
        ),
    ):
        status, encoded, result = _http(
            port,
            "/v1/chat/completions" if chat else "/v1/completions",
            {"model": MODEL, **body},
        )
    if status != 200 or encoded is None:
        raise GateFlowError("Missing direct-mode receipt")
    bundle: dict[str, Any] = result["verification"]
    receipt = bundle["receipt"]
    _require(
        json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        == receipt
    )
    verify_promise(
        receipt,
        log_id=config.log_id,
        log_key_id=config.log_key_id,
        public_key=public,
    )
    prompt, reply = bundle["prompt_token_ids"], bundle["reply_token_ids"]
    expected_prompt = (
        list(renderer.render(body["messages"])) if chat else body["prompt"]
    )
    _require(
        prompt == expected_prompt
        and reply == [(sum(prompt) + j + 1) % 512 for j in range(body["max_tokens"])]
    )
    choice = result["choices"][0]
    _require(choice["finish_reason"] == "length")
    _require(
        (choice["message"]["content"] == renderer.decode(reply))
        if chat
        else (choice["token_ids"] == reply)
    )
    _require(
        receipt["transcript_commitment"]
        == transcript_commitment(
            receipt["commitment_id"],
            receipt["render_profile"],
            body["max_tokens"],
            receipt["salt"],
            prompt,
            reply,
        )
    )
    return bundle


def _prove_job(
    inbox: AuditorInbox, key: str, bundle: dict[str, Any], budget: int
) -> None:
    material = inbox.read(key)
    if material is None:
        raise GateFlowError("Missing selected mock job")
    private = json.loads(material)
    _require(
        private["prompt_token_ids"] == bundle["prompt_token_ids"]
        and private["reply_token_ids"] == bundle["reply_token_ids"]
        and private["salt"] == bundle["receipt"]["salt"]
        and private["max_tokens"] == budget
    )
    statement = build_statement(private["prompt_token_ids"], private["reply_token_ids"])
    holder_ids = bundle["prompt_token_ids"] + bundle["reply_token_ids"]
    expected = struct.pack(
        "<1026I",
        *holder_ids,
        *([0] * (1024 - len(holder_ids))),
        len(bundle["prompt_token_ids"]) - 1,
        len(holder_ids) - 1,
    )
    _require(statement == expected)
    evidence = MockProver().prove(statement)
    _require(
        evidence.kind == "mock"
        and evidence.statement_sha256 == hashlib.sha256(statement).hexdigest()
    )


def _flow(asset_dir: Path, root: Path) -> dict[str, object]:
    renderer = ChatRenderer(asset_dir)
    clock = _Clock()
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes_raw()
    config = ServiceConfig(**{**CONFIG, "log_public_key": public.hex()})
    recipient = PrivateKey.generate()
    escrow = EscrowStore(
        root / "escrow.db",
        wrapping_key=os.urandom(32),
        auditor_public_key=bytes(recipient.public_key),
        clock=clock,
    )
    inbox = AuditorInbox(
        root / "inbox.db", auditor_private_key=bytes(recipient), clock=clock
    )
    log = MerkleLog(
        root / "log.db",
        log_id=config.log_id,
        log_key_id=config.log_key_id,
        signing_key=signer,
        leaf_hash=leaf_hash,
        clock=clock,
    )
    monitor = LogMonitor(
        root / "monitor.db",
        log_id=config.log_id,
        lookup_key=_lookup(public),
        clock=clock,
    )
    selections = Selections(root / "selections.db", log_id=config.log_id, clock=clock)
    selections.activate(0, "live")
    selections.activate(1, "soak")

    def endpoint(mode: str, engine: MockEngine) -> ServingApp:
        commit = DeliveryCommitter(
            config,
            endpoint_id="m1-toy",
            sampling_mode=mode,
            stage=escrow.stage,
            append=log.append,
            clock=clock,
        )
        return ServingApp(
            Serving(config, renderer, engine, commit, lambda t: t == "m1-toy"),
            request_timeout=5,
            retry_after_seconds=1,
        )

    proofs = 0
    verified = 0
    transferred = 0
    failures = 0
    holder: list[dict[str, Any]] = []
    with _loopback(LogApp(log, gateway_identity="m1-toy")) as log_port:

        def read(route: str) -> dict[str, Any]:
            return _public(log_port, "/log/v1/" + route)

        monitor.observe(read)
        for index, (name, mode, body) in enumerate(_CASES):
            bundle = _serve_case(
                endpoint(mode, MockEngine()), name, body, config, renderer, public
            )
            receipt = bundle["receipt"]
            _require(
                receipt["beacon_round"] == _ROUND
                and escrow.status(receipt["leaf_hash"]) == "pending"
            )
            monitor.hold(receipt)
            monitor.observe(read)
            _require(
                monitor.verified_leaf(index)["leaf_hash"] == receipt["leaf_hash"]
                and not monitor.incidents()
            )
            holder.append(bundle)
            verified += 1
        for engine, expected in (
            (MockEngine("integrity_error"), 502),
            (MockEngine("unavailable"), 503),
        ):
            with _loopback(endpoint("soak", engine)) as port:
                status, encoded, result = _http(
                    port, "/v1/completions", {"model": MODEL, **_CASES[0][2]}
                )
            _require(
                status == expected
                and encoded is None
                and "verification" not in result
                and "choices" not in result
            )
            _require(log.head()["tree_size"] == len(holder))
            failures += 1

        clock.now = _OPENS
        for index, bundle in enumerate(holder):
            key = bundle["receipt"]["leaf_hash"]
            custody = resolve_logged_leaf(
                escrow,
                index,
                INFO,
                None if index == 2 else LATER,
                read_verified_leaf=monitor.verified_leaf,
                leaf_hash=leaf_hash,
                round_for=round_for,
                round_is_open=round_is_open,
                select_round=select_round,
            )
            if custody == "transferring":
                _require(deliver_selected(escrow, key, inbox.accept) == "selected")
                transferred += 1
                _prove_job(inbox, key, bundle, _CASES[index][2]["max_tokens"])
                proofs += 1
            else:
                _require(
                    custody == ("pending" if index == 2 else "unselected")
                    and inbox.read(key) is None
                )

        clock.now = _SERVED + timedelta(minutes=5)
        _require(escrow.sweep() == 1)
        selections.sync(
            monitor,
            custody=escrow.status,
            chain_info=INFO,
            read_beacon=lambda r: LATER if r == _ROUND else None,
            limit=len(holder),
        )
        with _loopback(SelectionsApp(selections, page_size=1)) as audit_port:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tests.m1_flow",
                    str(log_port),
                    str(audit_port),
                    public.hex(),
                ],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                timeout=30,
                check=False,
            )
            _require(completed.returncode == 0)
            counts = json.loads(completed.stdout)
            _require(
                counts
                == {
                    "selected": 1,
                    "unselected": 1,
                    "gaps": 1,
                    "recomputed": len(holder),
                }
            )
    fixture = {"version": "m1-toy/1", "cases": _CASES, "round": LATER, "chain": INFO}
    return {
        "mode": "D",
        "engine": "mock",
        "prover": "mock",
        "fixture_sha256": hashlib.sha256(
            json.dumps(fixture, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest(),
        "logged": len(holder),
        "promises_verified": verified,
        "handed_off": transferred,
        "mock_proofs": proofs,
        "failure_controls": failures,
        **counts,
    }


def run_flow(asset_dir: Path) -> dict[str, object]:
    """Return only allowlisted aggregate evidence; destroy all fixture databases on exit."""
    try:
        with tempfile.TemporaryDirectory(prefix="vig-m1-") as directory:
            return _flow(asset_dir, Path(directory))
    except Exception:  # noqa: BLE001 -- HTTP payloads and database errors stay private.
        raise GateFlowError("Isolated Mode D fixture failed") from None


if __name__ == "__main__":
    result = _public_client(
        int(sys.argv[1]), int(sys.argv[2]), bytes.fromhex(sys.argv[3])
    )
    print(json.dumps(result))
