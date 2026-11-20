"""Loopback Mode R proof-of-concept with a separate router, toy engine and durable sealed pickup."""

from __future__ import annotations

import base64
import io
import json
import os
import secrets
import selectors
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from engine.mock import MockEngine
from escrow.store import EscrowStore
from gateway.commit_delivery import DeliveryCommitter
from gateway.discovery import ServiceConfig
from gateway.http import ServingApp
from gateway.renderer import CHAT_PROFILE_DIGEST, ChatRenderer
from gateway.serving import Serving
from gateway.stream_reader import terminal_evidence
from log.http import LogApp
from log.receipt import (
    checked_public_leaf,
    leaf_hash,
    params_digest,
    transcript_commitment,
    verify_promise,
)
from log.store import MerkleLog
from log.verification import verify_head, verify_inclusion
from pickup.crypto import PickupError, lookup_id
from pickup.crypto import open as open_pickup
from pickup.http import PerIPLimit, PickupApp, make_pickup_server
from pickup.store import PickupStore
from prover.request import reply_complete
from tests.m1_flow import _Clock, _http, _lookup, _loopback, _public
from tests.test_discovery import CONFIG, MODEL
from tests.test_mock_router import call, serve
from tools.gate_m1 import FIXTURES, _assets

_CHAT = [{"role": "user", "content": "Count to two."}]
_BUDGET = 2
_BASE = "/receipts/v1/pickup/"


class DemoError(RuntimeError):
    """A bounded diagnostic for the local demo."""


def require(ok: bool) -> None:
    if not ok:
        raise DemoError("Local router check failed")


def _pickup(port: int, digest: str) -> dict[str, str] | None:
    code, headers, raw = call(port, _BASE + digest, None)
    require(headers.get("cache-control") == "no-store")
    if code == 404:
        require(not raw)
        return None
    require(code == 200)
    envelope: dict[str, str] = json.loads(raw)
    require(envelope.keys() == {"version", "nonce", "ciphertext"})
    return envelope


def _stream(
    port: int, body: dict[str, Any], *, transparent: bool
) -> tuple[str, dict[str, Any] | None]:
    code, headers, data = call(
        port,
        "/v1/chat/completions",
        json.dumps({**body, "stream": True}).encode(),
        {"Content-Type": "application/json", "Authorization": "Bearer m1-toy"},
    )
    require(
        code == 200
        and headers.get("content-type", "").split(";")[0] == "text/event-stream"
    )
    require("x-vig-receipt" not in headers and str(body["user"]).encode() not in data)
    # Our buffered gateway emits a comment, one display delta and one finishing
    # event. Refuse recovery from a disconnected or unwarranted stream.
    wire = data.splitlines()
    require(any(line.startswith(b":") for line in wire))
    fields = [
        line.removeprefix(b"data: ") for line in wire if line.startswith(b"data: ")
    ]
    require(len(fields) == 3 and fields[-1] == b"[DONE]" and data.endswith(b"\n\n"))
    first, final = (json.loads(field) for field in fields[:2])
    require(
        "verification" not in first
        and first["choices"][0]["finish_reason"] is None
        and isinstance(final.get("choices"), list)
        and len(final["choices"]) == 1
        and final["choices"][0].get("finish_reason") in ("stop", "length")
    )
    text = first["choices"][0]["delta"]["content"]
    require(isinstance(text, str))
    if transparent:
        return text, terminal_evidence(io.BytesIO(data))
    require("verification" not in final)
    return text, None


@contextmanager
def _router(upstream_port: int, mode: str) -> Iterator[int]:
    child = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "router.mock",
            "--upstream",
            f"http://127.0.0.1:{upstream_port}",
            "--port",
            "0",
            "--mode",
            mode,
            "--timeout-seconds",
            "10",
        ],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        if child.stdout is None:
            raise DemoError("Router did not announce a port")
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            require(bool(ready.select(10)))
        port = json.loads(os.read(child.stdout.fileno(), 128))["port"]
        require(type(port) is int and 0 < port <= 65535)
        yield port
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
        child.wait()
        if child.stdout is not None:
            child.stdout.close()


def _verify(
    bundle: dict[str, Any],
    text: str,
    renderer: ChatRenderer,
    config: ServiceConfig,
    log_port: int,
) -> None:
    public = bytes.fromhex(config.log_public_key)
    receipt = bundle["receipt"]
    verify_promise(
        receipt, log_id=config.log_id, log_key_id=config.log_key_id, public_key=public
    )
    prompt, reply = bundle["prompt_token_ids"], bundle["reply_token_ids"]
    require(
        bundle["version"] == "vig/1"
        and prompt == list(renderer.render(_CHAT))
        and reply_complete(reply, _BUDGET)
        and renderer.decode(reply) == text
        and receipt["commitment_id"] == config.descriptor()["commitment_id"]
        and receipt["render_profile"] == CHAT_PROFILE_DIGEST
        and receipt["params_digest"] == params_digest(_BUDGET)
        and receipt["transcript_commitment"]
        == transcript_commitment(
            receipt["commitment_id"],
            CHAT_PROFILE_DIGEST,
            _BUDGET,
            receipt["salt"],
            prompt,
            reply,
        )
    )
    head = _public(log_port, "/log/v1/sth")
    verify_head(head, log_id=config.log_id, lookup_key=_lookup(public))
    size = head["tree_size"]
    for index in range(size):
        raw = _public(log_port, f"/log/v1/receipts/{index}")
        if raw["leaf_hash"] == receipt["leaf_hash"]:
            checked_public_leaf(raw, index=index, log_id=config.log_id)
            proof = _public(log_port, f"/log/v1/proof/{index}?size={size}")
            verify_inclusion(
                receipt["leaf_hash"],
                index,
                size,
                head["root_hash"],
                proof["audit_path"],
            )
            return
    raise DemoError("Signed receipt absent from log")


def run_demo(asset_dir: Path) -> dict[str, object]:
    """Exercise all four router behaviors and return a redacted report."""
    renderer = ChatRenderer(asset_dir)
    signer = Ed25519PrivateKey.generate()
    config = ServiceConfig(
        **{**CONFIG, "log_public_key": signer.public_key().public_bytes_raw().hex()}
    )
    clock = _Clock()
    with tempfile.TemporaryDirectory(prefix="vig-router-") as directory:
        root = Path(directory).resolve()
        pickup = PickupStore(root / "pickup.db", clock=clock)
        # Independent reader connection exercises the on-disk handoff.
        reader = PickupStore(root / "pickup.db", clock=clock)
        lookup_app = PickupApp(
            reader, limiter=PerIPLimit(requests=32, period_seconds=60, max_peers=2)
        )
        escrow = EscrowStore(
            root / "escrow.db",
            wrapping_key=secrets.token_bytes(32),
            auditor_public_key=bytes(PrivateKey.generate().public_key),
            clock=clock,
        )
        log = MerkleLog(
            root / "log.db",
            log_id=config.log_id,
            log_key_id=config.log_key_id,
            signing_key=signer,
            leaf_hash=leaf_hash,
            clock=clock,
        )
        commit = DeliveryCommitter(
            config,
            endpoint_id="router-demo",
            sampling_mode="live",
            stage=escrow.stage,
            append=log.append,
            pickup=pickup,
            clock=clock,
        )
        app = ServingApp(
            Serving(
                config, renderer, MockEngine(), commit, lambda token: token == "m1-toy"
            ),
            request_timeout=10,
            retry_after_seconds=1,
            stream_heartbeat_seconds=0.05,
        )
        with (
            _loopback(app) as upstream,
            _loopback(LogApp(log, gateway_identity="router-demo")) as log_port,
            serve(make_pickup_server(lookup_app, port=0)) as pickup_port,
        ):
            direct = {"model": MODEL, "messages": _CHAT, "max_tokens": _BUDGET}
            code, header, result = _http(upstream, "/v1/chat/completions", direct)
            require(code == 200 and header is not None)
            _verify(
                result["verification"],
                result["choices"][0]["message"]["content"],
                renderer,
                config,
                log_port,
            )
            for mode in (
                "transparent",
                "opaque",
                "rewrite-messages",
                "inject-sampling",
            ):
                secret = secrets.token_bytes(32)
                body = {
                    "model": MODEL,
                    "max_tokens": _BUDGET,
                    "messages": _CHAT,
                    "user": "vig-pickup/1:" + secret.hex(),
                }
                with _router(upstream, mode) as router:
                    status, header, result = _http(router, "/v1/chat/completions", body)
                    if mode in ("opaque", "transparent"):
                        stream_secret = secrets.token_bytes(32)
                        stream_body = {
                            **body,
                            "user": "vig-pickup/1:" + stream_secret.hex(),
                        }
                        displayed, evidence = _stream(
                            router, stream_body, transparent=mode == "transparent"
                        )
                        digest = lookup_id(_CHAT, _BUDGET, displayed, stream_secret)
                        sealed = _pickup(pickup_port, digest)
                        if sealed is None:
                            raise DemoError("Missing sealed stream receipt")
                        recovered = cast(
                            "dict[str, Any]",
                            open_pickup(
                                sealed, stream_secret, _CHAT, _BUDGET, displayed
                            ),
                        )
                        require(recovered["pickup_id"] == digest)
                        _verify(recovered, displayed, renderer, config, log_port)
                        if mode == "transparent":
                            require(evidence == recovered)
                require(secret.hex() not in json.dumps(result))
                if mode == "inject-sampling":
                    require(
                        status == 400
                        and result["error"]["code"] == "unsupported_parameter"
                        and header is None
                        and "verification" not in result
                    )
                    continue
                require(status == 200)
                text = result["choices"][0]["message"]["content"]
                digest = lookup_id(_CHAT, _BUDGET, text, secret)
                envelope = _pickup(pickup_port, digest)
                if mode == "rewrite-messages":
                    require(envelope is None)
                    continue
                if envelope is None:
                    raise DemoError("Missing sealed receipt")
                opened = cast(
                    "dict[str, Any]",
                    open_pickup(envelope, secret, _CHAT, _BUDGET, text),
                )
                require(opened["pickup_id"] == digest)
                _verify(opened, text, renderer, config, log_port)
                if mode == "transparent":
                    require(header is not None and result.get("verification") == opened)
                    if header is None:
                        raise DemoError("Missing direct receipt header")
                    decoded = json.loads(
                        base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
                    )
                    require(decoded == opened["receipt"])
                else:
                    require(
                        header is None
                        and "verification" not in result
                        and "pickup_id" not in result
                    )
                    wrong = bytes([secret[0] ^ 1]) + secret[1:]
                    require(
                        _pickup(pickup_port, lookup_id(_CHAT, _BUDGET, text, wrong))
                        is None
                    )
                    try:
                        open_pickup(envelope, wrong, _CHAT, _BUDGET, text)
                    except PickupError:
                        pass
                    else:
                        raise DemoError("Wrong holder secret opened the envelope")
            require(log.head()["tree_size"] == 6)
    return {
        "schema_version": 1,
        "status": "passed",
        "mode": "R",
        "engine": "mock",
        "pickup_store": "sqlite",
        "direct_receipt_verified": True,
        "transparent_stream_verified": True,
        "opaque_stream_pickup_verified": True,
        "transparent_receipt_verified": True,
        "opaque_pickup_verified": True,
        "wrong_secret_refused": True,
        "rewritten_messages_unrecoverable": True,
        "nonneutral_sampling_rejected": True,
        "logged": 6,
    }


def main() -> int:
    try:
        with tempfile.TemporaryDirectory(prefix="vig-router-assets-") as directory:
            manifest = json.loads(
                (FIXTURES / "render-goldens/manifest.json").read_bytes()
            )
            report = run_demo(_assets(Path(directory), manifest))
    except Exception:  # noqa: BLE001 -- internal route failures can contain private holder data.
        print(json.dumps({"schema_version": 1, "mode": "R", "status": "failed"}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
