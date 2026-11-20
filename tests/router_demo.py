"""Loopback Mode R proof-of-concept with a separate router, toy engine and volatile pickup."""

from __future__ import annotations

import base64
import json
import os
import secrets
import selectors
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime
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
from prover.request import reply_complete
from tests.m1_flow import _Clock, _http, _lookup, _loopback, _public
from tests.test_discovery import CONFIG, MODEL
from tools.gate_m1 import FIXTURES, _assets

_CHAT = [{"role": "user", "content": "Count to two."}]
_BUDGET = 2
_BASE = "/receipts/v1/pickup/"


class DemoError(RuntimeError):
    """A bounded diagnostic for the local demo."""


def require(ok: bool) -> None:
    if not ok:
        raise DemoError("Local router check failed")


class _PickupFixture:
    """Test-only volatile sink with a GET-only ciphertext view."""

    def __init__(self) -> None:
        self.reserved: dict[str, tuple[str, datetime]] = {}
        self.envelopes: dict[str, dict[str, str]] = {}

    def reserve(self, pickup_id: str, leaf_hash: str, expires_at: datetime) -> None:
        require(
            self.reserved.setdefault(pickup_id, (leaf_hash, expires_at))
            == (leaf_hash, expires_at)
        )

    def publish(
        self,
        pickup_id: str,
        leaf_hash: str,
        envelope: dict[str, str],
        expires_at: datetime,
    ) -> None:
        require(self.reserved[pickup_id] == (leaf_hash, expires_at))
        self.envelopes.setdefault(pickup_id, dict(envelope))

    def __call__(
        self,
        env: Mapping[str, object],
        start: Callable[[str, list[tuple[str, str]]], object],
    ) -> list[bytes]:
        path = str(env.get("PATH_INFO", ""))
        found = (
            self.envelopes.get(path[len(_BASE) :]) if path.startswith(_BASE) else None
        )
        body: dict[str, str]
        if env.get("REQUEST_METHOD") != "GET":
            status, body = "405 Method Not Allowed", {}
        elif found is None:
            status, body = "404 Not Found", {}
        else:
            status, body = "200 OK", found
        data = json.dumps(body).encode()
        start(
            status,
            [("Content-Type", "application/json"), ("Content-Length", str(len(data)))],
        )
        return [data]


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
    pickup = _PickupFixture()
    with tempfile.TemporaryDirectory(prefix="vig-router-") as directory:
        root = Path(directory)
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
        )
        with (
            _loopback(app) as upstream,
            _loopback(LogApp(log, gateway_identity="router-demo")) as log_port,
            _loopback(pickup) as pickup_port,
        ):
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
                found, _, envelope = _http(pickup_port, _BASE + digest)
                if mode == "rewrite-messages":
                    require(found == 404)
                    continue
                require(
                    found == 200
                    and envelope.keys() == {"version", "nonce", "ciphertext"}
                )
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
                        _http(
                            pickup_port, _BASE + lookup_id(_CHAT, _BUDGET, text, wrong)
                        )[0]
                        == 404
                    )
                    try:
                        open_pickup(envelope, wrong, _CHAT, _BUDGET, text)
                    except PickupError:
                        pass
                    else:
                        raise DemoError("Wrong holder secret opened the envelope")
            require(log.head()["tree_size"] == 3 and len(pickup.envelopes) == 3)
    return {
        "schema_version": 1,
        "status": "passed",
        "mode": "R",
        "engine": "mock",
        "pickup_store": "in-memory fixture",
        "transparent_receipt_verified": True,
        "opaque_pickup_verified": True,
        "wrong_secret_refused": True,
        "rewritten_messages_unrecoverable": True,
        "nonneutral_sampling_rejected": True,
        "logged": 3,
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
