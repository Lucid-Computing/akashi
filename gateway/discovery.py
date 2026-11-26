"""Public akashi/1 discovery routes and the configuration shared with admission."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Literal, Protocol, TypeVar
from urllib.parse import urlsplit

# Immutable renderer assets from parameters.md and the F37 source revision.
_ASSETS = (
    "https://huggingface.co/unsloth/Llama-4-Maverick-17B-128E-Instruct/resolve/"
    "86c5ecb6f2fbddf604c60120125fb202e09f2556/"
)
_TOKENIZER = "172c9eb4beafc72601690da3ccfcede5c2e6806a8d5ec1fca33e22acea8023a4"
_CONFIG = "2c56f1b600f928762c235c1b7a9349dc50c3574031f396a35ab25d3ad3ca425d"

Result_co = TypeVar("Result_co", covariant=True)
Mode = Literal["chat", "raw"]
Renderer = Callable[[object], tuple[int, ...]]


class Admission(Protocol[Result_co]):
    def __call__(
        self,
        body: bytes | Iterable[bytes],
        mode: Mode,
        *,
        authorization: str | None,
        authenticate: Callable[[str], bool],
        model: str,
        render: Renderer | None,
        max_tokens_cap: int,
    ) -> Result_co: ...


@dataclass(frozen=True, kw_only=True)
class ServiceConfig:
    model: str
    owned_by: str
    created: int
    log_id: str
    log_key_id: str
    log_public_key: str
    auditor_key_id: str
    auditor_public_key: str
    log_url: str
    pickup_url: str
    challenge_url: str
    audit_url: str
    max_tokens_cap: int = 256

    def __post_init__(self) -> None:
        for name in (self.model, self.owned_by, self.log_key_id, self.auditor_key_id):
            if not isinstance(name, str) or not name.strip() or not name.isprintable():
                raise ValueError(
                    "model, owner and key identifiers require printable text"
                )
        if type(self.created) is not int or self.created < 0:
            raise ValueError("expected an integer model creation timestamp")
        if type(self.max_tokens_cap) is not int or not 1 <= self.max_tokens_cap <= 256:
            raise ValueError("v1 token cap must be between 1 and 256")
        for octets in (self.log_id, self.log_public_key, self.auditor_public_key):
            if not isinstance(octets, str) or not re.fullmatch(r"[0-9a-f]{64}", octets):
                raise ValueError(
                    "expected a lowercase hex log identity or Ed25519 public key"
                )
        for url in (self.log_url, self.pickup_url, self.challenge_url, self.audit_url):
            if not isinstance(url, str) or any(c.isspace() or ord(c) < 32 for c in url):
                raise ValueError("invalid public service URL")
            try:
                parts = urlsplit(url)
                port = parts.port
            except ValueError:
                raise ValueError("invalid public service URL") from None
            if (
                parts.scheme != "https"
                or not parts.hostname
                or parts.username is not None
                or parts.query
                or parts.fragment
                or "\\" in url
                or port == 0
            ):
                raise ValueError(
                    "expected a public HTTPS service URL without credentials, query or fragment"
                )

    def admit(
        self,
        policy: Admission[Result_co],
        body: bytes | Iterable[bytes],
        mode: Mode,
        *,
        authorization: str | None,
        authenticate: Callable[[str], bool],
        render: Renderer | None = None,
    ) -> Result_co:
        """Apply gateway.policy.admit with the model and budget visible to clients."""
        return policy(
            body,
            mode,
            authorization=authorization,
            authenticate=authenticate,
            model=self.model,
            max_tokens_cap=self.max_tokens_cap,
            render=render,
        )

    def descriptor(self) -> dict[str, object]:
        chat = {
            "profile": "llama4-chat/1",
            "digest": hashlib.sha256(
                b"llama4-chat/1" + bytes.fromhex(_TOKENIZER + _CONFIG)
            ).hexdigest(),
            "tokenizer_json_url": _ASSETS + "tokenizer.json",
            "tokenizer_config_url": _ASSETS + "tokenizer_config.json",
            "tokenizer_json_sha256": _TOKENIZER,
            "tokenizer_config_sha256": _CONFIG,
        }
        raw = {
            "profile": "raw-ids/1",
            "digest": hashlib.sha256(b"raw-ids/1").hexdigest(),
        }
        return {
            "version": "akashi/1",
            "model": self.model,
            "commitment_id": "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46",
            "window": 1024,
            "max_tokens_cap": self.max_tokens_cap,
            "end_tokens": [200001, 200007, 200008],
            "sampling_rate": {"live": 20, "shadow": 1000},
            "render_profile": chat,
            "render_profiles": [chat, raw],
            "log": {
                "log_id": self.log_id,
                "log_key_id": self.log_key_id,
                "log_public_key": self.log_public_key,
                "url": self.log_url,
            },
            "beacon": {
                "chain": "quicknet",
                "chain_hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
                "url": "https://api.drand.sh",
            },
            "pickup_url": self.pickup_url,
            "challenge_url": self.challenge_url,
            "audit_url": self.audit_url,
            "auditor_key_id": self.auditor_key_id,
            "auditor_public_key": self.auditor_public_key,
        }


class DiscoveryApp:
    def __init__(self, config: ServiceConfig, *, streaming: bool = False) -> None:
        model = {
            "id": config.model,
            "object": "model",
            "owned_by": config.owned_by,
            "created": config.created,
            "window": 1024,
            "max_tokens_cap": config.max_tokens_cap,
        }
        feed = {
            "id": config.model,
            "quantization": "int4",
            "max_context_length": model["window"],
            "max_completion_tokens": config.max_tokens_cap,
            "max_length": config.max_tokens_cap,
            "supported_parameters": [
                "max_tokens",
                "temperature",
                *(["stream"] if streaming else []),
                "seed",
            ],
            "constraints": {"temperature": [0], "top_p": [1], "n": [1]},
            "description": "Greedy integer-model inference. See /.well-known/akashi.json for verification.",
        }
        self._routes = {
            "/router/models": json.dumps({"models": [feed]}).encode(),
            "/v1/models": json.dumps({"object": "list", "data": [model]}).encode(),
            "/.well-known/akashi.json": json.dumps(config.descriptor()).encode(),
        }

    def __call__(
        self,
        environ: Mapping[str, object],
        start_response: Callable[[str, list[tuple[str, str]]], object],
    ) -> list[bytes]:
        path = environ.get("PATH_INFO")
        if not isinstance(path, str) or path not in self._routes:
            start_response(
                "404 Not Found",
                [("Content-Type", "text/plain"), ("Content-Length", "0")],
            )
            return [b""]
        if environ.get("REQUEST_METHOD") != "GET":
            start_response(
                "405 Method Not Allowed",
                [
                    ("Allow", "GET"),
                    ("Content-Type", "text/plain"),
                    ("Content-Length", "0"),
                ],
            )
            return [b""]
        body = self._routes[path]
        start_response(
            "200 OK",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        )
        return [body]
