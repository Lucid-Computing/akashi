"""RFC-0003 terminal delivery after private custody and a verified RFC-0004 promise."""

from __future__ import annotations

import hmac
import json
import secrets
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, TypeVar, cast

import rfc8785

from auditor.beacon import round_for, round_is_open
from escrow.store import Binding
from gateway.discovery import ServiceConfig
from gateway.policy import InferenceRequest
from log.receipt import leaf_hash, params_digest, transcript_commitment, verify_promise
from pickup.crypto import lookup_id, seal
from pickup.store import PICKUP_LIFETIME


class CommitError(RuntimeError):
    """The gateway cannot return a warranted completion for this attempt."""


class PickupWriter(Protocol):
    """Durable, idempotent operations. The private binding tag and expiry must agree."""

    def reserve(
        self, pickup_id: str, binding_tag: str, expires_at: datetime, /
    ) -> None: ...

    def publish(
        self,
        pickup_id: str,
        binding_tag: str,
        envelope: dict[str, str],
        expires_at: datetime,
        /,
    ) -> None: ...


@dataclass(frozen=True, repr=False)
class DeliveryAttempt:
    """Internal retry state. It contains private material and must not enter telemetry."""

    request_id: str
    _binding: Binding
    _public: bytes
    _material: bytes
    _secret: bytes | None
    _pickup_id: str | None

    @property
    def served_at(self) -> str:
        return self._binding.served_at

    @property
    def beacon_round(self) -> int:
        return self._binding.beacon_round


def _utc() -> datetime:
    return datetime.now(timezone.utc)


_T = TypeVar("_T")


def _commit_step(operation: Callable[[], _T], reason: str) -> _T:
    try:
        return operation()
    except Exception:  # noqa: BLE001 -- private component errors can contain transcript material.
        raise CommitError(reason) from None


class DeliveryCommitter:
    def __init__(
        self,
        config: ServiceConfig,
        *,
        endpoint_id: str,
        sampling_mode: str,
        stage: Callable[[Binding, bytes], str],
        append: Callable[[Mapping[str, object]], Mapping[str, object]],
        pickup: PickupWriter | None = None,
        pickup_lifetime: timedelta = PICKUP_LIFETIME,
        clock: Callable[[], datetime] = _utc,
    ) -> None:
        if (
            not isinstance(endpoint_id, str)
            or not endpoint_id
            or sampling_mode not in ("live", "soak")
        ):
            raise ValueError("Invalid receipt endpoint or sampling mode")
        if not timedelta(0) < pickup_lifetime <= PICKUP_LIFETIME:
            raise ValueError("Invalid pickup lifetime")
        self._pickup_lifetime = pickup_lifetime
        self._config, self._endpoint, self._mode = config, endpoint_id, sampling_mode
        self._stage, self._append, self._pickup, self._clock = (
            stage,
            append,
            pickup,
            clock,
        )
        descriptor = config.descriptor()
        self._commitment = str(descriptor["commitment_id"])
        self._profiles = {
            p["profile"]: p["digest"]
            for p in cast("list[dict[str,str]]", descriptor["render_profiles"])
        }
        self._ends = frozenset(cast("list[int]", descriptor["end_tokens"]))

    @property
    def pickup_enabled(self) -> bool:
        return self._pickup is not None

    def prepare(
        self,
        request: InferenceRequest,
        reply: tuple[int, ...],
        *,
        original_chat: object | None = None,
        reply_text: str | None = None,
        holder_secret: bytes | None = None,
    ) -> DeliveryAttempt:
        """Freeze a validated execution, the original input, salt, identity and future round."""
        if request.model != self._config.model or request.mode not in ("raw", "chat"):
            raise CommitError("Request differs from serving configuration")
        if (
            type(request.max_tokens) is not int
            or not 1 <= request.max_tokens <= self._config.max_tokens_cap
            or not isinstance(reply, tuple)
            or not reply
            or any(type(token) is not int for token in reply)
            or len(reply) > request.max_tokens
            or not self._ends.isdisjoint(reply[:-1])
            or (len(reply) < request.max_tokens and reply[-1] not in self._ends)
        ):
            raise CommitError("Incomplete engine reply")
        if request.mode == "raw":
            if (
                original_chat is not None
                or reply_text is not None
                or holder_secret is not None
            ):
                raise CommitError("Invalid raw delivery material")
            profile = self._profiles["raw-ids/1"]
        else:
            if not isinstance(original_chat, list) or not isinstance(reply_text, str):
                raise CommitError("Invalid chat delivery material")
            profile = self._profiles["llama4-chat/1"]

        if holder_secret is not None and self._pickup is None:
            raise CommitError("Pickup is unavailable")
        salt = secrets.token_hex(32)
        commitment = _commit_step(
            lambda: transcript_commitment(
                self._commitment,
                profile,
                request.max_tokens,
                salt,
                request.prompt,
                reply,
            ),
            "Invalid transcript for receipt",
        )
        private: dict[str, Any] = {
            "max_tokens": request.max_tokens,
            "prompt_token_ids": list(request.prompt),
            "reply_token_ids": list(reply),
            "reply_text": reply_text,
            "salt": salt,
        }
        if request.mode == "chat":
            private["messages"] = original_chat
        material = _commit_step(
            lambda: rfc8785.dumps(private), "Invalid private delivery material"
        )
        # Derive lookup from the same frozen message bytes that go into escrow.
        pickup_id = None
        if holder_secret is not None and reply_text is not None:
            chat = json.loads(material)["messages"]
            pickup_id = _commit_step(
                lambda: lookup_id(chat, request.max_tokens, reply_text, holder_secret),
                "Invalid pickup material",
            )
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise CommitError("Invalid delivery clock")
        utc = now.astimezone(timezone.utc)
        utc = utc.replace(microsecond=(utc.microsecond // 1000) * 1000)
        served_at = utc.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        number = round_for(utc)
        request_id = str(uuid.uuid4())
        public: dict[str, Any] = {
            "log_id": self._config.log_id,
            "endpoint_id": self._endpoint,
            "request_id": request_id,
            "served_at": served_at,
            "commitment_id": self._commitment,
            "render_profile": profile,
            "params_digest": params_digest(request.max_tokens),
            "transcript_commitment": commitment,
            "beacon_round": number,
            "sampling_mode": self._mode,
            "log_key_id": self._config.log_key_id,
        }
        digest = leaf_hash(public)
        binding = Binding(digest, commitment, served_at, number, self._mode)
        return DeliveryAttempt(
            request_id,
            binding,
            rfc8785.dumps(public),
            material,
            holder_secret,
            pickup_id,
        )

    def check_release(self, attempt: DeliveryAttempt) -> None:
        now = self._clock()
        served = datetime.fromisoformat(attempt.served_at.replace("Z", "+00:00"))
        if (
            now.tzinfo is None
            or now.utcoffset() is None
            or now < served
            or round_is_open(attempt.beacon_round, now)
        ):
            raise CommitError("Delivery clock is outside the fixed pre-round interval")
        if attempt._pickup_id is not None and now >= served + self._pickup_lifetime:
            raise CommitError("Pickup expired before delivery")

    def commit(
        self, attempt: DeliveryAttempt, *, guard: Callable[[], None]
    ) -> dict[str, object]:
        """Retry with the same attempt. The caller guards its request deadline and cancellation."""

        def boundary() -> None:
            guard()
            self.check_release(attempt)

        boundary()
        public: dict[str, Any] = json.loads(attempt._public)
        private: dict[str, Any] = json.loads(attempt._material)
        if (
            public["log_id"] != self._config.log_id
            or public["log_key_id"] != self._config.log_key_id
            or public["endpoint_id"] != self._endpoint
            or public["sampling_mode"] != self._mode
        ):
            raise CommitError("Attempt differs from serving configuration")
        digest = attempt._binding.leaf_hash
        stage = _commit_step(
            lambda: self._stage(attempt._binding, attempt._material),
            "Private escrow commit failed",
        )
        if stage != "pending":
            raise CommitError("Private escrow is no longer pending")
        boundary()
        pickup = self._pickup
        pickup_id = attempt._pickup_id
        expires = (
            datetime.fromisoformat(attempt.served_at.replace("Z", "+00:00"))
            + self._pickup_lifetime
        )
        binding_tag = ""
        if pickup_id is not None:
            if pickup is None or attempt._secret is None:
                raise CommitError("Pickup is unavailable")
            # The pickup database must not carry a public-log index beside its opaque ID.
            binding_tag = hmac.digest(
                attempt._secret,
                b"akashi/pickup/reservation/1" + bytes.fromhex(digest),
                "sha256",
            ).hex()
            _commit_step(
                lambda: pickup.reserve(pickup_id, binding_tag, expires),
                "Pickup reservation failed",
            )
            boundary()

        expected = {**public, "leaf_hash": digest}
        # Keep local expected bytes separate from the writer's request and its mutable result.
        promised = _commit_step(
            lambda: dict(self._append(dict(expected))), "Log append failed"
        )
        boundary()
        if (
            promised.keys() != expected.keys() | {"leaf_index", "promise_sig"}
            or any(
                type(promised[k]) is not type(v) or promised[k] != v
                for k, v in expected.items()
            )
            or type(promised["leaf_index"]) is not int
            or not 0 <= promised["leaf_index"] < 1 << 64
        ):
            raise CommitError("Log promise differs from delivery")
        receipt = {
            **expected,
            "salt": private["salt"],
            "promise_sig": promised["promise_sig"],
        }
        _commit_step(
            lambda: verify_promise(
                receipt,
                log_id=self._config.log_id,
                log_key_id=self._config.log_key_id,
                public_key=bytes.fromhex(self._config.log_public_key),
            ),
            "Invalid log promise signature",
        )
        verification: dict[str, object] = {
            "version": "akashi/1",
            "receipt": receipt,
            "prompt_token_ids": private["prompt_token_ids"],
            "reply_token_ids": private["reply_token_ids"],
        }
        if pickup_id is not None and pickup is not None and attempt._secret is not None:
            verification["pickup_id"] = pickup_id
            actual, envelope = _commit_step(
                lambda: seal(
                    verification,
                    private["messages"],
                    private["max_tokens"],
                    private["reply_text"],
                    cast(bytes, attempt._secret),
                ),
                "Pickup sealing failed",
            )
            if actual != pickup_id:
                raise CommitError("Pickup identity changed")
            boundary()
            _commit_step(
                lambda: pickup.publish(pickup_id, binding_tag, envelope, expires),
                "Pickup publication failed",
            )
        boundary()
        return verification
