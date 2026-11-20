"""Bounded direct-mode delivery of buffered, receipted completions (RFC-0003)."""

import base64
import json
import math
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import CancelledError
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from engine.mock import EngineIntegrityError, EngineResult, EngineUnavailable
from gateway.commit_delivery import DeliveryCommitter
from gateway.discovery import ServiceConfig
from gateway.policy import Mode, PolicyError, read_body, validate
from pickup.crypto import PickupError, parse_holder_secret

END = frozenset({200001, 200007, 200008})  # F37


class Engine(Protocol):
    def generate(self, prompt: tuple[int, ...], max_tokens: int) -> EngineResult: ...


class Renderer(Protocol):
    def render(self, messages: object) -> tuple[int, ...]: ...
    def decode(self, token_ids: object) -> str: ...


class RequestControl:
    def __init__(self, queue: "AdmissionQueue", timeout: float) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("A finite positive request timeout is required")
        self.queue = queue
        self.deadline = time.monotonic() + timeout
        self.cancelled = False

    def cancel(self) -> None:
        with self.queue.changed:
            self.cancelled = True
            self.queue.changed.notify_all()

    def check(self) -> None:
        if self.cancelled or time.monotonic() >= self.deadline:
            raise CancelledError("Inference request ended before delivery")


class AdmissionQueue:
    """One active request and at most Q_max=4 waiting, including rendering and commit."""

    def __init__(self) -> None:
        self.changed = threading.Condition()
        self._active = False
        self._waiting: deque[object] = deque()

    @property
    def depth(self) -> int:
        with self.changed:
            return len(self._waiting)

    @contextmanager
    def slot(self, control: RequestControl) -> Iterator[None]:
        if control.queue is not self:
            raise ValueError("Control belongs to another gateway")
        with self.changed:
            control.check()
            if self._active or self._waiting:
                if len(self._waiting) >= 4:
                    raise PolicyError(429, "Inference queue is full", "queue_full")
                ticket = object()
                self._waiting.append(ticket)
                try:
                    while self._active or self._waiting[0] is not ticket:
                        control.check()
                        self.changed.wait(max(0, control.deadline - time.monotonic()))
                    control.check()
                finally:
                    self._waiting.remove(ticket)
                    self.changed.notify_all()
            self._active = True
        try:
            yield
        finally:
            with self.changed:
                self._active = False
                self.changed.notify_all()


@dataclass(frozen=True)
class Completion:
    body: dict[str, object] = field(repr=False)
    receipt_header: str = field(repr=False)
    check_release: Callable[[], None] = field(repr=False)


class Serving:
    def __init__(
        self,
        config: ServiceConfig,
        renderer: Renderer,
        engine: Engine,
        committer: DeliveryCommitter,
        authenticate: Callable[[str], bool],
    ) -> None:
        self.config, self.renderer, self.engine = config, renderer, engine
        self.committer, self.authenticate = committer, authenticate
        self.queue = AdmissionQueue()

    def complete(
        self,
        body: bytes | Iterable[bytes],
        mode: Mode,
        authorization: str | None,
        control: RequestControl,
    ) -> Completion:
        content = read_body(
            body, authorization=authorization, authenticate=self.authenticate
        )
        with self.queue.slot(control):
            req = validate(
                content,
                mode,
                model=self.config.model,
                render=self.renderer.render,
                max_tokens_cap=self.config.max_tokens_cap,
            )
            assert isinstance(content, dict)
            if req.stream:
                raise PolicyError(
                    400,
                    "Streaming is unavailable on this deployment",
                    "unsupported_parameter",
                    "stream",
                )
            try:
                secret = parse_holder_secret(content.get("user"))
            except PickupError:
                raise PolicyError(
                    400, "Invalid pickup option", "unsupported_parameter", "user"
                ) from None
            if secret is not None and (
                mode != "chat" or not self.committer.pickup_enabled
            ):
                raise PolicyError(
                    400,
                    "Pickup is unavailable for this request",
                    "unsupported_parameter",
                    "user",
                )
            control.check()
            try:
                result = self.engine.generate(req.prompt, req.max_tokens)
            except EngineUnavailable:
                raise PolicyError(
                    503, "Engine unavailable", "engine_unavailable"
                ) from None
            except EngineIntegrityError:
                raise PolicyError(
                    502, "Engine integrity check failed", "unwarranted_reply"
                ) from None
            control.check()
            if (
                not isinstance(result, EngineResult)
                or result.integrity_window_closed is not True
            ):
                raise PolicyError(
                    502, "Engine integrity window incomplete", "unwarranted_reply"
                )
            tokens = result.tokens
            if (
                not isinstance(tokens, tuple)
                or not 1 <= len(tokens) <= req.max_tokens
                or any(type(t) is not int or not 0 <= t < 202048 for t in tokens)
                or not END.isdisjoint(tokens[:-1])
                or (len(tokens) < req.max_tokens and tokens[-1] not in END)
            ):
                raise PolicyError(
                    502, "Incomplete or invalid engine reply", "unwarranted_reply"
                )
            display = self.renderer.decode(tokens) if mode == "chat" else None
            attempt = self.committer.prepare(
                req,
                tokens,
                original_chat=content.get("messages"),
                reply_text=display,
                holder_secret=secret,
            )
            verification = self.committer.commit(attempt, guard=control.check)

            def check_release() -> None:
                self.committer.check_release(attempt)
                control.check()

            check_release()
            choice: dict[str, object] = {
                "index": 0,
                "finish_reason": "stop" if tokens[-1] in END else "length",
            }
            if mode == "chat":
                choice["message"] = {"role": "assistant", "content": display}
            else:
                choice.update(text=None, token_ids=list(tokens))
            prefix = "chatcmpl" if mode == "chat" else "cmpl"
            response: dict[str, object] = {
                "id": f"{prefix}-{attempt.request_id}",
                "object": "chat.completion" if mode == "chat" else "text_completion",
                "created": int(
                    datetime.fromisoformat(
                        attempt.served_at.replace("Z", "+00:00")
                    ).timestamp()
                ),
                "model": req.model,
                "choices": [choice],
                "usage": {
                    "prompt_tokens": len(req.prompt),
                    "completion_tokens": len(tokens),
                    "total_tokens": len(req.prompt) + len(tokens),
                },
                "verification": verification,
            }
            header = (
                base64.urlsafe_b64encode(
                    json.dumps(
                        verification["receipt"], sort_keys=True, separators=(",", ":")
                    ).encode()
                )
                .rstrip(b"=")
                .decode("ascii")
            )
            return Completion(response, header, check_release)
