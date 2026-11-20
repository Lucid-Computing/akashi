"""Greedy-only inference request admission (RFC-0003 and specs/gateway-api.md)."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Literal, NoReturn

Mode = Literal["chat", "raw"]
Renderer = Callable[[object], tuple[int, ...]]
_NUMERIC_CONTROLS = {
    "temperature": 0,
    "top_p": 1,
    "frequency_penalty": 0,
    "presence_penalty": 0,
    "repetition_penalty": 1,
}
_COMMON = frozenset(
    (
        *_NUMERIC_CONTROLS,
        "model",
        "max_tokens",
        "max_completion_tokens",
        "top_k",
        "n",
        "seed",
        "stream",
        "stream_options",
        "user",
    )
)


class PolicyError(Exception):
    def __init__(
        self,
        status: int,
        message: str,
        code: str | None = None,
        param: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.param = param

    def as_dict(self) -> dict[str, dict[str, str]]:
        """Client-facing error fields. The HTTP adapter supplies any transport-specific code."""
        error = {"message": str(self)}
        if self.code is not None:
            error["code"] = self.code
        if self.param is not None:
            error["param"] = self.param
        return {"error": error}


def _unsupported(name: str) -> NoReturn:
    raise PolicyError(
        400, "Unsupported request parameter", "unsupported_parameter", name
    )


def _content(name: str | None = None) -> NoReturn:
    raise PolicyError(400, "Invalid request content", "unsupported_content", name)


@dataclass(frozen=True)
class InferenceRequest:
    model: str
    mode: Mode
    prompt: tuple[int, ...] = field(repr=False)
    max_tokens: int
    stream: bool
    include_usage: bool

    def engine_request(self) -> dict[str, object]:
        return {
            "model": self.model,
            "prompt": list(self.prompt),
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "return_token_ids": True,
            "stream": self.stream,
        }


class _LargeJsonInteger:
    """A syntactically valid JSON integer beyond the Python int conversion limit."""


def _integer(text: str) -> int | _LargeJsonInteger:
    try:
        return int(text)
    except ValueError:
        # Greedy requests ignore any integer seed, including a value this runtime cannot convert.
        return _LargeJsonInteger()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        _content()
    return obj


def validate(
    body: object,
    mode: Mode,
    *,
    model: str,
    render: Renderer | None = None,
    max_tokens_cap: int = 256,
) -> InferenceRequest:
    """Validate a decoded JSON value against the serving descriptor and renderer."""
    if mode not in ("chat", "raw") or not isinstance(model, str) or not model:
        raise ValueError("invalid inference endpoint configuration")
    if type(max_tokens_cap) is not int or max_tokens_cap < 1:
        raise ValueError("invalid configured token cap")
    if not isinstance(body, dict):
        _content()
    input_field = "messages" if mode == "chat" else "prompt"
    for name in body:
        if name != input_field and name not in _COMMON:
            if not isinstance(name, str):
                _content()
            _unsupported(name)
    if body.get("model") != model:
        _unsupported("model")
    for name, neutral in _NUMERIC_CONTROLS.items():
        value = body.get(name, neutral)
        if type(value) not in (int, float, Decimal) or value != neutral:
            _unsupported(name)
    for name, allowed in (("top_k", (0, -1)), ("n", (1,))):
        value = body.get(name, allowed[0])
        if type(value) is not int or value not in allowed:
            _unsupported(name)
    if "seed" in body and type(body["seed"]) not in (int, _LargeJsonInteger):
        _unsupported("seed")
    if "user" in body and not isinstance(body["user"], str):
        _unsupported("user")
    stream = body.get("stream", False)
    if type(stream) is not bool:
        _unsupported("stream")
    options = body.get("stream_options", {})
    if not isinstance(options, dict) or options.keys() - {"include_usage"}:
        _unsupported("stream_options")
    include_usage = options.get("include_usage", False)
    if type(include_usage) is not bool:
        _unsupported("stream_options.include_usage")
    budget = max_tokens_cap
    for name in ("max_tokens", "max_completion_tokens"):
        if name in body:
            value = body[name]
            if type(value) is not int or not 1 <= value <= max_tokens_cap:
                _unsupported(name)
            if (
                name == "max_completion_tokens"
                and "max_tokens" in body
                and value != budget
            ):
                _unsupported(name)
            budget = value
    value = body.get(input_field)
    if not isinstance(value, list) or not value:
        _content(input_field)
    if mode == "chat":
        if render is None:
            raise ValueError("chat endpoint requires a configured renderer")
        try:
            prompt = render(value)
        except (TypeError, ValueError):
            raise PolicyError(
                400, "Unsupported message content", "unsupported_content", input_field
            ) from None
        if (
            not isinstance(prompt, tuple)
            or not prompt
            or any(
                type(token) is not int or not 0 <= token < 202048 for token in prompt
            )
        ):
            raise RuntimeError("configured renderer returned invalid token IDs")
    else:
        if any(type(token) is not int or not 0 <= token < 202048 for token in value):
            _content(input_field)
        prompt = tuple(value)
    if len(prompt) + budget > 1024:
        raise PolicyError(
            400, "Request exceeds the model window", "context_too_long", input_field
        )
    return InferenceRequest(model, mode, prompt, budget, stream, include_usage)


def _invalid_constant(_: str) -> NoReturn:
    _content()


def read_body(
    body: bytes | Iterable[bytes],
    *,
    authorization: str | None,
    authenticate: Callable[[str], bool],
    body_limit: int = 256 * 1024,
) -> object:
    """Authenticate before reading and enforce the byte limit before parsing."""
    if type(body_limit) is not int or body_limit < 1:
        raise ValueError("invalid configured body limit")
    match = re.fullmatch(
        r"Bearer +([A-Za-z0-9._~+/-]+=*)", authorization or "", re.IGNORECASE | re.ASCII
    )
    if match is None or authenticate(match[1]) is not True:
        raise PolicyError(401, "Authentication required")
    data = bytearray()
    for chunk in (body,) if isinstance(body, bytes) else body:
        if not isinstance(chunk, bytes):
            _content()
        if len(data) + len(chunk) > body_limit:
            raise PolicyError(413, "Request body exceeds the configured limit")
        data.extend(chunk)
    try:
        decoded = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=Decimal,
            parse_int=_integer,
            parse_constant=_invalid_constant,
        )
    except (ValueError, ArithmeticError, RecursionError):
        raise PolicyError(400, "Invalid JSON body", "unsupported_content") from None
    return decoded


def admit(
    body: bytes | Iterable[bytes],
    mode: Mode,
    *,
    authorization: str | None,
    authenticate: Callable[[str], bool],
    model: str,
    render: Renderer | None = None,
    body_limit: int = 256 * 1024,
    max_tokens_cap: int = 256,
) -> InferenceRequest:
    """Authenticate before reading the body and enforce its byte limit before JSON parsing."""
    decoded = read_body(
        body,
        authorization=authorization,
        authenticate=authenticate,
        body_limit=body_limit,
    )
    return validate(
        decoded, mode, model=model, render=render, max_tokens_cap=max_tokens_cap
    )
