"""Buffered, mutually authenticated client for the pinned vLLM completion route."""

import json
import math
import socket
import ssl
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager, suppress
from http.client import HTTPException, HTTPSConnection
from pathlib import Path
from threading import Timer

from engine.adapter import EngineUnavailable


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate response field")
    return fields


class EngineClient:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        model: str,
        ca: Path,
        cert: Path,
        key: Path,
        margin_seconds: float,
        max_response_bytes: int,
    ) -> None:
        if not host or not model or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid engine endpoint")
        if (
            type(margin_seconds) not in (int, float)
            or not math.isfinite(margin_seconds)
            or margin_seconds <= 0
        ):
            raise ValueError("invalid engine request margin")
        if type(max_response_bytes) is not int or max_response_bytes <= 0:
            raise ValueError("invalid engine response limit")
        self._tls = ssl.create_default_context(cafile=str(ca))
        self._tls.load_cert_chain(cert, key)
        self._host, self._port, self._model = host, port, model
        self._margin, self._response_limit = margin_seconds, max_response_bytes

    @contextmanager
    def _connection(self, timeout: float) -> Iterator[HTTPSConnection]:
        deadline = time.monotonic() + timeout
        with closing(
            HTTPSConnection(self._host, self._port, timeout=timeout, context=self._tls)
        ) as client:
            client.connect()
            connection = client.sock
            if connection is None or time.monotonic() >= deadline:
                raise TimeoutError("engine connection deadline elapsed")

            def interrupt() -> None:
                with suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)

            timer = Timer(deadline - time.monotonic(), interrupt)
            timer.start()
            try:
                yield client
                if time.monotonic() >= deadline:
                    raise TimeoutError("engine request deadline elapsed")
            finally:
                timer.cancel()
                timer.join()

    def healthy(self, timeout: float) -> bool:
        try:
            with self._connection(timeout) as client:
                client.request("GET", "/health")
                with client.getresponse() as response:
                    return response.status == 200
        except (OSError, HTTPException):
            return False

    def generate(self, prompt: tuple[int, ...], max_tokens: int) -> tuple[int, ...]:
        body = json.dumps(
            {
                "model": self._model,
                "prompt": list(prompt),
                "temperature": 0,
                "max_tokens": max_tokens,
                "return_token_ids": True,
                "stream": False,
            }
        ).encode()
        # Per-request timeout policy in specs/parameters.md.
        timeout = max_tokens * 0.62 + self._margin
        try:
            with self._connection(timeout) as client:
                client.request(
                    "POST",
                    "/v1/completions",
                    body,
                    {"Content-Type": "application/json"},
                )
                with client.getresponse() as response:
                    if response.status != 200:
                        raise EngineUnavailable("engine completion unavailable")
                    data = response.read(self._response_limit + 1)
                if len(data) > self._response_limit:
                    raise ValueError("oversized response")
                result = json.loads(data.decode("utf-8"), object_pairs_hook=_unique)
                choices = result["choices"]
                if (
                    result.get("model") != self._model
                    or not isinstance(choices, list)
                    or len(choices) != 1
                    or not isinstance(choices[0], dict)
                ):
                    raise ValueError("unexpected completion")
                choice = choices[0]
                received = choice.get("prompt_token_ids")
                reply = choice.get("token_ids")
                if (
                    type(choice.get("index")) is not int
                    or choice["index"] != 0
                    or choice.get("finish_reason") not in ("length", "stop")
                    or not isinstance(received, list)
                    or not all(type(t) is int for t in received)
                    or tuple(received) != prompt
                    or not isinstance(reply, list)
                    or not 1 <= len(reply) <= max_tokens
                    or not all(type(t) is int and 0 <= t < 202048 for t in reply)
                ):
                    raise ValueError("missing or mismatched engine token IDs")
                return tuple(reply)
        except (
            OSError,
            HTTPException,
            KeyError,
            TypeError,
            ValueError,
            RecursionError,
        ):
            raise EngineUnavailable(
                "engine did not return an observable completion"
            ) from None
