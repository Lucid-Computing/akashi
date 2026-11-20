"""Buffered HTTP inference and discovery for an authenticated gateway deployment."""

import json
import math
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import CancelledError
from http import HTTPStatus
from typing import BinaryIO, cast

from gateway.commit_delivery import CommitError
from gateway.discovery import DiscoveryApp
from gateway.policy import Mode, PolicyError
from gateway.serving import RequestControl, Serving

_INFERENCE: dict[str, Mode] = {"/v1/completions": "raw", "/v1/chat/completions": "chat"}


def _body(environ: Mapping[str, object]) -> Iterator[bytes]:
    length = environ.get("CONTENT_LENGTH")
    remaining: int | None
    if length in ("", None):
        remaining = None if environ.get("wsgi.input_terminated") is True else 0
    elif isinstance(length, str) and length.isascii() and length.isdigit():
        stripped = length.lstrip("0")
        if len(stripped) > 6 or int(stripped or "0") > 256 * 1024:
            raise PolicyError(413, "Request body exceeds the configured limit")
        remaining = int(stripped or "0")
    else:
        raise PolicyError(400, "Invalid request length", "unsupported_content")
    stream = cast(BinaryIO, environ["wsgi.input"])
    while remaining is None or remaining > 0:
        chunk = stream.read(8192 if remaining is None else min(8192, remaining))
        if not chunk:
            if remaining:
                raise PolicyError(400, "Incomplete request body", "unsupported_content")
            return
        yield chunk
        if remaining is not None:
            remaining -= len(chunk)


class ServingApp:
    """Mount behind TLS with one queue-owning coordinator per configured engine."""

    def __init__(
        self, serving: Serving, *, request_timeout: float, retry_after_seconds: int
    ) -> None:
        if not math.isfinite(request_timeout) or request_timeout <= 0:
            raise ValueError("invalid gateway request timeout")
        if type(retry_after_seconds) is not int or retry_after_seconds <= 0:
            raise ValueError("invalid Retry-After interval")
        self.serving = serving
        self.discovery = DiscoveryApp(serving.config)
        self.request_timeout, self.retry_after = request_timeout, retry_after_seconds

    def __call__(
        self,
        environ: Mapping[str, object],
        start_response: Callable[[str, list[tuple[str, str]]], object],
    ) -> list[bytes]:
        path = environ.get("PATH_INFO")
        if not isinstance(path, str) or path not in _INFERENCE:
            return self.discovery(environ, start_response)
        if environ.get("REQUEST_METHOD") != "POST":
            start_response(
                "405 Method Not Allowed", [("Allow", "POST"), ("Content-Length", "0")]
            )
            return [b""]
        control = environ.get("vig.request_control")
        if not isinstance(control, RequestControl):
            control = RequestControl(self.serving.queue, self.request_timeout)
        status = HTTPStatus.OK
        headers: list[tuple[str, str]] = []
        try:
            auth = environ.get("HTTP_AUTHORIZATION")
            completion = self.serving.complete(
                _body(environ),
                _INFERENCE[path],
                auth if isinstance(auth, str) else None,
                control,
            )
            payload = json.dumps(
                completion.body, ensure_ascii=False, separators=(",", ":")
            ).encode()
            completion.check_release()
            headers.append(("x-vig-receipt", completion.receipt_header))
        except PolicyError as exc:
            status = HTTPStatus(exc.status)
            error = exc.as_dict()
            error["error"].setdefault(
                "code",
                {401: "unauthorized", 413: "payload_too_large"}.get(
                    exc.status, "unsupported_content"
                ),
            )
            if exc.status == 429:
                headers.append(("Retry-After", str(self.retry_after)))
            payload = json.dumps(error).encode()
        except CancelledError:
            status = HTTPStatus.SERVICE_UNAVAILABLE
            payload = b'{"error":{"code":"request_cancelled","message":"Request ended before delivery"}}'
        except CommitError:
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            payload = b'{"error":{"code":"commit_failed","message":"Receipt could not be committed"}}'
        except Exception:  # noqa: BLE001 -- backend diagnostics and request content are private.
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            payload = b'{"error":{"code":"internal_error","message":"Completion unavailable"}}'
        start_response(
            f"{status.value} {status.phrase}",
            [
                *headers,
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(payload))),
            ],
        )
        return [payload]
