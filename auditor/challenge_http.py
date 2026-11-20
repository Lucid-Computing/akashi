"""Authenticated, bounded submission of a private holder challenge (RFC-0007)."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Mapping
from http import HTTPStatus
from typing import Any, BinaryIO, NoReturn, cast

from auditor.intake import IntakeError

_ROUTE = "/audit/v1/challenges"
_BEARER = re.compile(r"Bearer +([A-Za-z0-9._~+/-]+=*)", re.ASCII | re.IGNORECASE)
_CODES = {
    (401, "unauthorized"),
    (400, "invalid_bundle"),
    (400, "expired"),
    (413, "payload_too_large"),
    (429, "rate_limited"),
    (503, "verifier_unavailable"),
}


def _unique(fields: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(fields)
    if len(result) != len(fields):
        raise ValueError("Duplicate field")
    return result


def _invalid(_: str) -> NoReturn:
    raise ValueError("Invalid numeric value")


def _float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("Invalid numeric value")
    return value


def _body(env: Mapping[str, object], limit: int) -> tuple[dict[str, Any], int]:
    length = env.get("CONTENT_LENGTH")
    terminated = env.get("wsgi.input_terminated") is True
    expected: int | None
    if length is None or length == "":
        if not terminated:
            raise IntakeError(400, "invalid_bundle")
        expected = None
    elif isinstance(length, str) and length.isascii() and length.isdigit():
        digits = length.lstrip("0") or "0"
        if len(digits) > len(str(limit)) or int(digits) > limit:
            raise IntakeError(413, "payload_too_large")
        expected = int(digits)
    else:
        raise IntakeError(400, "invalid_bundle")
    stream = cast(BinaryIO, env["wsgi.input"])
    data = bytearray()
    # Without the termination extension WSGI reads must stop exactly at the declared
    # length. Reading one further byte can block on a persistent connection.
    ceiling = limit + 1 if expected is None else expected
    while len(data) < ceiling:
        size = min(8192, ceiling - len(data))
        chunk = stream.read(size)
        if not isinstance(chunk, bytes) or len(chunk) > size:
            raise IntakeError(400, "invalid_bundle")
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > limit:
        raise IntakeError(413, "payload_too_large")
    if expected is not None and (
        len(data) != expected or (terminated and stream.read(1))
    ):
        raise IntakeError(400, "invalid_bundle")
    try:
        doc = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_float=_float,
            parse_constant=_invalid,
        )
    except (ValueError, RecursionError):
        raise IntakeError(400, "invalid_bundle") from None
    if (
        not isinstance(doc, dict)
        or doc.keys() != {"bundle", "leaf_index"}
        or not isinstance(doc["bundle"], dict)
        or type(doc["leaf_index"]) is not int
        or not 0 <= doc["leaf_index"] < 2**64
    ):
        raise IntakeError(400, "invalid_bundle")
    return doc["bundle"], doc["leaf_index"]


class ChallengeApp:
    def __init__(
        self,
        submit: Callable[[str, dict[str, Any], int], dict[str, object]],
        *,
        authenticate: Callable[[str], str | None],
        body_limit: int,
    ) -> None:
        if type(body_limit) is not int or body_limit < 1:
            raise ValueError("Positive challenge body limit required")
        self._submit = submit
        self._authenticate = authenticate
        self._limit = body_limit

    def __call__(
        self,
        environ: Mapping[str, object],
        start_response: Callable[[str, list[tuple[str, str]]], object],
    ) -> list[bytes]:
        result: dict[str, object]
        headers = [("Cache-Control", "no-store"), ("Content-Type", "application/json")]
        if environ.get("PATH_INFO") != _ROUTE or environ.get("QUERY_STRING"):
            status, result = HTTPStatus.NOT_FOUND, {"error": {"code": "not_found"}}
        elif environ.get("REQUEST_METHOD") != "POST":
            status, result = (
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": {"code": "method_not_allowed"}},
            )
            headers.append(("Allow", "POST"))
        else:
            try:
                auth = environ.get("HTTP_AUTHORIZATION")
                match = _BEARER.fullmatch(auth) if isinstance(auth, str) else None
                holder = self._authenticate(match[1]) if match else None
                if not isinstance(holder, str) or not holder:
                    raise IntakeError(401, "unauthorized")
                bundle, index = _body(environ, self._limit)
                handle = self._submit(holder, bundle, index)
                result = {
                    name: handle[name]
                    for name in ("challenge_id", "status", "capability")
                }
                if not all(
                    isinstance(value, str) and value for value in result.values()
                ):
                    raise ValueError("Invalid challenge handle")
                status = HTTPStatus.ACCEPTED
            except IntakeError as exc:
                valid_retry = type(exc.retry_after) is int and exc.retry_after > 0
                if (exc.status, exc.code) in _CODES and (
                    exc.status != 429 or valid_retry
                ):
                    status, result = (
                        HTTPStatus(exc.status),
                        {"error": {"code": exc.code}},
                    )
                    if exc.status == 429:
                        headers.append(("Retry-After", str(exc.retry_after)))
                    if exc.status == 401:
                        headers.append(("WWW-Authenticate", "Bearer"))
                else:
                    status, result = (
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": {"code": "verifier_unavailable"}},
                    )
            except Exception:  # noqa: BLE001 -- dependencies may include credentials/transcripts in errors.
                status, result = (
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": {"code": "verifier_unavailable"}},
                )
        payload = json.dumps(result, separators=(",", ":")).encode("ascii")
        headers.append(("Content-Length", str(len(payload))))
        start_response(f"{status.value} {status.phrase}", headers)
        return [payload]
