"""Run a loopback HTTP router for testing Mode R forwarding, recovery and controls."""

from __future__ import annotations

import argparse
import json
import math
from collections.abc import Iterable, Iterator
from contextlib import closing
from http import HTTPStatus
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Literal
from urllib.parse import SplitResult, urlsplit

Mode = Literal["opaque", "transparent", "rewrite-messages", "inject-sampling"]
MODES = ("opaque", "transparent", "rewrite-messages", "inject-sampling")
_CHAT = "/v1/chat/completions"
_FEED = "/router/models"


def origin(value: str) -> SplitResult:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or any(c.isspace() or ord(c) < 32 for c in value)
        or "\\" in value
        or (
            parsed.scheme == "http"
            and parsed.hostname not in ("127.0.0.1", "::1", "localhost")
        )
    ):
        raise ValueError("Expected a loopback HTTP origin or a trusted HTTPS origin")
    return parsed


def _forwarded(body: bytes, mode: Mode) -> bytes:
    if mode in ("opaque", "transparent"):
        return body
    request = json.loads(body)
    if not isinstance(request, dict):
        raise TypeError("Expected a chat request")
    if mode == "inject-sampling":
        request["temperature"] = 1  # Incompatible forwarding control.
    else:
        messages = request.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("Expected chat messages")
        # Deliberately change a valid message while preserving the holder secret and budget.
        changed = dict(messages[-1])
        changed["content"] = "Local router rewrite fixture."
        request["messages"] = [*messages[:-1], changed]
    return json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode()


def _opaque(data: bytes) -> bytes:
    value = json.loads(data)
    if not isinstance(value, dict):
        raise TypeError("Expected an upstream JSON object")
    value.pop("verification", None)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def _events(lines: Iterable[bytes], transparent: bool) -> Iterator[bytes]:
    """Forward SSE frame boundaries. A truncated upstream must never gain a final event."""
    frame: list[bytes] = []
    for line in lines:
        if line not in (b"\n", b"\r\n"):
            frame.append(line)
            continue
        if transparent:
            yield b"".join(frame) + line
        else:
            fields, data = [], []
            for field in frame:
                raw = field.rstrip(b"\r\n")
                name, separator, value = raw.partition(b":")
                if name == b"data":
                    data.append(value.removeprefix(b" ") if separator else b"")
                else:
                    fields.append(field)
            if data:
                payload = b"\n".join(data)
                if payload != b"[DONE]":
                    payload = _opaque(payload)
                fields.append(b"data: " + payload + b"\n")
            yield b"".join(fields) + b"\n"
        frame.clear()


class MockRouter(ThreadingHTTPServer):
    """No shared provider credential and no request or response logging."""

    def __init__(
        self, upstream: str, port: int, mode: Mode, timeout_seconds: float
    ) -> None:
        if (
            mode not in MODES
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("Invalid mock router configuration")
        self.upstream, self.mode, self.timeout_seconds = (
            origin(upstream),
            mode,
            timeout_seconds,
        )
        super().__init__(("127.0.0.1", port), Forwarder)

    def handle_error(self, request: object, client_address: object) -> None:
        # Do not leak URLs, headers, bodies or connection diagnostics on handler failures.
        pass


class Forwarder(BaseHTTPRequestHandler):
    server: MockRouter

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.timeout_seconds)

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _error(self, status: HTTPStatus) -> None:
        body = json.dumps(
            {"error": {"code": "mock_router_error", "message": status.phrase}}
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != _FEED:
            self._error(HTTPStatus.NOT_FOUND)
            return
        self._proxy(None)

    def do_POST(self) -> None:
        if self.path != _CHAT:
            self._error(HTTPStatus.NOT_FOUND)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (
            self.headers.get("Transfer-Encoding")
            or len(lengths) != 1
            or not lengths[0].isascii()
            or not lengths[0].isdigit()
        ):
            self._error(HTTPStatus.BAD_REQUEST)
            return
        length = lengths[0].lstrip("0") or "0"
        if len(length) > 6 or int(length) > 256 * 1024:  # gateway request body limit
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        try:
            raw = self.rfile.read(int(length))
            if len(raw) != int(length):
                raise ValueError("Incomplete request")
            body = _forwarded(raw, self.server.mode)
        except (ValueError, TypeError, OSError, RecursionError):
            self._error(HTTPStatus.BAD_REQUEST)
            return
        self._proxy(body)

    def _proxy(self, body: bytes | None) -> None:
        upstream = self.server.upstream
        assert upstream.hostname is not None
        connection = HTTPSConnection if upstream.scheme == "https" else HTTPConnection
        headers = {"Accept-Encoding": "identity"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            auth = self.headers.get_all("Authorization", [])
            if len(auth) > 1:
                self._error(HTTPStatus.BAD_REQUEST)
                return
            if auth:
                headers["Authorization"] = auth[0]
        started = False
        try:
            with closing(
                connection(
                    upstream.hostname,
                    upstream.port,
                    timeout=self.server.timeout_seconds,
                )
            ) as conn:
                conn.request(self.command, self.path, body, headers)
                with conn.getresponse() as result:
                    media = (
                        (result.getheader("Content-Type") or "")
                        .split(";")[0]
                        .strip()
                        .lower()
                    )
                    if media not in (
                        "application/json",
                        "text/event-stream",
                    ) or result.getheader("Content-Encoding") not in (None, "identity"):
                        raise ValueError("Unsupported upstream encoding")
                    transparent = self.server.mode == "transparent"
                    payload = None
                    if media == "application/json":
                        payload = result.read()
                        if (
                            body is not None
                            and result.status == 200
                            and not transparent
                        ):
                            payload = _opaque(payload)
                    self.send_response(result.status)
                    self.send_header("Content-Type", media)
                    self.send_header("Cache-Control", "no-store")
                    for name, value in result.getheaders():
                        if name.lower() == "retry-after" or (
                            transparent and name.lower().startswith("x-vig-")
                        ):
                            self.send_header(name, value)
                    if payload is not None:
                        self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    started = True
                    if payload is not None:
                        self.wfile.write(payload)
                    else:
                        for event in _events(result, transparent):
                            self.wfile.write(event)
                            self.wfile.flush()
        except (HTTPException, OSError, ValueError, TypeError, RecursionError):
            self.close_connection = True
            if not started:
                self._error(HTTPStatus.BAD_GATEWAY)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, help="gateway origin")
    parser.add_argument(
        "--port",
        required=True,
        type=int,
        help="loopback port, or 0 for an available port",
    )
    parser.add_argument("--mode", choices=MODES, default="opaque")
    parser.add_argument(
        "--timeout-seconds",
        required=True,
        type=float,
        help="upstream and client socket timeout",
    )
    args = parser.parse_args()
    try:
        with MockRouter(
            args.upstream, args.port, args.mode, args.timeout_seconds
        ) as server:
            print(json.dumps({"port": server.server_port}), flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except (ValueError, OSError, OverflowError):
        parser.exit(2, "Could not start the local mock router\n")


if __name__ == "__main__":
    main()
