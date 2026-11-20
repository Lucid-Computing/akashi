"""RFC-0010 ciphertext retrieval and a quiet loopback WSGI host."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Protocol
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

if TYPE_CHECKING:
    from _typeshed.wsgi import ErrorStream, WSGIEnvironment

from pickup.crypto import VERSION, PickupError, envelope_parts

_PREFIX = "/receipts/v1/pickup/"
_ROUTE = re.compile(_PREFIX + r"([0-9a-f]{64})")


class PickupReader(Protocol):
    def get(self, pickup_id: str, /) -> dict[str, str] | None: ...


class PerIPLimit:
    """Process-local rolling window. Full live peer slots deny new peers."""

    def __init__(
        self,
        *,
        requests: int,
        period_seconds: float,
        max_peers: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if any(type(v) is not int or v <= 0 for v in (requests, max_peers)):
            raise ValueError("Positive request and peer limits are required")
        if (
            type(period_seconds) not in (int, float)
            or not math.isfinite(period_seconds)
            or period_seconds <= 0
        ):
            raise ValueError("A positive finite rate-limit period is required")
        self.retry_after_seconds = math.ceil(period_seconds)
        self._requests = requests
        self._period = period_seconds
        self._max_peers = max_peers
        self._clock = clock
        self._lock = threading.Lock()
        self._peers: OrderedDict[str, deque[float]] = OrderedDict()

    def __call__(self, peer: str) -> bool:
        with self._lock:
            now = self._clock()
            cutoff = now - self._period
            # Entries are ordered by their most recent admitted request.
            while self._peers and next(iter(self._peers.values()))[-1] <= cutoff:
                self._peers.popitem(last=False)
            hits = self._peers.get(peer)
            if hits is None:
                if len(self._peers) >= self._max_peers:
                    return False
                hits = self._peers[peer] = deque()
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) == self._requests:
                return False
            hits.append(now)
            self._peers.move_to_end(peer)
            return True


def _peer(environ: Mapping[str, object]) -> str | None:
    text = environ.get("REMOTE_ADDR")
    if not isinstance(text, str) or "%" in text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def _public_body(row: dict[str, str]) -> bytes:
    if row.keys() != {"version", "nonce", "ciphertext"}:
        raise PickupError("Invalid sealed envelope")
    nonce, ciphertext = envelope_parts(row)
    return json.dumps(
        {"version": VERSION, "nonce": nonce.hex(), "ciphertext": ciphertext.hex()},
        separators=(",", ":"),
    ).encode("ascii")


class PickupApp:
    def __init__(self, store: PickupReader, *, limiter: PerIPLimit) -> None:
        self._store = store
        self._limiter = limiter

    def __call__(
        self,
        environ: Mapping[str, object],
        start_response: Callable[[str, list[tuple[str, str]]], object],
    ) -> list[bytes]:
        path = environ.get("PATH_INFO")
        status = "404 Not Found"
        body = b""
        headers = [("Cache-Control", "no-store")]
        if isinstance(path, str) and path.startswith(_PREFIX):
            try:
                peer = _peer(environ)
                match = _ROUTE.fullmatch(path)
                if peer is None or not self._limiter(peer):
                    status = "429 Too Many Requests"
                    headers.append(
                        ("Retry-After", str(self._limiter.retry_after_seconds))
                    )
                elif (
                    match
                    and not environ.get("QUERY_STRING")
                    and environ.get("RAW_URI", path) == path
                    and environ.get("REQUEST_URI", path) == path
                ):
                    if environ.get("REQUEST_METHOD") != "GET":
                        status = "405 Method Not Allowed"
                        headers.append(("Allow", "GET"))
                    else:
                        row = self._store.get(match[1])
                        if row is not None:
                            body = _public_body(row)
                            status = "200 OK"
                            headers.append(("Content-Type", "application/json"))
            except Exception:  # noqa: BLE001 -- redact all dependency diagnostics.
                # Dependency failures must not expose an identifier or exception text.
                status = "503 Service Unavailable"
        headers.append(("Content-Length", str(len(body))))
        start_response(status, headers)
        return [body]


class _DiscardErrors:
    def write(self, value: str) -> None:
        pass

    def writelines(self, values: list[str]) -> None:
        pass

    def flush(self) -> None:
        pass


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass

    def get_stderr(self) -> ErrorStream:
        return _DiscardErrors()

    def get_environ(self) -> WSGIEnvironment:
        env = super().get_environ()
        env["RAW_URI"] = self.path
        return env

    def send_error(
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> None:
        # The standard parser can include the offending request line in errors.
        self.send_response(code)
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()


class _QuietServer(WSGIServer):
    def handle_error(self, request: object, client_address: object) -> None:
        pass


def make_pickup_server(
    app: PickupApp, *, host: str = "127.0.0.1", port: int
) -> WSGIServer:
    """Return a single-process reference host with access and error logs suppressed."""
    return make_server(host, port, app, _QuietServer, _QuietHandler)
