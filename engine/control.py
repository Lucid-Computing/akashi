"""Local, peer-authenticated observation of a single supervised engine process."""

from __future__ import annotations

import ctypes
import hmac
import json
import math
import os
import secrets
import select
import socket
import stat
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, fields
from pathlib import Path
from types import TracebackType
from typing import Any, final

from engine.adapter import Canary, Cursor, EngineUnavailable, StartupEvidence, Window

# Three host-owned canaries each fit the 1024-token window, including the reply.
_FRAME = 64 * 1024


def _peer_uid(conn: socket.socket) -> int:
    option = getattr(socket, "SO_PEERCRED", None)
    if option is not None:
        layout = struct.Struct("iII")  # Linux struct ucred
        _, uid, _ = layout.unpack(
            conn.getsockopt(socket.SOL_SOCKET, option, layout.size)
        )
        return int(uid)
    # Darwin and the BSDs export getpeereid(3) from libc.
    getpeereid = getattr(ctypes.CDLL(None, use_errno=True), "getpeereid", None)
    if getpeereid is None:
        raise EngineUnavailable("Local peer authentication unavailable")
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    if getpeereid(conn.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise EngineUnavailable("Local peer authentication failed")
    return uid.value


def _object(value: Any, names: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or value.keys() != names:
        raise ValueError("Invalid engine control fields")
    return value


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate engine control field")
    return obj


def _receive(conn: socket.socket, timeout: float) -> Any:
    deadline = time.monotonic() + timeout

    def read(n: int) -> bytes:
        data = bytearray()
        while len(data) < n:
            conn.settimeout(max(0, deadline - time.monotonic()))
            part = conn.recv(n - len(data))
            if not part:
                raise EOFError("Incomplete control frame")
            data.extend(part)
        return bytes(data)

    length = int.from_bytes(read(4), "big")
    if not 0 < length <= _FRAME:
        raise ValueError("Invalid engine control frame")
    return json.loads(read(length).decode("utf-8"), object_pairs_hook=_unique)


def _send(conn: socket.socket, value: object) -> None:
    data = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(data) > _FRAME:
        raise ValueError("Oversize engine control frame")
    conn.sendall(len(data).to_bytes(4, "big") + data)


def _cursor(raw: object) -> Cursor:
    obj = _object(raw, {"instance", "position"})
    if (
        not isinstance(obj["instance"], str)
        or not obj["instance"]
        or type(obj["position"]) is not int
        or obj["position"] < 0
    ):
        raise ValueError("Invalid observation cursor")
    return Cursor(obj["instance"], obj["position"])


def _canary(raw: object) -> Canary:
    obj = _object(raw, {"prompt", "expected", "max_tokens"})
    if type(obj["max_tokens"]) is not int or not all(
        isinstance(obj[field], list) and all(type(t) is int for t in obj[field])
        for field in ("prompt", "expected")
    ):
        raise ValueError("Invalid observed canary")
    return Canary(tuple(obj["prompt"]), obj["max_tokens"], tuple(obj["expected"]))


def _window(raw: object) -> Window:
    obj = _object(raw, {"start", "end", "covered", "integrity_error"})
    if not all(type(obj[k]) is bool for k in ("covered", "integrity_error")):
        raise ValueError("Invalid window status")
    return Window(
        _cursor(obj["start"]),
        _cursor(obj["end"]),
        obj["covered"],
        obj["integrity_error"],
    )


def _settings(uid: int, timeout: float) -> None:
    if (
        type(uid) is not int
        or not 0 <= uid < 2**32 - 1
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Invalid engine control settings")


@final
class ControlServer:
    def __init__(
        self,
        path: Path,
        *,
        gateway_uid: int,
        gateway_gid: int,
        timeout: float,
        instance: str,
        evidence: Callable[[], StartupEvidence],
        canaries: tuple[Canary, ...],
        begin: Callable[[], Cursor],
        finish: Callable[[Cursor], Window],
    ) -> None:
        _settings(gateway_uid, timeout)
        _settings(gateway_gid, timeout)
        if not isinstance(instance, str) or not instance:
            raise ValueError("Engine observation requires a process identity")
        self._path = Path(path)
        self._uid, self._gid, self._timeout = gateway_uid, gateway_gid, timeout
        self._instance, self._evidence, self._canaries = instance, evidence, canaries
        self._begin, self._finish = begin, finish
        self._lease: tuple[str, Cursor] | None = None
        self._poisoned = False
        self._listener: socket.socket | None = None
        self._identity: tuple[int, int] | None = None
        self._thread: threading.Thread | None = None
        self._r: socket.socket | None = None
        self._w: socket.socket | None = None

    def __enter__(self) -> ControlServer:
        if self._listener is not None:
            raise RuntimeError("Control server already open")
        directory = self._path.parent.lstat()
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid not in (0, os.geteuid())
            or directory.st_mode & 0o022
        ):
            raise PermissionError("Unsafe engine control directory")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener = listener
        try:
            # bind fails on both stale sockets and arbitrary existing paths.
            listener.bind(str(self._path))
            entry = self._path.lstat()
            self._identity = (entry.st_dev, entry.st_ino)
            if entry.st_gid != self._gid:
                os.chown(self._path, -1, self._gid)
            os.chmod(self._path, 0o660)
            listener.listen()
            self._r, self._w = socket.socketpair()
            self._thread = threading.Thread(
                target=self._serve, args=(listener, self._r), daemon=True
            )
            self._thread.start()
            return self
        except BaseException:
            self.close()
            raise

    def _request(self, raw: object) -> object:
        if not isinstance(raw, dict):
            raise TypeError("Invalid engine control request")
        op = raw.get("op")
        if op == "startup":
            _object(raw, {"op"})
            evidence = self._evidence()
            if self._poisoned or evidence.instance != self._instance:
                raise EngineUnavailable("No current engine startup")
            return {
                "evidence": asdict(evidence),
                "canaries": [asdict(c) for c in self._canaries],
            }
        if self._poisoned:
            raise EngineUnavailable("Engine observation quarantined")
        if op == "begin":
            _object(raw, {"op", "instance"})
            if raw["instance"] != self._instance or self._lease is not None:
                raise EngineUnavailable("Engine window unavailable")
            # Do not admit a new window if obtaining its start fails.
            self._poisoned = True
            start = _cursor(asdict(self._begin()))
            if start.instance != self._instance:
                raise EngineUnavailable("Process identity changed")
            lease = secrets.token_hex(32)
            self._lease = (lease, start)
            self._poisoned = False
            return {"start": asdict(start), "lease": lease}
        if op == "finish":
            _object(raw, {"op", "lease", "start"})
            start = _cursor(raw["start"])
            if (
                self._lease is None
                or not isinstance(raw["lease"], str)
                or not raw["lease"].isascii()
                or not hmac.compare_digest(self._lease[0], raw["lease"])
                or start != self._lease[1]
            ):
                raise EngineUnavailable("Unknown active observation")
            self._poisoned = True
            window = _window(asdict(self._finish(start)))
            if (
                window.start == start
                and window.end.instance == self._instance
                and window.end.position >= start.position
                and window.covered is True
                and window.integrity_error is False
            ):
                self._lease = None
                self._poisoned = False
            return asdict(window)
        raise ValueError("Unknown control operation")

    def _serve(self, listener: socket.socket, stopped: socket.socket) -> None:
        while True:
            readable, _, _ = select.select([stopped, listener], [], [])
            if stopped in readable:
                return
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(self._timeout)
                try:
                    if _peer_uid(conn) != self._uid:
                        continue
                    result = self._request(_receive(conn, self._timeout))
                    _send(conn, {"ok": True, "value": result})
                except Exception:  # noqa: BLE001 -- never send provider diagnostics to the peer.
                    try:
                        _send(conn, {"ok": False})
                    except OSError:
                        pass

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._w is not None:
            self._w.sendall(b".")
            if self._thread is not None and self._thread.is_alive():
                self._thread.join()
            self._w.close()
            self._w = None
        if self._r is not None:
            self._r.close()
            self._r = None
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        if self._identity is not None:
            try:
                entry = self._path.lstat()
            except FileNotFoundError:
                pass
            else:
                if (
                    stat.S_ISSOCK(entry.st_mode)
                    and (entry.st_dev, entry.st_ino) == self._identity
                ):
                    self._path.unlink()
            self._identity = None


class ControlClient:
    def __init__(self, path: Path, *, provider_uid: int, timeout: float) -> None:
        _settings(provider_uid, timeout)
        self._path = Path(path)
        self._uid, self._timeout = provider_uid, timeout
        self._instance: str | None = None
        self._lease: str | None = None

    def _call(self, request: dict[str, object]) -> Any:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(self._timeout)
                conn.connect(str(self._path))
                if _peer_uid(conn) != self._uid:
                    raise EngineUnavailable("Unexpected engine observation provider")
                _send(conn, request)
                obj = _object(_receive(conn, self._timeout), {"ok", "value"})
                if obj["ok"] is not True:
                    raise EngineUnavailable("Engine observation unavailable")
                return obj["value"]
        except (ValueError, EOFError, OSError, RecursionError):
            raise EngineUnavailable("Engine observation unavailable") from None

    def startup(self) -> tuple[StartupEvidence, tuple[Canary, ...]]:
        try:
            raw = _object(self._call({"op": "startup"}), {"evidence", "canaries"})
            obj = _object(raw["evidence"], {f.name for f in fields(StartupEvidence)})
            if (
                not isinstance(obj["instance"], str)
                or not obj["instance"]
                or not isinstance(obj["commitment_id"], str)
                or not all(
                    type(obj[k]) is bool
                    for k in obj.keys() - {"instance", "commitment_id"}
                )
                or not isinstance(raw["canaries"], list)
                or len(raw["canaries"]) != 3
            ):
                raise ValueError("Invalid observed startup")
            evidence = StartupEvidence(**obj)
            canaries = tuple(_canary(c) for c in raw["canaries"])
            self._instance = evidence.instance
            return evidence, canaries
        except (TypeError, ValueError):
            raise EngineUnavailable("Invalid engine startup observation") from None

    def begin(self) -> Cursor:
        try:
            obj = _object(
                self._call({"op": "begin", "instance": self._instance}),
                {"start", "lease"},
            )
            start = _cursor(obj["start"])
            lease = obj["lease"]
            if (
                start.instance != self._instance
                or not isinstance(lease, str)
                or len(lease) != 64
                or not lease.isascii()
            ):
                raise ValueError("Invalid issued window")
            self._lease = lease
            return start
        except (ValueError, TypeError):
            raise EngineUnavailable("Invalid engine window start") from None

    def finish(self, start: Cursor) -> Window:
        try:
            result = _window(
                self._call(
                    {"op": "finish", "start": asdict(start), "lease": self._lease}
                )
            )
            self._lease = None
            return result
        except (ValueError, TypeError):
            raise EngineUnavailable("Invalid engine window checkpoint") from None
