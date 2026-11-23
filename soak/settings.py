"""Role-owned soak configuration, private loopback I/O and pinned public inputs."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import stat
import urllib.parse
from pathlib import Path
from typing import Any

from soak.ledger import require


def private(path: Path) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        mode = os.fstat(fd)
        require(
            stat.S_ISREG(mode.st_mode)
            and mode.st_uid == os.geteuid()
            and not mode.st_mode & 0o077,
            "Expected a role-private configuration",
        )
        result = json.load(stream)
    if not isinstance(result, dict):
        raise TypeError("Invalid soak configuration")
    return result


def digest(path: Path) -> str:
    with path.open("rb") as f:
        check = hashlib.sha256()
        while data := f.read(1 << 20):
            check.update(data)
    return check.hexdigest()


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: Path, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


def response(
    origin: str,
    route: str,
    *,
    timeout: float,
    cap: int,
    data: object = None,
    decode_only_ok: bool = False,
) -> tuple[int, Any]:
    require(
        route.startswith("/")
        and not route.startswith("//")
        and type(cap) is int
        and cap > 0
        and timeout > 0,
        "Invalid observation endpoint",
    )
    host = urllib.parse.urlsplit(origin)
    if host.scheme == "unix":
        require(
            not host.netloc
            and host.path.startswith("/")
            and not host.query
            and not host.fragment,
            "Invalid role socket",
        )
        conn: http.client.HTTPConnection = UnixConnection(Path(host.path), timeout)
    else:
        require(
            host.scheme == "http"
            and host.hostname in {"127.0.0.1", "::1"}
            and not host.username
            and not host.password
            and not host.query
            and not host.fragment
            and host.path in ("", "/"),
            "Expected a local role listener",
        )
        conn = http.client.HTTPConnection(
            str(host.hostname), host.port, timeout=timeout
        )
    try:
        body = None if data is None else json.dumps(data, allow_nan=False).encode()
        conn.request(
            "GET" if body is None else "POST",
            route,
            body=body,
            headers={"Content-Type": "application/json"},
        )
        raw = conn.getresponse()
        if decode_only_ok and raw.status != 200:
            return raw.status, None
        content = raw.read(cap + 1)
        require(len(content) <= cap, "Role response exceeds configured bound")
        return raw.status, json.loads(content) if content else {}
    finally:
        conn.close()


def public_keys(descriptor: dict[str, Any]) -> dict[tuple[str, str], bytes]:
    values = {}
    for role in ("log", "auditor"):
        cfg = descriptor["log"] if role == "log" else descriptor
        values[role, cfg[role + "_key_id"]] = bytes.fromhex(cfg[role + "_public_key"])
    for row in descriptor.get("verification_keys", []):
        value = bytes.fromhex(row["public_key"])
        require(
            row["role"] in ("log", "auditor")
            and len(value) == 32
            and values.setdefault((row["role"], row["key_id"]), value) == value,
            "Conflicting archived signer",
        )
    return values


def primary_host_matches(evidence: Path) -> bool:
    """Compare this Linux node with the private identity recorded during M0."""
    machine = Path("/etc/machine-id").read_bytes().strip()
    if len(machine) != 32 or any(c not in b"0123456789abcdef" for c in machine):
        return False
    value = hashlib.sha256(b"vig-m0-host-v1\0" + machine).hexdigest()
    return evidence.read_text().strip() == value
