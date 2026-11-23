"""Provision and supervise the role-isolated traffic side of the one-node M4 run."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
import pwd
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from contextlib import ExitStack, closing
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from nacl.public import PrivateKey

from gateway.discovery import ServiceConfig
from log.verification import verify_head
from pickup.http import PerIPLimit
from prover.submission import COMMITMENT, guarded_spool
from soak.ledger import DURATION, NativeProcess, jcs, require
from soak.settings import digest, primary_host_matches, private, public_keys, response
from tools.gate_m1 import _write

Json = dict[str, Any]
PORT_NAMES = ("gateway", "log", "pickup", "router", "audit", "ingress")
SECS = (
    "startup_timeout",
    "request_timeout",
    "network_timeout",
    "poll_seconds",
    "resource_poll_seconds",
    "max_observation_gap_seconds",
    "proof_deadline_seconds",
    "lease_seconds",
    "verification_timeout_seconds",
    "retention_interval_seconds",
    "shutdown_timeout",
    "archive_drain_seconds",
)
COUNTS = (
    "retry_after",
    "response_cap",
    "verification_memory_bytes",
    "max_proof_bytes",
    "page_size",
    "challenge_limit_bytes",
    "carrier_limit_bytes",
)
GPU = r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"


def _private_dir(path: Path) -> None:
    detail = path.lstat()
    require(
        stat.S_ISDIR(detail.st_mode)
        and detail.st_uid == os.geteuid()
        and not detail.st_mode & 0o077,
        "Private role directory required",
    )


def _limits(limits: Json) -> None:
    require(
        all(
            type(limits[k]) in (float, int)
            and math.isfinite(limits[k])
            and limits[k] > 0
            for k in SECS
        ),
        "Invalid operational interval",
    )
    require(
        all(type(limits[k]) is int and limits[k] > 0 for k in COUNTS),
        "Invalid operational capacity",
    )
    require(
        limits["lease_seconds"] > limits["proof_deadline_seconds"]
        and max(limits["resource_poll_seconds"], limits["poll_seconds"])
        < limits["max_observation_gap_seconds"]
        <= 300,
        "Inconsistent observation bounds",
    )
    PerIPLimit(**limits["pickup_limit"])


def _ports() -> dict[str, int]:
    ports = {}
    with ExitStack() as stack:
        for name in PORT_NAMES:
            sock = stack.enter_context(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            )
            sock.bind(("127.0.0.1", 0))
            ports[name] = sock.getsockname()[1]
    return ports


@dataclass(frozen=True)
class Primary:
    previous: Path
    fresh: Path
    engine: int
    native: NativeProcess
    gpus: dict[str, str]
    endpoint: Json
    verifier: Path
    spool: Path

    @property
    def submission(self) -> Path:
        return self.spool.with_name("submission")

    @property
    def prover(self) -> int:
        return self.native.pid


def _gpu(path: Path, pattern: str) -> str:
    match = re.fullmatch(pattern, path.read_text().strip())
    if match is None:
        raise ValueError("Unrecognized single-GPU role assignment")
    return match[1]


def physical(root: Path, config: Json, env: Mapping[str, str]) -> Primary:
    _private_dir(root)
    previous, fresh, ep, spool, verifier = (
        Path(env["VIG_M4_" + k])
        for k in (
            "PRIMARY_READY",
            "FRESH_READY",
            "ENGINE_ENDPOINT",
            "PROVER_SPOOL",
            "VERIFIER",
        )
    )
    require(
        Path(env["VIG_M4_ROOT"]) == root
        and root.is_absolute()
        and fresh == root / "gateway/ready.json"
        and ep == root / "engine-endpoint.json"
        and spool == root / "proof-io/spool"
        and previous.is_absolute()
        and verifier.is_absolute(),
        "Role environment differs from allocation",
    )
    original, active = private(previous), private(fresh)
    identity = previous.parent / "host-fingerprint"
    stamp = private(root / "control/provider-observed.json")
    require(
        primary_host_matches(identity)
        and active["primary_host"] == identity.read_text().strip()
        and active["primary_ready_sha256"]
        == digest(previous)
        == config["primary_ready_sha256"]
        and all(
            active[k] == original[k]
            for k in (
                "phase",
                "commitment_id",
                "dtype",
                "same_process_f21",
                "float64_cases_passed",
                "platform",
                "canaries",
            )
        )
        and active["phase"] == "eligible"
        and active["commitment_id"] == COMMITMENT
        and active["dtype"] == "float32"
        and active["same_process_f21"] is True
        and len(active["canaries"])
        == len({tuple(c["prompt"]) for c in active["canaries"]})
        == 3
        and active["instance"]
        and active["instance"] == stamp["instance"],
        "Qualified primary startup evidence mismatch",
    )
    endpoint = private(ep)
    require(
        endpoint["schema_version"] == 1
        and endpoint["host"] == "127.0.0.1"
        and endpoint["provider_uid"] == os.geteuid()
        and endpoint["model"] == "maverick-int"
        and type(endpoint["port"]) is int
        and 0 < endpoint["port"] < 65536
        and Path(endpoint["control_socket"]) == root / "control/s"
        and Path(endpoint["spool"]) == spool
        and all(
            Path(endpoint[k]) == root / "gateway" / file
            for k, file in (
                ("ca", "ca.crt"),
                ("cert", "client.crt"),
                ("key", "client.key"),
            )
        ),
        "Unexpected provider interface",
    )
    ready = private(root / "prover/ready.json")
    engine, prover = (
        int((root / "control/provider.pid").read_text()),
        ready["native_pid"],
    )
    require(
        ready["schema_version"] == 1
        and ready["phase"] == "spool_open"
        and ready["commitment_id"] == COMMITMENT
        and type(ready["batch"]) is int
        and ready["batch"] == 1
        and type(prover) is int
        and min(engine, prover) > 1
        and engine != prover,
        "Single-writer prover evidence mismatch",
    )
    cgroups = []
    for pid in (engine, prover):
        os.kill(pid, 0)
        cgroups.append((Path("/proc") / str(pid) / "cgroup").read_text().strip())
    require(
        cgroups[0] != cgroups[1] and cgroups[1] == ready["cgroup"],
        "Physical roles lack distinct active cgroups",
    )
    native = NativeProcess(prover, ready["start_ticks"], ready["cgroup"])
    native.check()
    gpus = {
        "engine": _gpu(root / "control/gpu-assignment", rf"[0-9]+,\s*({GPU})"),
        "prover": _gpu(root / "prover/gpu-assignment", rf"({GPU}),\s*[0-9]+"),
    }
    require(len(set(gpus.values())) == 2, "Physical roles share a GPU")
    _private_dir(spool.parent)
    _private_dir(spool.with_name("submission"))
    require(
        {child.name for child in spool.parent.iterdir()} == {"spool", "submission"},
        "Unexpected entries in the proof I/O mount",
    )
    with guarded_spool(spool):
        pass
    verifier_attestation = json.loads((verifier / "verified.json").read_bytes())
    require(
        verifier_attestation
        == {
            "schema_version": 1,
            "native_published_example": "VERIFIED",
            "manifest_sha256": digest(verifier / "manifest.json"),
        },
        "Published native verifier example has not passed",
    )
    return Primary(previous, fresh, engine, native, gpus, endpoint, verifier, spool)


def _raw(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _certificate(staging: Path, startup: float, shutdown: float) -> None:
    now = datetime.now(timezone.utc)
    end = now + timedelta(seconds=DURATION + startup + shutdown, days=1)
    ca, server = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "M4 private ingress CA")]
    )

    def builder(
        key: ec.EllipticCurvePrivateKey, name: x509.Name
    ) -> x509.CertificateBuilder:
        return (
            x509.CertificateBuilder()
            .serial_number(x509.random_serial_number())
            .issuer_name(ca_name)
            .subject_name(name)
            .public_key(key.public_key())
            .not_valid_before(now)
            .not_valid_after(end)
        )

    authority = (
        builder(ca, ca_name)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca.public_key()), False
        )
        .sign(ca, hashes.SHA256())
    )
    leaf = (
        builder(
            server, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), False
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            False,
        )
        .sign(ca, hashes.SHA256())
    )
    _raw(
        staging / "public/ingress-ca.pem",
        authority.public_bytes(serialization.Encoding.PEM),
    )
    _raw(
        staging / "gateway/ingress.pem",
        leaf.public_bytes(serialization.Encoding.PEM)
        + server.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _proxy(path: Path, ports: dict[str, int], limits: Json) -> bytes:
    require(
        not re.search(r"[^a-zA-Z0-9/_.-]", str(path)),
        "Unrepresentable private HAProxy path",
    )
    lines = [
        "global",
        "defaults",
        "  mode http",
        f"  timeout connect {math.ceil(limits['network_timeout'] * 1000)}ms",
        f"  timeout client {math.ceil(limits['request_timeout'] * 1000)}ms",
        f"  timeout server {math.ceil(limits['request_timeout'] * 1000)}ms",
        "frontend holder",
        f"  bind 127.0.0.1:{ports['ingress']} ssl crt {path} ssl-min-ver TLSv1.2",
        "  acl read method GET",
        "  acl post method POST",
        "  acl log path_beg /log/v1/",
        "  acl pickup path_beg /receipts/v1/pickup/",
        "  acl audit path_beg /audit/v1/",
        "  acl challenge path /audit/v1/challenges",
        "  http-request deny unless read or post challenge",
        "  http-request deny unless log or pickup or audit",
    ]
    for role in ("log", "pickup", "audit"):
        lines.append(f"  use_backend backend_{role} if {role}")
    for role in ("log", "pickup", "audit"):
        lines.extend(
            [f"backend backend_{role}", f"  server local 127.0.0.1:{ports[role]}"]
        )
    return ("\n".join(lines) + "\n").encode("ascii")


def _populate(
    stage: Path, dest: Path, c: Json, p: Primary, ports: dict[str, int]
) -> None:
    for name in (
        "public",
        "gateway",
        "auditor",
        "holder",
        "runner",
        "ipc",
        "ipc/gateway",
        "ipc/auditor",
    ):
        (stage / name).mkdir(mode=0o700)
    l = c["limits"]
    _certificate(stage, l["startup_timeout"], l["shutdown_timeout"])
    _raw(stage / "gateway/ingress.cfg", _proxy(dest / "gateway/ingress.pem", ports, l))
    log, audit = (Ed25519PrivateKey.generate() for _ in range(2))
    recipient = PrivateKey.generate()
    challenge, inference = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    origin = f"https://127.0.0.1:{ports['ingress']}"

    def local(name: str) -> str:
        return f"http://127.0.0.1:{ports[name]}"

    service = ServiceConfig(
        model=p.endpoint["model"],
        owned_by=c.get("owned_by", pwd.getpwuid(os.geteuid()).pw_name),
        created=int(time.time()),
        log_id=secrets.token_hex(32),
        log_key_id=secrets.token_hex(16),
        log_public_key=log.public_key().public_bytes_raw().hex(),
        auditor_key_id=secrets.token_hex(16),
        auditor_public_key=audit.public_key().public_bytes_raw().hex(),
        log_url=origin + "/log/v1/",
        pickup_url=origin + "/receipts/v1/pickup",
        challenge_url=origin + "/audit/v1/challenges",
        audit_url=origin + "/audit/v1",
    )
    _write(stage / "public/descriptor.json", service.descriptor())
    native = {
        "binary": str(p.verifier / "public/cp_verify"),
        "manifest": str(p.verifier / "manifest.json"),
        "config_dir": str(p.verifier / "public/config"),
        "public_key_dir": str(p.verifier / "public/ivk"),
        "timeout_seconds": l["verification_timeout_seconds"],
        "memory_bytes": l["verification_memory_bytes"],
        "max_proof_bytes": l["max_proof_bytes"],
    }
    _write(stage / "public/native-runtime.json", native)
    gateway, auditor, holder = (
        dest / role for role in ("gateway", "auditor", "holder")
    )
    status, custody = dest / "ipc/gateway/escrow.sock", dest / "ipc/auditor/audit.sock"
    descriptor = str(dest / "public/descriptor.json")
    ep = p.endpoint
    _write(
        stage / "gateway/config.json",
        dict(
            state=str(gateway),
            assets=c["assets"],
            service=asdict(service),
            log_signer=log.private_bytes_raw().hex(),
            escrow_key=secrets.token_hex(32),
            auditor_recipient=bytes(recipient.public_key).hex(),
            provider={
                "host": ep["host"],
                "port": ep["port"],
                "model": ep["model"],
                "uid": ep["provider_uid"],
                "control": ep["control_socket"],
                "ca": ep["ca"],
                "cert": ep["cert"],
                "key": ep["key"],
            },
            log_origin=local("log"),
            audit_socket="unix://" + str(custody),
            escrow_status_socket=str(status),
            inference_bearer=inference,
            gateway_port=ports["gateway"],
            log_port=ports["log"],
            pickup_port=ports["pickup"],
            **{
                k: l[k]
                for k in (
                    "request_timeout",
                    "startup_timeout",
                    "poll_seconds",
                    "network_timeout",
                    "response_cap",
                    "retry_after",
                    "pickup_limit",
                )
            },
        ),
    )
    for name, value in (
        ("recipient.key", bytes(recipient)),
        ("holder-hmac.key", secrets.token_bytes(32)),
        ("signer.key", audit.private_bytes_raw()),
        ("bearer", challenge.encode()),
    ):
        _raw(stage / "auditor" / name, value)
    _write(
        stage / "auditor/config.json",
        dict(
            schema_version=1,
            state=str(auditor),
            assets=c["assets"],
            descriptor=descriptor,
            recipient_key=str(auditor / "recipient.key"),
            holder_hmac_key=str(auditor / "holder-hmac.key"),
            verdict_signing_key=str(auditor / "signer.key"),
            holder_bearer_file=str(auditor / "bearer"),
            log_url=local("log") + "/log/v1/",
            escrow_socket=str(status),
            auditor_socket=str(custody),
            custody_peer_uid=os.geteuid(),
            http_host="127.0.0.1",
            http_port=ports["audit"],
            submission_state=str(p.submission),
            spool=str(p.spool),
            native_runtime=native,
            reference=c["reference"],
            io_timeout_seconds=l["network_timeout"],
            read_limit_bytes=l["response_cap"],
            **{
                k: l[k]
                for k in (
                    "poll_seconds",
                    "lease_seconds",
                    "proof_deadline_seconds",
                    "page_size",
                    "challenge_limit_bytes",
                    "carrier_limit_bytes",
                )
            },
        ),
    )
    _write(
        stage / "holder/config.json",
        {
            "state": str(holder / "holder.db"),
            "assets": c["assets"],
            "descriptor": descriptor,
            "runtime": str(dest / "public/native-runtime.json"),
            "ca_file": str(dest / "public/ingress-ca.pem"),
            "router_origin": local("router"),
            "inference_bearer": inference,
            "challenge_bearer": challenge,
            "timeout_seconds": l["request_timeout"],
            "max_response_bytes": l["response_cap"],
        },
    )


def provision(root: Path, c: Json, p: Primary) -> dict[str, int]:
    """Under the supervisor lock, atomically publish one role layout. Reuse its keys on retry."""
    require(
        type(c["schema_version"]) is int and c["schema_version"] == 1,
        "Unknown deployment schema",
    )
    _limits(c["limits"])
    for key in (
        "python",
        "source",
        "audit_python",
        "audit_source",
        "role_command",
        "assets",
        "haproxy",
    ):
        require(Path(c[key]).is_absolute(), "Absolute role path required")
    dest = root / "traffic"
    binding = hashlib.sha256(
        jcs(
            [
                c,
                digest(p.fresh),
                digest(p.previous),
                p.endpoint,
                p.engine,
                asdict(p.native),
                p.gpus,
                str(p.verifier),
                digest(p.verifier / "manifest.json"),
                str(p.spool),
            ]
        ).encode()
    ).hexdigest()
    if dest.exists():
        _private_dir(dest)
        manifest = private(dest / "runner/deployment.json")
        require(
            manifest["binding"] == binding,
            "Existing deployment differs from current allocation",
        )
        ports: dict[str, int] = manifest["ports"]
        require(
            set(ports) == set(PORT_NAMES)
            and len(set(ports.values())) == len(PORT_NAMES)
            and all(type(v) is int and 0 < v < 65536 for v in ports.values()),
            "Invalid stored ports",
        )
        return ports
    stage = Path(tempfile.mkdtemp(prefix=".traffic-", dir=root))
    try:
        ports = _ports()
        _populate(stage, dest, c, p, ports)
        _write(stage / "runner/deployment.json", {"binding": binding, "ports": ports})
        for path, _, _files in os.walk(stage, topdown=False):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        os.rename(stage, dest)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return ports


@dataclass(frozen=True)
class Command:
    role: str
    name: str
    argv: tuple[str, ...]
    cwd: Path


def commands(t: Path, c: Json, p: Primary, ports: dict[str, int]) -> list[Command]:
    """Every private application runs behind the provisioned role mount namespace."""
    role_cmd, py, apy = c["role_command"], c["python"], c["audit_python"]
    source, audit_source = Path(c["source"]), Path(c["audit_source"])
    gw, au = t / "gateway", t / "auditor"

    def role(name: str, component: str, args: list[str]) -> Command:
        return Command(
            name,
            component,
            (role_cmd, name, "--", *args),
            audit_source if name == "auditor" else source,
        )

    result = [
        role(
            "gateway",
            "gateway",
            [py, "-m", "soak.gateway_service", "--config", str(gw / "config.json")],
        ),
        role(
            "gateway", "ingress", [c["haproxy"], "-db", "-f", str(gw / "ingress.cfg")]
        ),
        role(
            "router",
            "router",
            [
                py,
                "-m",
                "router.mock",
                "--upstream",
                f"http://127.0.0.1:{ports['gateway']}",
                "--port",
                str(ports["router"]),
                "--mode",
                "opaque",
                "--timeout-seconds",
                str(c["limits"]["request_timeout"]),
            ],
        ),
    ]
    for name in ("http", "custody", "worker", "index"):
        result.append(
            role(
                "auditor",
                name,
                [
                    apy,
                    "-m",
                    "soak.audit_service",
                    "--role",
                    name,
                    "--config",
                    str(au / "config.json"),
                ],
            )
        )
    sweep = [
        apy,
        "-m",
        "operations.retention",
        "--interval-seconds",
        str(c["limits"]["retention_interval_seconds"]),
    ]
    result.extend(
        [
            role(
                "auditor",
                "sweep-auditor",
                [
                    *sweep,
                    "auditor",
                    str(au / "challenge.sqlite"),
                    str(au / "inbox.sqlite"),
                ],
            ),
            role(
                "auditor",
                "sweep-spool",
                [*sweep, "prover", str(p.submission), str(p.spool)],
            ),
        ]
    )
    return result


def _ready(t: Path, ports: dict[str, int], c: Json, p: Primary) -> bool:
    limits = c["limits"]
    read = {"timeout": limits["network_timeout"], "cap": limits["response_cap"]}
    desc = private(t / "public/descriptor.json")
    gw = private(t / "gateway/service-ready.json")
    if (
        gw.get("physical_engine_eligible") is not True
        or gw.get("sampling_mode") != "soak"
    ):
        return False
    code, served = response(
        f"http://127.0.0.1:{ports['gateway']}", "/.well-known/vig.json", **read
    )
    if code != 200 or served != desc:
        return False
    code, feed = response(
        f"http://127.0.0.1:{ports['router']}", "/router/models", **read
    )
    if code != 200 or [m["id"] for m in feed["models"]] != [desc["model"]]:
        return False
    for role, name, route in (
        ("gateway", "escrow", "/internal/escrow/status/"),
        ("auditor", "audit", "/internal/sampled/"),
    ):
        code, _ = response(
            "unix://" + str(t / "ipc" / role / (name + ".sock")),
            route + "0" * 64,
            **read,
        )
        if code != 404:
            return False
    ctx = ssl.create_default_context(cafile=str(t / "public/ingress-ca.pem"))
    keys = public_keys(desc)
    for route, expected in (
        ("/log/v1/sth", 200),
        ("/audit/v1/selections?cursor=0", 200),
        ("/receipts/v1/pickup/" + "0" * 64, 404),
    ):
        conn = http.client.HTTPSConnection(
            "127.0.0.1",
            ports["ingress"],
            context=ctx,
            timeout=limits["network_timeout"],
        )
        try:
            conn.request("GET", route)
            reply = conn.getresponse()
            data = reply.read(limits["response_cap"] + 1)
            if reply.status != expected or len(data) > limits["response_cap"]:
                return False
            if expected == 200:
                document = json.loads(data)
                if document["log_id"] != desc["log"]["log_id"]:
                    return False
                if route == "/log/v1/sth":
                    verify_head(
                        document,
                        log_id=desc["log"]["log_id"],
                        lookup_key=lambda role, key: keys[role, key],
                    )
        finally:
            conn.close()
    return all(
        path.is_file()
        for path in (
            t / "auditor/challenge.sqlite",
            t / "auditor/inbox.sqlite",
            p.submission / "submissions.sqlite3",
        )
    )


class Children:
    def __init__(self) -> None:
        self.live: dict[str, subprocess.Popen[bytes]] = {}

    def start(self, cmd: Command, log: Path) -> int:
        fd = os.open(log, os.O_APPEND | os.O_NOFOLLOW | os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "ab") as output:
            sub = subprocess.Popen(
                cmd.argv,
                cwd=cmd.cwd,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=output,
                start_new_session=True,
            )
        self.live[cmd.name] = sub
        return sub.pid

    def check(self, stop: threading.Event) -> None:
        require(not stop.is_set(), "Operator stopped deployment")
        for name, child in self.live.items():
            if name != "runner" and child.poll() is not None:
                raise RuntimeError("Deployment role stopped: " + name)

    def shutdown(self, timeout: float) -> None:
        until = time.monotonic() + timeout
        children = list(reversed(self.live.values()))
        for child in children:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for child in children:
            try:
                child.wait(timeout=max(0, until - time.monotonic()))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()


def _clear_stale_socket(endpoint: Path) -> None:
    """Recover a crashed listener under the supervisor lock in its private directory."""
    _private_dir(endpoint.parent)
    try:
        before = endpoint.lstat()
    except FileNotFoundError:
        return
    require(
        stat.S_ISSOCK(before.st_mode) and before.st_uid == os.geteuid(),
        "Unexpected role socket entry",
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.setblocking(False)
        try:
            probe.connect(str(endpoint))
        except ConnectionRefusedError:
            after = endpoint.lstat()
            require(
                (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                "Role socket changed during restart",
            )
            endpoint.unlink()
            return
        except BlockingIOError:
            pass
    raise RuntimeError("Role listener already active")


def _archive_recoverable(journal: Path, budget: float) -> bool:
    if not journal.is_file():
        return False
    with closing(sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True)) as db:
        row = db.execute("SELECT end_ns FROM run WHERE id=1").fetchone()
    return (
        row is not None
        and type(row[0]) is int
        and time.monotonic_ns() < row[0] + budget * 1e9
    )


def supervise(
    root: Path, c: Json, p: Primary, ports: dict[str, int], stop: threading.Event
) -> int:
    t = root / "traffic"
    children = Children()
    limits = c["limits"]
    procs: dict[str, list[int]] = {
        "engine": [p.engine],
        "prover": [p.prover],
        "auditor": [],
        "gateway": [],
    }
    for endpoint in ("ipc/gateway/escrow.sock", "ipc/auditor/audit.sock"):
        _clear_stale_socket(t / endpoint)
    jobs = commands(t, c, p, ports)

    def launch(item: Command) -> None:
        group = "gateway" if item.role == "router" else item.role
        pid = children.start(item, t / "runner" / (item.name + ".log"))
        procs[group].append(pid)

    try:
        check = subprocess.run(
            [
                c["role_command"],
                "auditor",
                "--",
                c["audit_python"],
                "-m",
                "soak.audit_service",
                "--role",
                "check-spool",
                "--config",
                str(t / "auditor/config.json"),
            ],
            cwd=c["audit_source"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=limits["startup_timeout"],
            check=False,
        )
        require(check.returncode == 0, "Auditor spool publication preflight failed")
        for item in jobs:
            if not item.name.startswith("sweep-"):
                launch(item)
        deadline = time.monotonic() + limits["startup_timeout"]
        while True:
            children.check(stop)
            require(
                time.monotonic() < deadline,
                "Live traffic services did not become ready",
            )
            try:
                if _ready(t, ports, c, p):
                    break
            except (OSError, http.client.HTTPException):
                pass
            stop.wait(limits["poll_seconds"])
        for item in jobs:
            if item.name.startswith("sweep-"):
                launch(item)
        children.check(stop)
        config = t / "runner/config.json"
        _write(
            config,
            dict(
                state=str(t / "runner"),
                active_startup=str(p.fresh),
                primary_startup=str(p.previous),
                original_host_identity=str(p.previous.parent / "host-fingerprint"),
                descriptor=str(t / "public/descriptor.json"),
                holder_config=str(t / "holder/config.json"),
                holder_case_path=str(t / "holder/case.json"),
                holder_command=[
                    c["role_command"],
                    "holder",
                    "--",
                    c["python"],
                    "-m",
                    "router.soak_holder",
                ],
                assets=c["assets"],
                processes=procs,
                native_prover=asdict(p.native),
                gpus=p.gpus,
                log_origin=f"http://127.0.0.1:{ports['log']}",
                audit_origin=f"http://127.0.0.1:{ports['audit']}",
                audit_socket="unix://" + str(t / "ipc/auditor/audit.sock"),
                **{
                    k: limits[k]
                    for k in (
                        "network_timeout",
                        "poll_seconds",
                        "archive_drain_seconds",
                        "resource_poll_seconds",
                        "max_observation_gap_seconds",
                        "response_cap",
                    )
                },
            ),
        )
        runner = Command(
            "runner",
            "runner",
            (c["python"], "-m", "soak.runner", "--config", str(config)),
            Path(c["source"]),
        )
        children.start(runner, t / "runner/collector.log")
        while True:
            children.check(stop)
            status = children.live["runner"].poll()
            if status is not None:
                if status >= 0 or not _archive_recoverable(
                    t / "runner/journal.db", limits["archive_drain_seconds"]
                ):
                    return status
                # A signalled collector may resume only the already-finished interval's GETs.
                children.start(
                    Command(
                        "runner", "runner", (*runner.argv, "--archive-only"), runner.cwd
                    ),
                    t / "runner/collector.log",
                )
            stop.wait(limits["poll_seconds"])
    finally:
        children.shutdown(limits["shutdown_timeout"])


def deploy(root: Path, config: Path, stop: threading.Event) -> int:
    os.umask(0o077)
    _private_dir(root)
    fd = os.open(root / ".traffic.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "rb+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        c = private(config)
        p = physical(root, c, os.environ)
        ports = provision(root, c, p)
        return supervise(root, c, p, ports, stop)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    try:
        return deploy(args.root, args.config, stop)
    except (
        KeyError,
        ValueError,
        TypeError,
        RuntimeError,
        OSError,
        http.client.HTTPException,
        subprocess.TimeoutExpired,
    ) as exc:
        print("M4 traffic deployment stopped:", type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
