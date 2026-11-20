"""Exercise the shipped HAProxy policy with real TLS sessions and a loopback backend."""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import closing
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CONFIG = Path(__file__).resolve().parents[1] / "deploy/engine-proxy/engine-proxy.cfg"
HAPROXY = shutil.which(os.environ.get("HAPROXY", "haproxy"))
OPENSSL = shutil.which("openssl")


def make_certificates(directory: Path, openssl: str) -> str:
    """Issue ephemeral server, gateway and other-role credentials under one test CA."""

    def issue(*args: str) -> None:
        subprocess.run(
            [openssl, *args], cwd=directory, check=True, capture_output=True, timeout=30
        )

    (directory / "ca.cnf").write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\n[ext]\n"
        "subjectKeyIdentifier=hash\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
    )
    issue(
        "req",
        "-new",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-config",
        "ca.cnf",
        "-subj",
        "/CN=Test CA",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
    )
    for serial, role in enumerate(("proxy", "gateway", "other"), start=1):
        extensions = (
            "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1"
            if role == "proxy"
            else "extendedKeyUsage=clientAuth"
        )
        (directory / "leaf.cnf").write_text(
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
            f"basicConstraints=critical,CA:FALSE\n{extensions}\n"
        )
        issue(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            f"/CN={role}",
            "-keyout",
            f"{role}.key",
            "-out",
            f"{role}.csr",
        )
        issue(
            "x509",
            "-req",
            "-in",
            f"{role}.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-set_serial",
            str(serial),
            "-days",
            "1",
            "-extfile",
            "leaf.cnf",
            "-out",
            f"{role}.pem",
        )
    (directory / "server.pem").write_bytes(
        (directory / "proxy.pem").read_bytes() + (directory / "proxy.key").read_bytes()
    )
    gateway_der = ssl.PEM_cert_to_DER_cert((directory / "gateway.pem").read_text())
    return hashlib.sha256(gateway_der).hexdigest()


class RecordingBackend(ThreadingHTTPServer):
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, bytes]] = []
        super().__init__(("127.0.0.1", 0), BackendHandler)


class BackendHandler(BaseHTTPRequestHandler):
    server: RecordingBackend

    def handle_allowed_request(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append((self.command, self.path, body))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"engine fixture")

    do_GET = handle_allowed_request
    do_POST = handle_allowed_request

    def log_message(self, format: str, *args: object) -> None:
        pass


@unittest.skipUnless(
    HAPROXY and OPENSSL, "engine proxy test requires HAProxy and openssl"
)
class EngineProxyTests(unittest.TestCase):
    directory: Path
    backend: RecordingBackend
    port: int
    process: subprocess.Popen[bytes]

    @classmethod
    def setUpClass(cls) -> None:
        assert HAPROXY is not None and OPENSSL is not None
        scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(scratch.cleanup)
        cls.directory = Path(scratch.name)
        fingerprint = make_certificates(cls.directory, OPENSSL)
        cls.backend = RecordingBackend()
        cls.addClassCleanup(cls.backend.server_close)
        threading.Thread(target=cls.backend.serve_forever, daemon=True).start()
        cls.addClassCleanup(cls.backend.shutdown)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            cls.port = int(reserve.getsockname()[1])
        environment = dict(
            os.environ,
            VIG_PROXY_LISTEN=f"127.0.0.1:{cls.port}",
            VIG_PROXY_CONNECT_TIMEOUT="5s",
            VIG_PROXY_IO_TIMEOUT="5s",
            VIG_PROXY_CERT=str(cls.directory / "server.pem"),
            VIG_GATEWAY_CA=str(cls.directory / "ca.pem"),
            VIG_GATEWAY_CERT_SHA256=fingerprint,
            VIG_ENGINE_PORT=str(cls.backend.server_port),
        )
        subprocess.run(
            [HAPROXY, "-c", "-f", str(CONFIG)], env=environment, check=True, timeout=10
        )
        with (cls.directory / "proxy.log").open("wb") as log:
            cls.process = subprocess.Popen(
                [HAPROXY, "-db", "-f", str(CONFIG)],
                env=environment,
                stdout=log,
                stderr=log,
            )
        cls.addClassCleanup(cls.stop_proxy)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if cls.process.poll() is not None:
                raise RuntimeError((cls.directory / "proxy.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.02)
        raise TimeoutError("HAProxy did not start")

    @classmethod
    def stop_proxy(cls) -> None:
        cls.process.terminate()
        cls.process.wait(timeout=10)

    def connection(self, role: str | None, timeout: float = 3) -> HTTPSConnection:
        context = ssl.create_default_context(cafile=str(self.directory / "ca.pem"))
        if role is not None:
            context.load_cert_chain(
                self.directory / f"{role}.pem", self.directory / f"{role}.key"
            )
        return HTTPSConnection("127.0.0.1", self.port, context=context, timeout=timeout)

    def request(
        self, role: str | None, method: str, target: str, body: bytes = b""
    ) -> tuple[int, bytes]:
        with closing(self.connection(role)) as connection:
            connection.request(method, target, body=body)
            response = connection.getresponse()
            return response.status, response.read()

    def setUp(self) -> None:
        self.backend.requests.clear()

    def test_gateway_only_reaches_both_exact_routes(self) -> None:
        body = b'{"prompt":[7]}'
        self.assertEqual(
            self.request("gateway", "GET", "/health"), (200, b"engine fixture")
        )
        self.assertEqual(
            self.request("gateway", "POST", "/v1/completions", body),
            (200, b"engine fixture"),
        )
        for method, target in (
            ("GET", "/metrics"),
            ("POST", "/invocations"),
            ("POST", "/generative_scoring"),
            ("GET", "/v1/models"),
            ("POST", "/health"),
            ("GET", "/v1/completions"),
            ("GET", "/health/"),
            ("GET", "/health?debug=1"),
        ):
            with self.subTest(method=method, target=target):
                self.assertEqual(self.request("gateway", method, target)[0], 404)
        self.assertEqual(
            self.backend.requests,
            [("GET", "/health", b""), ("POST", "/v1/completions", body)],
        )

    def test_other_trusted_role_and_missing_certificate_never_reach_backend(
        self,
    ) -> None:
        self.assertEqual(self.request("other", "GET", "/health")[0], 403)
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.request(None, "GET", "/health")
        self.assertEqual(self.backend.requests, [])

    def test_only_one_active_connection(self) -> None:
        with closing(self.connection("gateway")) as first:
            first.connect()
            with (
                closing(self.connection("gateway", timeout=0.25)) as second,
                self.assertRaises(TimeoutError),
            ):
                second.connect()
        self.assertEqual(
            self.request("gateway", "GET", "/health"), (200, b"engine fixture")
        )
