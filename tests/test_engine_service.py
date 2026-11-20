"""Provider-only launch and independent gateway attachment to the observed child."""

import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import AbstractContextManager, ExitStack
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from engine.adapter import Canary, EngineUnavailable
from engine.control import ControlClient, ControlServer
from engine.launch import (
    FILE_LINE,
    TENSOR_LINE,
    LaunchConfig,
    StartedEngine,
    StartupTracker,
)
from engine.service import EngineObservation, attach_engine, observe_engine
from engine.transport import EngineClient

# A harmless loopback token server. It receives neither gateway nor proxy TLS material.
CHILD = """
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
class Tokens(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.send_response(200 if self.path == '/health' else 404)
        self.end_headers()
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        prompt = request['prompt']
        reply = {'model': request['model'], 'choices': [{'index': 0, 'finish_reason': 'length',
                 'prompt_token_ids': prompt, 'token_ids': [prompt[0] + 10]}]}
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(reply).encode())
server = HTTPServer(('127.0.0.1', 0), Tokens)
Path(sys.argv[1]).write_text(str(server.server_port))
print(sys.argv[2], flush=True)
print(sys.argv[3], flush=True)
server.serve_forever()
"""


class ServiceTests(unittest.TestCase):
    def launch_child(self, program: str) -> StartedEngine:
        scratch = tempfile.TemporaryDirectory()
        root = Path(scratch.name)
        self.port_file = root / "port"
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-u",
                "-c",
                program,
                str(self.port_file),
                FILE_LINE.decode(),
                TENSOR_LINE.decode(),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            cwd=root,
            env={},
        )
        instance = "fresh-fixture"
        started = StartedEngine(
            process,
            instance,
            StartupTracker(instance),
            tuple(Canary((i,), 1, (i + 10,)) for i in (1, 2, 3)),
            scratch,
            1.0,
        )
        self.addCleanup(started.close)
        return started

    @staticmethod
    def observe() -> AbstractContextManager[EngineObservation]:
        return observe_engine(
            Mock(spec=LaunchConfig),
            startup_timeout=2,
            health_poll_seconds=0.01,
            checkpoint_timeout=1,
            max_log_line_bytes=4096,
        )

    @unittest.skipUnless(shutil.which("openssl"), "TLS fixtures require OpenSSL")
    def test_provider_boots_before_gateway_credentials_exist_and_canaries_use_mtls(
        self,
    ) -> None:
        started = self.launch_child(CHILD)
        with ExitStack() as resources:
            resources.enter_context(patch("engine.service.start", return_value=started))
            with patch.object(
                ssl.SSLContext,
                "load_cert_chain",
                side_effect=AssertionError("provider requested a TLS key"),
            ):
                observation = resources.enter_context(self.observe())
                evidence, goldens = observation.startup()
            self.assertEqual(evidence.instance, started.instance)
            self.assertEqual(tuple(g.prompt for g in goldens), ((1,), (2,), (3,)))
            control_dir = Path(resources.enter_context(tempfile.TemporaryDirectory()))
            socket_path = control_dir / "observation.sock"
            resources.enter_context(
                ControlServer(
                    socket_path,
                    gateway_uid=os.geteuid(),
                    gateway_gid=os.getegid(),
                    timeout=2,
                    instance=evidence.instance,
                    evidence=lambda: observation.startup()[0],
                    canaries=goldens,
                    begin=observation.begin,
                    finish=observation.finish,
                )
            )
            gateway_view = ControlClient(
                socket_path, provider_uid=os.geteuid(), timeout=2
            )
            # Both keypairs first exist after the provider measured its own startup.
            seen: list[tuple[str, tuple[int, ...]]] = []
            with tempfile.TemporaryDirectory() as tls_dir:
                certs = Path(tls_dir)
                for name in ("gateway", "proxy"):
                    fixture_cert(certs, name)
                server = make_proxy(certs, int(self.port_file.read_text()), seen)
                thread = threading.Thread(
                    target=server.serve_forever,
                    kwargs={"poll_interval": 0.02},
                    daemon=True,
                )
                thread.start()
                try:
                    client = EngineClient(
                        "127.0.0.1",
                        server.server_port,
                        model="maverick-int",
                        ca=certs / "proxy.pem",
                        cert=certs / "gateway.pem",
                        key=certs / "gateway.key",
                        margin_seconds=2,
                        max_response_bytes=8192,
                    )
                    adapter = attach_engine(
                        client,
                        gateway_view,
                        startup_timeout=2,
                        health_poll_seconds=0.05,
                    )
                    self.assertTrue(adapter.ready)
                    self.assertEqual(
                        [ids for route, ids in seen if route == "/v1/completions"],
                        [(1,), (2,), (3,)],
                    )
                    result = adapter.generate((18,), 1)
                    self.assertEqual(result.tokens, (28,))
                    self.assertTrue(result.integrity_window_closed)
                    self.assertIn(("/health", ()), seen)
                    self.assertEqual(seen[-1], ("/v1/completions", (18,)))
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join()
        self.assertIsNotNone(started.process.returncode)

    def test_exited_child_supplies_no_gates_even_with_both_markers(self) -> None:
        started = self.launch_child(
            "import sys; print(sys.argv[2]); print(sys.argv[3])"
        )
        started.process.wait(timeout=2)
        client = Mock(spec=EngineClient)
        client.healthy.return_value = True
        with (
            patch("engine.service.start", return_value=started),
            self.assertRaises(EngineUnavailable),
            self.observe() as observation,
        ):
            attach_engine(
                client, observation, startup_timeout=1, health_poll_seconds=0.01
            )
        client.generate.assert_not_called()

    def test_failed_proxy_health_prevents_canaries_on_a_live_observation(self) -> None:
        started = self.launch_child(CHILD)
        client = Mock(spec=EngineClient)
        client.healthy.return_value = False
        with (
            patch("engine.service.start", return_value=started),
            self.observe() as observation,
            self.assertRaises(EngineUnavailable),
        ):
            attach_engine(
                client, observation, startup_timeout=0.05, health_poll_seconds=0.01
            )
        client.generate.assert_not_called()


def fixture_cert(directory: Path, name: str) -> None:
    # The disposable CAs are separate identities and trust anchors for this loopback test.
    config = directory / (name + ".cnf")
    config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\n[ext]\n"
        "subjectAltName=IP:127.0.0.1\nsubjectKeyIdentifier=hash\n"
        "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign\n"
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-config",
            str(config),
            "-subj",
            "/CN=" + name,
            "-out",
            str(directory / (name + ".pem")),
            "-keyout",
            str(directory / (name + ".key")),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )


def make_proxy(
    directory: Path, backend: int, seen: list[tuple[str, tuple[int, ...]]]
) -> HTTPServer:
    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def forward(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            ids = tuple(json.loads(body)["prompt"]) if body else ()
            seen.append((self.path, ids))
            connection = HTTPConnection("127.0.0.1", backend, timeout=2)
            try:
                connection.request(self.command, self.path, body)
                response = connection.getresponse()
                data = response.read()
                self.send_response(response.status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            finally:
                connection.close()

        do_GET = do_POST = forward

    server = HTTPServer(("127.0.0.1", 0), Proxy)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(directory / "proxy.pem", directory / "proxy.key")
    tls.load_verify_locations(cafile=str(directory / "gateway.pem"))
    tls.verify_mode = ssl.CERT_REQUIRED
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    return server
