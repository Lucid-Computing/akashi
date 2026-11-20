import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from engine.adapter import EngineUnavailable
from engine.process_log import ProcessLog
from engine.transport import EngineClient


class PipeTests(unittest.TestCase):
    def setUp(self) -> None:
        code = "import sys;sys.stdout.buffer.write(b'boot\\n');sys.stdout.buffer.flush();sys.stdin.buffer.read()"
        self.child = subprocess.Popen(
            [sys.executable, "-u", "-c", code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        assert self.child.stdout is not None
        self.addCleanup(self.child.stdout.close)
        assert self.child.stdin is not None
        self.addCleanup(self.child.stdin.close)
        self.addCleanup(self.child.wait)
        self.addCleanup(self.child.terminate)
        self.captured = threading.Event()
        self.log = ProcessLog(
            self.child,
            "process-id",
            lambda _: self.captured.set(),
            max_line_bytes=1024,
            checkpoint_timeout=2,
        )
        self.addCleanup(self.log.close)
        self.assertTrue(self.captured.wait(2))

    def test_clean_checkpoint_and_dead_child_cannot_close_new_window(self) -> None:
        start = self.log.begin()
        clean = self.log.finish(start)
        self.assertTrue(clean.covered)
        self.assertFalse(clean.integrity_error)
        self.child.terminate()
        self.child.wait()
        with self.assertRaises(EngineUnavailable):
            self.log.finish(start)

    def test_warning_and_incomplete_line_on_a_live_pipe(self) -> None:
        read_fd, write_fd = os.pipe()
        with (
            os.fdopen(read_fd, "rb") as reader,
            os.fdopen(write_fd, "wb", buffering=0) as writer,
        ):
            # A second child writes to a distinct, directly captured pipe.
            child = subprocess.Popen(
                [sys.executable, "-c", "import sys;sys.stdin.buffer.read()"],
                stdin=subprocess.PIPE,
                stdout=writer,
                stderr=writer,
            )
            child.stdout = reader
            seen = threading.Event()
            log = ProcessLog(
                child,
                "second",
                lambda _: seen.set(),
                max_line_bytes=1024,
                checkpoint_timeout=2,
            )
            try:
                start = log.begin()
                writer.write(
                    b"WARNING vLLM served the token at position 8, but the integer model chose another one.\n"
                )
                self.assertTrue(seen.wait(2))
                self.assertTrue(log.finish(start).integrity_error)
                again = log.begin()
                writer.write(b"ERR")
                with self.assertRaises(EngineUnavailable):
                    log.finish(again)
                writer.write(b"OR range check failed\n")
                self.assertTrue(log.finish(again).integrity_error)
            finally:
                child.terminate()
                child.wait()
                assert child.stdin
                child.stdin.close()
                log.close()


@unittest.skipUnless(
    shutil.which("openssl"), "ephemeral TLS fixtures require OpenSSL CLI"
)
class TokenTransportTests(unittest.TestCase):
    def test_authenticated_buffered_token_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            openssl = shutil.which("openssl")
            assert openssl
            # A disposable self-signed peer on both ends isolates the buffered vLLM wire contract.
            config = root / "peer.cnf"
            config.write_text(
                "[req]\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\n[ext]\n"
                "subjectAltName=IP:127.0.0.1\nsubjectKeyIdentifier=hash\n"
                "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign\n"
            )
            pem, key = root / "peer.pem", root / "peer.key"
            subprocess.run(
                [
                    openssl,
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
                    "/CN=loopback-fixture",
                    "-keyout",
                    str(key),
                    "-out",
                    str(pem),
                ],
                check=True,
                capture_output=True,
            )
            received: list[dict[str, object]] = []
            responses: list[dict[str, object]] = []

            class Endpoint(BaseHTTPRequestHandler):
                def do_POST(self) -> None:
                    self.send_response(200)
                    self.end_headers()
                    received.append(
                        json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    )
                    self.wfile.write(json.dumps(responses.pop(0)).encode())

                def log_message(self, format: str, *args: object) -> None:
                    pass

            with HTTPServer(("127.0.0.1", 0), Endpoint) as server:
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.load_cert_chain(pem, key)
                tls.load_verify_locations(pem)
                tls.verify_mode = ssl.CERT_REQUIRED
                server.socket = tls.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    client = EngineClient(
                        "127.0.0.1",
                        server.server_port,
                        model="maverick-int",
                        ca=pem,
                        cert=pem,
                        key=key,
                        margin_seconds=2,
                        max_response_bytes=8192,
                    )
                    good = {
                        "index": 0,
                        "finish_reason": "stop",
                        "prompt_token_ids": [200000, 1],
                        "token_ids": [7, 200001],
                    }
                    responses.append({"model": "maverick-int", "choices": [good]})
                    self.assertEqual(client.generate((200000, 1), 2), (7, 200001))
                    self.assertEqual(
                        received[-1],
                        {
                            "model": "maverick-int",
                            "prompt": [200000, 1],
                            "max_tokens": 2,
                            "return_token_ids": True,
                            "temperature": 0,
                            "stream": False,
                        },
                    )
                    for changes in (
                        {"prompt_token_ids": [200000, True]},
                        {"finish_reason": None},
                        {"token_ids": None},
                        {"token_ids": [202048]},
                        {"index": True},
                    ):
                        responses.append(
                            {"model": "maverick-int", "choices": [good | changes]}
                        )
                        with (
                            self.subTest(changes=changes),
                            self.assertRaises(EngineUnavailable),
                        ):
                            client.generate((200000, 1), 2)
                finally:
                    server.shutdown()
                    thread.join()
