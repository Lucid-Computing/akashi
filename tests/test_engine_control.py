"""Exercise the real provider observation socket without exposing gateway TLS keys."""

import json
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from engine.adapter import Canary, Cursor, EngineUnavailable, StartupEvidence, Window
from engine.control import ControlClient, ControlServer

EVIDENCE = StartupEvidence("fresh-process", "ab" * 32, True, True, True, True)
CANARIES = tuple(Canary((i,), 1, (i + 1,)) for i in range(3))


class ControlTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "control.sock"
        self.uid = os.geteuid()
        self.started = Cursor(EVIDENCE.instance, 7)
        self.closed = Window(self.started, Cursor(EVIDENCE.instance, 8), True, False)
        self.evidence = Mock(return_value=EVIDENCE)
        self.begin = Mock(return_value=self.started)
        self.finish = Mock(return_value=self.closed)

    def server(self, uid: int | None = None) -> ControlServer:
        return ControlServer(
            self.path,
            gateway_uid=self.uid if uid is None else uid,
            gateway_gid=os.getegid(),
            timeout=2,
            instance=EVIDENCE.instance,
            evidence=self.evidence,
            canaries=CANARIES,
            begin=self.begin,
            finish=self.finish,
        )

    def client(self, uid: int | None = None) -> ControlClient:
        return ControlClient(
            self.path, provider_uid=self.uid if uid is None else uid, timeout=2
        )

    def test_authenticated_peer_and_provider_wide_window_lease(self) -> None:
        one, two = self.client(), self.client()
        with self.server():
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o660)
            self.assertEqual(one.startup(), (EVIDENCE, CANARIES))
            self.assertEqual(two.startup(), (EVIDENCE, CANARIES))
            start = one.begin()
            self.assertEqual(start, self.started)
            with self.assertRaises(EngineUnavailable):
                two.begin()
            with self.assertRaises(EngineUnavailable):
                two.finish(start)
            self.finish.assert_not_called()
            self.assertEqual(one.finish(start), self.closed)
            # The reader returned the same position during a quiet interval. A
            # lease from the previous window still cannot close the current one.
            self.assertEqual(two.begin(), start)
            with self.assertRaises(EngineUnavailable):
                one.finish(start)
            self.assertEqual(two.finish(start), self.closed)
        self.assertFalse(self.path.exists())
        with self.assertRaises(EngineUnavailable):
            one.startup()

    def test_kernel_credential_checks_on_both_ends(self) -> None:
        with self.server(self.uid + 1), self.assertRaises(EngineUnavailable):
            self.client().startup()
        self.evidence.assert_not_called()
        with self.server(), self.assertRaises(EngineUnavailable):
            self.client(self.uid + 1).startup()
        self.evidence.assert_not_called()

    def test_dropped_request_does_not_create_a_window(self) -> None:
        with self.server():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.connect(str(self.path))
                conn.sendall((100).to_bytes(4, "big") + b"{")
            client = self.client()
            client.startup()
            self.assertEqual(client.finish(client.begin()), self.closed)
            self.assertEqual(self.begin.call_count, 1)

    def test_dropped_begin_response_keeps_uncertain_window_reserved(self) -> None:
        with self.server():
            body = json.dumps({"op": "begin", "instance": EVIDENCE.instance}).encode()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.connect(str(self.path))
                conn.sendall(len(body).to_bytes(4, "big") + body)
            client = self.client()
            client.startup()
            with self.assertRaises(EngineUnavailable):
                client.begin()
            self.assertEqual(self.begin.call_count, 1)

    def test_uncertain_finish_quarantines_original_process(self) -> None:
        for close in (
            None,
            Window(self.started, self.started, False, False),
            Window(self.started, self.started, True, True),
        ):
            with self.subTest(window=close), self.server():
                self.finish.return_value = close
                client = self.client()
                client.startup()
                start = client.begin()
                if close is None:
                    with self.assertRaises(EngineUnavailable):
                        client.finish(start)
                else:
                    self.assertEqual(client.finish(start), close)
                with self.assertRaises(EngineUnavailable):
                    self.client().startup()
                with self.assertRaises(EngineUnavailable):
                    client.begin()

    def test_existing_file_and_replacement_survive_server_cleanup(self) -> None:
        self.path.write_text("provisioned file")
        with self.assertRaises(OSError), self.server():
            self.fail("server bound an existing path")
        self.assertEqual(self.path.read_text(), "provisioned file")
        self.path.unlink()
        with self.server():
            self.path.unlink()
            self.path.write_text("replacement")
        self.assertEqual(self.path.read_text(), "replacement")
