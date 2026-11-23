"""The soak hands off only after verifying the log and exact signed beacon round."""

import os
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch
from wsgiref.simple_server import make_server

from nacl.public import PrivateKey

from escrow.mailbox import AuditorInbox
from escrow.store import Binding, EscrowStore
from log.http import LogApp
from log.monitor import LogMonitor
from log.receipt import leaf_hash
from log.store import MerkleLog
from pickup.http import _QuietHandler
from soak.audit_service import accept_carrier
from soak.gateway_service import _custody
from soak.settings import response
from tests.test_beacon import GENESIS, INFO, LATER
from tests.test_log_store import KEY, KEY_ID, LOG_ID, preimage


class SoakGatewayTests(unittest.TestCase):
    def test_signed_log_and_authenticated_draw_hand_off_same_private_record(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            when = GENESIS + timedelta(seconds=(1_000_000 - 2) * 3 - 13)
            ready = when + timedelta(minutes=1)
            issued = when.isoformat(timespec="milliseconds").replace("+00:00", "Z")
            receipt = {
                **preimage(0),
                "sampling_mode": "soak",
                "served_at": issued,
                "beacon_round": 1_000_000,
            }
            binding = Binding(
                leaf_hash(receipt),
                str(receipt["transcript_commitment"]),
                issued,
                1_000_000,
                "soak",
            )
            recipient = PrivateKey.generate()
            escrow = EscrowStore(
                root / "escrow.db",
                wrapping_key=os.urandom(32),
                auditor_public_key=bytes(recipient.public_key),
                clock=lambda: ready,
            )
            inbox = AuditorInbox(
                root / "inbox.db",
                auditor_private_key=bytes(recipient),
                clock=lambda: ready,
            )
            escrow.stage(binding, b"holder supplied evidence")
            log = MerkleLog(
                root / "log.db",
                log_id=LOG_ID,
                log_key_id=KEY_ID,
                signing_key=KEY,
                leaf_hash=leaf_hash,
                clock=lambda: when,
            )
            log.append(receipt)
            history = LogMonitor(
                root / "monitor.db",
                log_id=LOG_ID,
                lookup_key=lambda _role, _kid: KEY.public_key().public_bytes_raw(),
                clock=lambda: ready,
            )
            accepted = threading.Event()
            stop = threading.Event()

            def read(origin: str, route: str, **kwargs: Any) -> tuple[int, Any]:
                if route == "/internal/escrow/accept":
                    digest = accept_carrier(inbox, kwargs["data"])
                    accepted.set()
                    return 200, {"leaf_hash": digest}
                return response(origin, route, **kwargs)

            with make_server(
                "127.0.0.1",
                0,
                LogApp(log, gateway_identity="soak"),
                handler_class=_QuietHandler,
            ) as server:
                public = threading.Thread(target=server.serve_forever)
                public.start()
                conf = {
                    "network_timeout": 3,
                    "response_cap": 20000,
                    "log_origin": f"http://127.0.0.1:{server.server_port}",
                    "audit_socket": "unix:///fixture",
                    "poll_seconds": 0.02,
                }
                with (
                    patch("soak.gateway_service.response", side_effect=read),
                    patch(
                        "soak.gateway_service.quicknet",
                        side_effect=lambda path, **_: INFO if path == "info" else LATER,
                    ),
                ):
                    thread = threading.Thread(
                        target=_custody, args=(conf, escrow, history, stop)
                    )
                    thread.start()
                    try:
                        self.assertTrue(
                            accepted.wait(8), "custody did not reach the auditor"
                        )
                    finally:
                        stop.set()
                        thread.join(5)
                        server.shutdown()
                        public.join(5)
            self.assertEqual(escrow.status(binding.leaf_hash), "selected")
            self.assertEqual(inbox.read(binding), b"holder supplied evidence")
