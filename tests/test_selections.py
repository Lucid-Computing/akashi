"""Public selection pages over genuinely signed log history and quicknet randomness."""

import hashlib
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import Mock

from auditor.selections import Selections, SelectionsApp
from log.monitor import LogMonitor
from log.receipt import leaf_hash
from log.store import MerkleLog
from tests.test_beacon import GENESIS, INFO, LATER
from tests.test_log_store import KEY, KEY_ID, LOG_ID
from tests.test_selection_record import leaf_for


class SelectionPages(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.now = GENESIS + timedelta(seconds=3 * (1_000_000 - 1))
        self.log = MerkleLog(
            self.root / "log",
            log_id=LOG_ID,
            log_key_id=KEY_ID,
            signing_key=KEY,
            leaf_hash=leaf_hash,
            clock=lambda: self.now,
        )
        self.monitor = LogMonitor(
            self.root / "monitor",
            log_id=LOG_ID,
            lookup_key=lambda *_: KEY.public_key().public_bytes_raw(),
            clock=lambda: self.now,
        )
        self.state = self.open_state()

    def open_state(self) -> Selections:
        return Selections(
            self.root / "selections", log_id=LOG_ID, clock=lambda: self.now
        )

    def append(self, number: int, mode: str) -> str:
        p = leaf_for(number, mode)
        p.pop("leaf_index")
        digest = p.pop("leaf_hash")
        self.log.append(p)
        return str(digest)

    def observe(self) -> None:
        def read(uri: str) -> object:
            if uri == "sth":
                return self.log.head()
            if uri.startswith("receipts/"):
                return self.log.receipt(int(uri.split("/")[1]))
            bounds = uri.split("=")
            old = int(bounds[1].split("&")[0])
            new = int(bounds[2])
            return {
                "from": old,
                "to": new,
                "consistency_path": [h.hex() for h in self.log.consistency(old, new)],
            }

        self.monitor.observe(read)

    def test_http_cursor_independent_recomputation_and_immutable_epochs(self) -> None:
        self.state.activate(0, "live")
        self.state.activate(1, "soak")
        self.append(1, "live")
        self.append(2, "soak")
        self.observe()
        status = {}
        for i in range(2):
            leaf = self.log.receipt(i)
            k = hashlib.sha256(
                bytes.fromhex(str(leaf["transcript_commitment"]))
                + (1_000_000).to_bytes(8, "big")
                + bytes.fromhex(str(LATER["signature"]))
            ).digest()
            selected = int.from_bytes(k[:4], "big") % (20 if i == 0 else 1) == 0
            status[str(leaf["leaf_hash"])] = "selected" if selected else "unselected"
        self.state.sync(
            self.monitor,
            custody=status.get,
            chain_info=INFO,
            read_beacon=lambda _: LATER,
            limit=5,
        )
        app = SelectionsApp(self.open_state(), page_size=1)

        def page(query: str) -> tuple[str, dict[str, Any]]:
            start = Mock()
            body = app(
                {
                    "PATH_INFO": "/audit/v1/selections",
                    "REQUEST_METHOD": "GET",
                    "QUERY_STRING": query,
                },
                start,
            )
            return start.call_args.args[0], json.loads(b"".join(body))

        _, one = page("")
        self.assertEqual(one["checkpoint"], self.log.head())
        self.assertEqual((one["indexed_size"], one["next_cursor"]), (2, 1))
        _, two = page("cursor=1")
        self.assertIsNone(two["next_cursor"])
        self.assertEqual([e["sampling_mode"] for e in two["epochs"]], ["live", "soak"])
        for data in (one, two):
            rec = data["selections"][0]
            self.assertEqual(rec["status"], status[rec["leaf_hash"]])
            bits = int.from_bytes(
                hashlib.sha256(
                    bytes.fromhex(rec["transcript_commitment"])
                    + rec["beacon_round"].to_bytes(8, "big")
                    + bytes.fromhex(rec["beacon_signature"])
                ).digest()[:4],
                "big",
            )
            self.assertEqual(
                (rec["selected"], rec["shadow_selected"]),
                (bits % rec["divisor"] == 0, bits % 1000 == 0),
            )
        for query in ("cursor=-1", "cursor=1&cursor=2", "token=private"):
            self.assertEqual(page(query)[0], "400 Bad Request")
        with self.assertRaises(ValueError):
            self.open_state().activate(0, "soak")

    def test_gap_visible_through_outage_then_persists_with_late_reproducible_math(
        self,
    ) -> None:
        self.state.activate(0, "soak")
        self.append(1, "soak")
        self.observe()
        self.state.sync(
            self.monitor,
            custody=lambda _: "gap",
            chain_info=INFO,
            read_beacon=Mock(side_effect=OSError()),
            limit=1,
        )
        row = self.state.page(0, 1)["selections"][0]
        self.assertEqual(
            (row["status"], row["reason"], row["selected"]),
            ("gap", "escrow_expired", None),
        )
        restart = self.open_state()
        restart.sync(
            self.monitor,
            custody=lambda _: "selected",
            chain_info=INFO,
            read_beacon=lambda _: LATER,
            limit=1,
        )
        row = restart.page(0, 1)["selections"][0]
        self.assertEqual((row["status"], row["selected"]), ("gap", True))

    def test_signed_epoch_mismatch_rolls_back_whole_batch(self) -> None:
        self.state.activate(0, "live")
        self.append(1, "live")
        self.append(2, "soak")
        self.observe()
        with self.assertRaises(ValueError):
            self.state.sync(
                self.monitor,
                custody=lambda _: None,
                chain_info=INFO,
                read_beacon=lambda _: LATER,
                limit=5,
            )
        self.assertEqual(self.state.page(0, 5)["indexed_size"], 0)

    def test_cached_public_signature_survives_beacon_outage_during_transfer(
        self,
    ) -> None:
        self.state.activate(0, "soak")
        self.append(1, "soak")
        self.observe()
        self.state.sync(
            self.monitor,
            custody=lambda _: "transferring",
            chain_info=INFO,
            read_beacon=lambda _: LATER,
            limit=1,
        )
        network = Mock(
            side_effect=AssertionError("A previously verified signature is sufficient")
        )
        restart = self.open_state()
        restart.sync(
            self.monitor,
            custody=lambda _: "selected",
            chain_info=None,
            read_beacon=network,
            limit=1,
        )
        self.assertEqual(restart.page(0, 1)["selections"][0]["status"], "selected")
        network.assert_not_called()
