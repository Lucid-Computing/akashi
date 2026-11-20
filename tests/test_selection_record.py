"""Selection evidence and custody against the authentic quicknet round 1,000,000."""

import json
import tempfile
import unittest
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path

from nacl.public import PrivateKey

from auditor.beacon import round_for, round_is_open, select_round
from auditor.selection_record import evaluate
from escrow.mailbox import AuditorInbox
from escrow.sampler import deliver_selected, resolve_logged_leaf
from escrow.store import Binding, EscrowStore
from log.receipt import leaf_hash
from tests.test_beacon import FIRST_SIG, GENESIS, INFO, LATER, LATER_SIG
from tests.test_log_store import preimage, store_at, wire_hash

_ROUND = 1_000_000
_OPENS = GENESIS + timedelta(seconds=3 * (_ROUND - 1))
_SERVED = _OPENS - timedelta(seconds=15)
_SERVED_WIRE = _SERVED.isoformat(timespec="milliseconds").replace("+00:00", "Z")
_PUBLIC_KEYS = {
    "leaf_index",
    "leaf_hash",
    "transcript_commitment",
    "beacon_round",
    "sampling_mode",
    "divisor",
    "status",
    "selected",
    "shadow_selected",
    "beacon_signature",
}


def leaf_for(t: int, mode: str = "live") -> dict[str, object]:
    pre = preimage(t) | {
        "beacon_round": _ROUND,
        "served_at": _SERVED_WIRE,
        "transcript_commitment": t.to_bytes(32, "big").hex(),
        "sampling_mode": mode,
    }
    return pre | {"leaf_index": 7, "leaf_hash": wire_hash(pre)}


def derive(
    leaf: Mapping[str, object],
    status: str | None = None,
    *,
    mode: str = "live",
    now: datetime = _OPENS,
    info: Mapping[str, object] | None = INFO,
    beacon: Mapping[str, object] | None = LATER,
    index: int = 7,
) -> dict[str, object]:
    return evaluate(
        index,
        leaf,
        mode=mode,
        now=now,
        chain_info=info,
        beacon=beacon,
        escrow_status=status,
    )


class SelectionRecordTests(unittest.TestCase):
    def test_independent_reference_decisions_for_historical_epoch(self) -> None:
        # tests/test_beacon.py records these Node SHA-256 first words for this real round.
        for t, word in ((0, 1067648162), (8, 1988721580), (1176, 2175411000)):
            for mode, divisor in (("live", 20), ("soak", 1)):
                with self.subTest(t=t, mode=mode):
                    status = "selected" if word % divisor == 0 else "unselected"
                    record = derive(leaf_for(t, mode), status, mode=mode)
                    self.assertEqual(record.keys(), _PUBLIC_KEYS)
                    self.assertEqual(record["status"], status)
                    self.assertEqual(record["divisor"], divisor)
                    self.assertIs(record["selected"], word % divisor == 0)
                    self.assertIs(record["shadow_selected"], word % 1000 == 0)
                    self.assertEqual(record["beacon_signature"], LATER_SIG)

    def test_future_round_withholding_and_missing_custody(self) -> None:
        leaf = leaf_for(8)
        early = _OPENS - timedelta(microseconds=1)
        for record in (
            derive(leaf, "selected", now=early),
            derive(leaf, "selected", info=None),
            derive(leaf, "selected", beacon=None),
        ):
            self.assertEqual(record["status"], "pending")
            for field in ("selected", "shadow_selected", "beacon_signature"):
                self.assertIsNone(record[field])
        for state in ("pending", "transferring", None):
            with self.subTest(state=state):
                record = derive(leaf, state)
                self.assertEqual(record["status"], "pending")
                self.assertIs(record["selected"], True)
                self.assertIs(record["shadow_selected"], False)
        # Unknown custody cannot assert the actual reason for an outage.
        self.assertNotIn("reason", derive(leaf, now=_SERVED + timedelta(days=1)))
        with self.assertRaises(ValueError):
            derive(leaf, now=_OPENS.replace(tzinfo=None))

    def test_reject_unbound_metadata_and_inconsistent_assertions(self) -> None:
        leaf = leaf_for(8)
        changed_round = leaf | {"beacon_round": _ROUND + 1}
        changed_round["leaf_hash"] = wire_hash(changed_round)
        for altered in (
            leaf | {"leaf_hash": "00" * 32},
            leaf
            | {
                "served_at": _OPENS.isoformat(timespec="milliseconds").replace(
                    "+00:00", "Z"
                )
            },
            leaf | {"salt": "a holder secret"},
            leaf | {"leaf_index": True},
            changed_round,
        ):
            with self.subTest(keys=altered.keys()), self.assertRaises(ValueError):
                derive(altered)
        with self.assertRaises(ValueError):
            derive(leaf, index=8)
        with self.assertRaises(ValueError):
            derive(leaf, mode="soak")
        with self.assertRaises(ValueError):
            derive(leaf, mode="unknown")
        for status in ("unselected", "untrusted/private"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                derive(leaf, status)
        for status in ("selected", "transferring"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                derive(leaf_for(0), status)

    def test_signed_round_required_even_for_soak(self) -> None:
        leaf = leaf_for(0, "soak")
        with self.assertRaises(ValueError):
            derive(leaf, "selected", mode="soak", info=INFO | {"hash": "aa" * 32})
        for beacon in (
            LATER | {"round": 1},
            LATER | {"randomness": "cc" * 32},
            {"round": _ROUND, "signature": FIRST_SIG},
        ):
            with self.subTest(beacon=beacon), self.assertRaises(ValueError):
                derive(leaf, "selected", mode="soak", beacon=beacon)

    def test_real_escrow_handoff_and_permanent_gap_after_outage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            now = _SERVED
            auditor = PrivateKey.generate()
            path = Path(directory)

            def open_store() -> EscrowStore:
                return EscrowStore(
                    path / "escrow.db",
                    wrapping_key=b"w" * 32,
                    auditor_public_key=bytes(auditor.public_key),
                    clock=lambda: now,
                )

            store = open_store()
            inbox = AuditorInbox(
                path / "inbox.db", auditor_private_key=bytes(auditor), clock=lambda: now
            )
            public_log = store_at(path / "log.db", now)
            for t in (0, 8, 1176):
                leaf = leaf_for(t)
                binding = Binding(
                    str(leaf["leaf_hash"]),
                    str(leaf["transcript_commitment"]),
                    _SERVED_WIRE,
                    _ROUND,
                    "live",
                )
                self.assertEqual(
                    store.stage(binding, b"private fixture transcript"), "pending"
                )
                del leaf["leaf_index"]
                public_log.append(leaf)
            now = _OPENS
            for index, expected in enumerate(("unselected", "transferring", "pending")):
                leaf = public_log.receipt(index)
                fixed_beacon = None if expected == "pending" else LATER
                status = resolve_logged_leaf(
                    store,
                    index,
                    INFO,
                    fixed_beacon,
                    read_verified_leaf=public_log.receipt,
                    leaf_hash=leaf_hash,
                    round_for=round_for,
                    round_is_open=round_is_open,
                    select_round=select_round,
                )
                self.assertEqual(status, expected)
                record = derive(leaf, status, index=index, beacon=fixed_beacon)
                self.assertEqual(
                    record["status"], "unselected" if index == 0 else "pending"
                )
                self.assertNotIn("private fixture transcript", json.dumps(record))
            selected = public_log.receipt(1)
            key = str(selected["leaf_hash"])
            self.assertEqual(deliver_selected(store, key, inbox.accept), "selected")
            self.assertEqual(
                derive(selected, store.status(key), index=1)["status"], "selected"
            )

            missed = public_log.receipt(2)
            key = str(missed["leaf_hash"])
            now = _SERVED + timedelta(minutes=5)
            restarted_store = open_store()
            self.assertEqual(restarted_store.status(key), "gap")
            gap = derive(
                missed, restarted_store.status(key), index=2, now=now, beacon=None
            )
            self.assertEqual(gap.keys(), _PUBLIC_KEYS | {"reason"})
            self.assertEqual(gap["status"], "gap")
            self.assertEqual(gap["reason"], "escrow_expired")
            self.assertIsNone(gap["selected"])
            returned = derive(missed, restarted_store.status(key), index=2, now=now)
            self.assertEqual(returned["status"], "gap")
            self.assertEqual(returned["reason"], gap["reason"])
            self.assertIs(returned["selected"], True)
            self.assertIs(returned["shadow_selected"], True)
