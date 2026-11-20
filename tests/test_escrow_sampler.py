import hashlib
import json
import multiprocessing
import tempfile
import threading
import unittest
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from nacl.public import PrivateKey

from escrow.sampler import ExpiryWorker, deliver_selected, resolve_logged_leaf
from escrow.store import Binding, EscrowStore, Transfer


def public_hash(leaf: Mapping[str, object]) -> str:
    fields = {k: v for k, v in leaf.items() if k not in {"leaf_hash", "leaf_index"}}
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


def stage_elsewhere(
    path: Path, public_key: bytes, binding: Binding, clock: datetime
) -> None:
    other = EscrowStore(
        path,
        wrapping_key=bytes(range(32)),
        auditor_public_key=public_key,
        clock=lambda: clock,
    )
    other.stage(binding, b"second fixture")


class SamplerTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.served = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.now = self.served
        self.path = Path(temp.name, "escrow.db")
        self.auditor = bytes(PrivateKey.generate().public_key)
        self.store = EscrowStore(
            self.path,
            wrapping_key=bytes(range(32)),
            auditor_public_key=self.auditor,
            clock=lambda: self.now,
        )
        self.leaf: dict[str, object] = {
            "leaf_index": 3,
            "beacon_round": 20,
            "transcript_commitment": "11" * 32,
            "served_at": "2026-01-01T00:00:00.000Z",
            "sampling_mode": "live",
        }
        self.digest = public_hash(self.leaf)
        self.leaf["leaf_hash"] = self.digest
        self.binding = Binding(
            leaf_hash=self.digest,
            transcript_commitment="11" * 32,
            served_at="2026-01-01T00:00:00.000Z",
            beacon_round=20,
            sampling_mode="live",
        )
        self.store.stage(self.binding, b"private fixture")
        self.source = Mock(return_value=self.leaf)
        self.selector = Mock(return_value={1: True, 20: False, 1000: False})
        self.opened = Mock(return_value=True)
        self.assignment = Mock(return_value=20)

    def resolve(self, beacon: Mapping[str, object] | None) -> str:
        return resolve_logged_leaf(
            self.store,
            3,
            {},
            beacon,
            read_verified_leaf=self.source,
            leaf_hash=public_hash,
            round_for=self.assignment,
            round_is_open=self.opened,
            select_round=self.selector,
        )

    def test_fixed_round_and_authenticated_selection_control_transfer(self) -> None:
        self.opened.return_value = False
        self.assertEqual(self.resolve({}), "pending")
        self.selector.assert_not_called()
        self.opened.return_value = True
        self.selector.side_effect = ValueError("invalid signature")
        with self.assertRaises(ValueError):
            self.resolve({})
        self.assertEqual(self.store.status(self.digest), "pending")
        self.selector.side_effect = None
        self.assertEqual(self.resolve({}), "unselected")
        self.selector.assert_called_with(bytes.fromhex("11" * 32), 20, {}, {})
        self.assertIsNone(self.store.transfer(self.digest))

    def test_wrong_leaf_or_assignment_cannot_release_material(self) -> None:
        self.source.return_value = {**self.leaf, "leaf_index": 2}
        with self.assertRaises(ValueError):
            self.resolve({})
        self.source.return_value = self.leaf
        self.assignment.return_value = 19
        with self.assertRaises(ValueError):
            self.resolve({})
        self.selector.assert_not_called()
        self.assertEqual(self.store.status(self.digest), "pending")

    def test_missing_beacon_does_not_restart_the_clock(self) -> None:
        self.now += timedelta(minutes=4)
        self.assertEqual(self.resolve(None), "pending")
        self.now += timedelta(minutes=1)
        self.assertEqual(self.resolve(None), "gap")
        self.assertEqual(self.resolve({}), "gap")
        self.selector.assert_not_called()

    def test_expiry_worker_purges_while_idle_and_stops(self) -> None:
        # The fixture clock jumps, so notify the worker as the deployment clock advances.
        expired = threading.Event()
        original = self.store.sweep

        def sweep() -> int:
            count = original()
            if count:
                expired.set()
            return count

        patched = patch.object(self.store, "sweep", side_effect=sweep)
        patched.start()
        self.addCleanup(patched.stop)
        worker = ExpiryWorker(self.store)
        thread = threading.Thread(target=worker.run, daemon=True)
        thread.start()
        try:
            self.now += timedelta(minutes=5)
            self.store.changed.set()
            self.assertTrue(expired.wait(3))
        finally:
            worker.stop()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.store.status(self.digest), "gap")

    def test_lost_auditor_ack_retries_original_job(self) -> None:
        self.selector.return_value = {1: True, 20: True, 1000: False}
        self.assertEqual(self.resolve({}), "transferring")
        accepted: dict[str, Transfer] = {}

        def lose_reply(transfer: Transfer) -> str:
            accepted[self.digest] = transfer
            raise ConnectionError("response lost")

        with self.assertRaises(ConnectionError):
            deliver_selected(self.store, self.digest, lose_reply)
        self.assertEqual(self.store.status(self.digest), "transferring")
        with self.assertRaises(ValueError):
            deliver_selected(self.store, self.digest, lambda item: "ff" * 32)

        def confirm(transfer: Transfer) -> str:
            self.assertEqual(transfer, accepted[self.digest])
            return self.digest

        self.assertEqual(deliver_selected(self.store, self.digest, confirm), "selected")
        self.assertIsNone(self.store.transfer(self.digest))
        self.assertEqual(deliver_selected(self.store, self.digest, Mock()), "selected")

    def test_stage_in_another_process_wakes_an_idle_database_worker(self) -> None:
        self.store.resolve(self.binding, selected=False)
        ready, expired = threading.Event(), threading.Event()
        next_expiry, sweep = self.store.next_expiry, self.store.sweep

        def record_next() -> datetime | None:
            deadline = next_expiry()
            if deadline is None:
                ready.set()
            return deadline

        def record_sweep() -> int:
            count = sweep()
            if count:
                expired.set()
            return count

        other = Binding("33" * 32, "44" * 32, self.binding.served_at, 20, "live")
        worker = ExpiryWorker(self.store)
        with (
            patch.object(self.store, "next_expiry", side_effect=record_next),
            patch.object(self.store, "sweep", side_effect=record_sweep),
        ):
            thread = threading.Thread(target=worker.run, daemon=True)
            thread.start()
            try:
                self.assertTrue(ready.wait(3))
                with self.assertRaises(BlockingIOError), self.store.changed.reader():
                    self.fail("simultaneous expiry worker admitted")
                self.now = self.served + timedelta(minutes=5)
                process = multiprocessing.get_context("spawn").Process(
                    target=stage_elsewhere,
                    args=(self.path, self.auditor, other, self.served),
                )
                process.start()
                process.join(5)
                self.assertEqual(process.exitcode, 0)
                self.assertTrue(expired.wait(3))
            finally:
                worker.stop()
                thread.join(3)
        self.assertEqual(self.store.status(other.leaf_hash), "gap")
