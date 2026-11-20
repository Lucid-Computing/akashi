"""Exercise the serialized token adapter against controllable host checkpoints."""

import threading
import unittest
from concurrent.futures import CancelledError, ThreadPoolExecutor
from dataclasses import replace
from typing import Any
from unittest.mock import Mock

from engine.adapter import (
    Canary,
    Cursor,
    Engine,
    EngineIntegrityError,
    EngineResult,
    EngineUnavailable,
    StartupEvidence,
    Window,
)

EVIDENCE = StartupEvidence(
    "process-one",
    "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46",
    True,
    True,
    True,
    True,
)
CANARIES = (
    Canary((11,), 1, (21,)),
    Canary((12,), 2, (22, 22)),
    Canary((13,), 3, (23, 23, 23)),
)


class Host:
    def __init__(self) -> None:
        self.position = 0
        self.instance = EVIDENCE.instance
        self.begin = Mock(side_effect=lambda: Cursor(self.instance, self.position))
        self.finish = Mock(side_effect=self.clean)
        self.send = Mock(side_effect=self.reply)
        self.engine = Engine(self.send, self.begin, self.finish)

    def reply(self, prompt: tuple[int, ...], budget: int) -> tuple[int, ...]:
        return (prompt[0] + 10,) * budget

    def clean(self, start: Cursor) -> Window:
        self.position += 1
        return Window(start, Cursor(self.instance, self.position), True, False)

    def start(self) -> None:
        self.engine.start(replace(EVIDENCE, instance=self.instance), CANARIES)


class EngineAdapterTests(unittest.TestCase):
    def test_each_evidence_gate_precedes_any_dispatch(self) -> None:
        invalid_gates: tuple[tuple[str, Any], ...] = (
            ("commitment_id", "00" * 32),
            ("launch_verified", False),
            ("float64_exact", False),
            ("reference_files_verified", False),
            ("weight_tensors_verified", False),
            ("float64_exact", 1),
            ("instance", ""),
        )
        for field, value in invalid_gates:
            with self.subTest(field=field, value=value):
                host = Host()
                with self.assertRaises(EngineUnavailable):
                    host.engine.generate((1,), 1)
                with self.assertRaises(EngineUnavailable):
                    host.engine.start(replace(EVIDENCE, **{field: value}), CANARIES)
                with self.assertRaises(EngineUnavailable):
                    host.engine.generate((1,), 1)
                self.assertFalse(host.engine.ready)
                host.send.assert_not_called()

    def test_three_distinct_exact_canaries_with_closed_windows(self) -> None:
        for canaries in ((), CANARIES[:2], CANARIES + CANARIES[:1], (CANARIES[0],) * 3):
            host = Host()
            with (
                self.subTest(count=len(canaries)),
                self.assertRaises(EngineUnavailable),
            ):
                host.engine.start(EVIDENCE, canaries)
            host.send.assert_not_called()
        host = Host()
        host.start()
        self.assertTrue(host.engine.ready)
        self.assertTrue(host.engine.gates.canaries_verified)
        self.assertEqual(host.begin.call_count, 3)
        self.assertEqual(host.finish.call_count, 3)
        self.assertEqual(
            [c.args for c in host.send.call_args_list],
            [(c.prompt, c.max_tokens) for c in CANARIES],
        )
        for bad_output in ((99,), ()):
            host = Host()
            host.send.side_effect = None
            host.send.return_value = bad_output
            with self.assertRaises(EngineUnavailable):
                host.start()
            self.assertFalse(host.engine.ready)
            self.assertTrue(host.engine.quarantined)
        host = Host()
        host.finish.side_effect = lambda s: Window(s, s, False, False)
        with self.assertRaises(EngineUnavailable):
            host.start()
        self.assertFalse(host.engine.gates.canaries_verified)
        with self.assertRaises(EngineUnavailable):
            host.engine.reconcile(host.clean)

    def test_complete_output_and_admitted_domain(self) -> None:
        host = Host()
        host.start()
        host.send.side_effect = None
        for reply, budget in (
            ((1, 2), 2),
            ((200001,), 10),
            ((200007,), 256),
            ((1, 200008), 2),
        ):
            host.send.return_value = reply
            self.assertEqual(
                host.engine.generate((202047,), budget), EngineResult(reply, True)
            )
        calls = host.send.call_count
        invalid: tuple[tuple[Any, Any], ...] = (
            ((True,), 1),
            ((202048,), 1),
            ((-1,), 1),
            ([], 1),
            ((), 1),
            ((1,), True),
            ((1,), 0),
            ((1,), 257),
            ((1,) * 1024, 1),
        )
        for prompt, budget in invalid:
            with (
                self.subTest(prompt_length=len(prompt), budget=budget),
                self.assertRaises(ValueError),
            ):
                host.engine.generate(prompt, budget)
        self.assertEqual(host.send.call_count, calls)
        for invalid_reply in (
            (),
            (1,),
            (1, 2, 3),
            (200008, 1),
            (True, 1),
            (202048, 1),
            [1, 2],
        ):
            host = Host()
            host.start()
            host.send.side_effect = None
            host.send.return_value = invalid_reply
            with (
                self.subTest(reply=invalid_reply),
                self.assertRaises(EngineIntegrityError),
            ):
                host.engine.generate((1,), 2)
            self.assertTrue(host.engine.quarantined)
            self.assertEqual(host.finish.call_count, 4)

    def test_fault_and_missing_or_misaligned_coverage_quarantine(self) -> None:
        start = Cursor(EVIDENCE.instance, 3)
        for window in (
            None,
            Window(start, start, False, False),
            Window(start, start, True, True),
            Window(start, Cursor("other", 4), True, False),
            Window(Cursor(start.instance, 2), start, True, False),
            Window(start, Cursor(start.instance, 1), True, False),
        ):
            with self.subTest(window=window):
                host = Host()
                host.start()
                host.finish.side_effect = None
                host.finish.return_value = window
                with self.assertRaises(EngineIntegrityError):
                    host.engine.generate((1,), 1)
                self.assertFalse(host.engine.ready)
                with self.assertRaises(EngineUnavailable):
                    host.engine.generate((2,), 1)
                self.assertEqual(host.send.call_count, 4)
        for invalid in (None, Cursor("other", 10), Cursor(start.instance, 1)):
            host = Host()
            host.start()
            host.begin.side_effect = None
            host.begin.return_value = invalid
            with self.assertRaises(EngineIntegrityError):
                host.engine.generate((1,), 1)
            self.assertEqual(host.send.call_count, 3)

    def test_cancellation_requires_drained_coverage_or_a_new_process(self) -> None:
        host = Host()
        host.start()
        host.send.side_effect = CancelledError()
        with self.assertRaises(CancelledError):
            host.engine.generate((1,), 1)
        self.assertTrue(host.engine.quarantined)
        with self.assertRaises(EngineUnavailable):
            host.engine.generate((1,), 1)
        with self.assertRaises(EngineUnavailable):
            host.engine.reconcile(lambda start: Window(start, start, False, False))
        host.engine.reconcile(host.clean)
        host.send.side_effect = host.reply
        self.assertEqual(host.engine.generate((1,), 1).tokens, (11,))

        host.finish.side_effect = OSError("private diagnostic")
        with self.assertRaises(EngineIntegrityError) as failure:
            host.engine.generate((1,), 1)
        self.assertNotIn("private diagnostic", str(failure.exception))
        with self.assertRaises(EngineUnavailable):
            host.start()
        host.instance = "process-two"
        host.finish.side_effect = host.clean
        host.start()
        self.assertTrue(host.engine.ready)

    def test_exclusive_slot_extends_through_final_checkpoint(self) -> None:
        host = Host()
        host.start()
        in_checkpoint, release, second_entered, second_sent = (
            threading.Event() for _ in range(4)
        )

        def finish(start: Cursor) -> Window:
            in_checkpoint.set()
            if not release.wait(3):
                raise RuntimeError("test checkpoint timed out")
            return host.clean(start)

        def send(prompt: tuple[int, ...], budget: int) -> tuple[int, ...]:
            if prompt == (2,):
                second_sent.set()
            return host.reply(prompt, budget)

        def second() -> EngineResult:
            second_entered.set()
            return host.engine.generate((2,), 1)

        host.finish.side_effect = finish
        host.send.side_effect = send
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(host.engine.generate, (1,), 1)
            try:
                self.assertTrue(in_checkpoint.wait(2))
                later = pool.submit(second)
                self.assertTrue(second_entered.wait(2))
                self.assertFalse(second_sent.wait(0.05))
            finally:
                release.set()
            self.assertEqual(first.result().tokens, (11,))
            self.assertEqual(later.result().tokens, (12,))
