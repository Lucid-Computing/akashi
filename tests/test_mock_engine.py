"""CPU fixtures for the RFC-0001 engine boundary and the M1 toy vocabulary."""

import unittest
from typing import cast

from engine.mock import EngineIntegrityError, EngineUnavailable, MockEngine


class MockEngineTests(unittest.TestCase):
    def test_deterministic_dispatch(self) -> None:
        engine = MockEngine()
        first = engine.generate((507, 2), max_tokens=5)
        self.assertEqual(first.tokens, (510, 511, 0, 1, 2))
        self.assertTrue(first.integrity_window_closed)
        self.assertEqual(engine.generate((507, 2), 2).tokens, first.tokens[:2])
        self.assertNotEqual(engine.generate((2,), 5).tokens, first.tokens)
        self.assertEqual(engine.generate((507, 2), 5), first)
        self.assertEqual(MockEngine().generate((507, 2), 5), first)

    def test_accepts_pinned_chat_ids_with_toy_output(self) -> None:
        # F37 empty user turn including the generation prompt.
        ids = (200000, 200005, 1556, 200006, 368, 200008, 200005, 140680, 200006, 368)
        self.assertEqual(MockEngine().generate(ids, 1).tokens, ((sum(ids) + 1) % 512,))

    def test_full_window_at_both_ends_of_budget_range(self) -> None:
        for prompt, budget in (((511,) * 1023, 1), ((0,) * 768, 256)):
            with self.subTest(prompt_length=len(prompt), budget=budget):
                result = MockEngine().generate(prompt, budget)
                self.assertTrue(result.integrity_window_closed)
                self.assertEqual(len(result.tokens), budget)
                self.assertTrue(all(0 <= token < 512 for token in result.tokens))

    def test_faults_are_visible_and_redacted(self) -> None:
        integrity = MockEngine(outcome="integrity_error")
        unavailable = MockEngine(outcome="unavailable")
        for engine, failure in (
            (integrity, EngineIntegrityError),
            (unavailable, EngineUnavailable),
        ):
            for _ in range(2):
                with (
                    self.subTest(failure=failure),
                    self.assertRaises(failure) as caught,
                ):
                    engine.generate((492, 217, 393), 3)
                message = str(caught.exception)
                for token in ("492", "217", "393"):
                    self.assertNotIn(token, message)
                self.assertFalse(hasattr(caught.exception, "tokens"))

    def test_rejects_invalid_dispatch(self) -> None:
        for prompt, budget in (
            ((), 1),
            ((1,), False),
            ((1,), -1),
            ((1,), 0),
            ((1,), 257),
            ((1,) * 1024, 1),
            ((True,), 1),
            ((-1,), 1),
            ((202048,), 1),
            ((cast(int, "8"),), 1),
        ):
            with (
                self.subTest(prompt_length=len(prompt), budget=budget),
                self.assertRaises((TypeError, ValueError)),
            ):
                MockEngine().generate(prompt, budget)
