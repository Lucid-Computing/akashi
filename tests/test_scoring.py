"""Proof candidates preserve the first served prefix; private range evidence is scoped."""

import struct
import unittest
from unittest.mock import Mock

from prover.reference import ReferenceTrace, ReferenceUnavailable
from prover.request import build_statement
from prover.scoring import Divergence, assess, deviation_statement
from prover.worker import Unavailable


def trace(
    values: tuple[int, ...], position: int | None = None, condition: int | None = None
) -> Mock:
    n = 1024 if position is None else position
    return Mock(
        score=Mock(
            return_value=ReferenceTrace((values + (0,) * n)[:n], position, condition)
        )
    )


class ScoringTests(unittest.TestCase):
    def test_two_wrong_tokens_only_first_changes_and_suffix_is_padded(self) -> None:
        prompt = (101, 102, 103)
        served = (201, 202, 203)
        ref = trace((6, 7, 201, 99, 88))
        plan = assess(prompt, served, 3, ref)
        self.assertEqual(plan.kind, "deviation")
        self.assertEqual(plan.divergence, Divergence(1, 99))
        self.assertEqual(plan.statement, build_statement(prompt, (201, 99)))
        assert plan.statement is not None
        words = struct.unpack("<1026I", plan.statement)
        self.assertEqual(words[:6], (101, 102, 103, 201, 99, 0))
        self.assertEqual(words[-2:], (2, 4))
        ref.score.assert_called_once_with(prompt + served + (0,) * (1024 - 6))

    def test_first_and_terminal_divergence_use_original_receipt_token(self) -> None:
        for d in (0, 1):
            y = (31, 32)
            self.assertEqual(
                deviation_statement((1,), y, Divergence(d, 40)),
                build_statement((1,), (*y[:d], 40)),
            )
        for invalid in (
            Divergence(-1, 40),
            Divergence(2, 40),
            Divergence(0, 31),
            Divergence(0, False),
        ):
            with self.assertRaises(ValueError):
                deviation_statement((1,), (31,), invalid)

    def test_incomplete_transcripts_never_call_model(self) -> None:
        ref = Mock()
        for y, m in (((4,), 2), ((200008, 3), 2), ((1, 2), 1)):
            self.assertEqual(assess((1,), y, m, ref).kind, "incomplete")
        ref.score.assert_not_called()

    def test_padding_and_last_unconsumed_position_need_independent_fault_and_failure(
        self,
    ) -> None:
        failed = Unavailable("spool_failure")
        for pos in (2, 3, 600, 1023):
            ref = trace((1, 42), pos, 3)
            candidate = assess((3, 4), (42,), 1, ref, failure=failed)
            self.assertEqual(candidate.kind, "excused_range")
            self.assertIsNone(candidate.statement)
            self.assertIsNotNone(candidate.private_range)
            assert candidate.private_range is not None
            self.assertEqual(
                (candidate.private_range.position, candidate.private_range.condition),
                (pos, 3),
            )
            self.assertNotIn("condition", repr(candidate))
            self.assertEqual(assess((3, 4), (42,), 1, ref).kind, "unavailable")

    def test_unattributed_failure_or_evaluated_range_never_excuses(self) -> None:
        failed = Unavailable("spool_failure")
        self.assertEqual(
            assess((1,), (42,), 1, trace((42,)), failure=failed).kind, "unavailable"
        )
        self.assertEqual(
            assess((1,), (42,), 1, trace((), 0, 3), failure=failed).kind, "unavailable"
        )
        self.assertEqual(
            assess(
                (1,),
                (42,),
                1,
                Mock(score=Mock(side_effect=ReferenceUnavailable())),
                failure=failed,
            ).kind,
            "unavailable",
        )
        self.assertEqual(
            assess((1,), (42,), 1, trace((42,), 400, 0), failure=failed).kind,
            "unavailable",
        )
        self.assertEqual(
            assess(
                (1,), (42,), 1, trace((42,), 400, 3), failure=Unavailable("deadline")
            ).kind,
            "unavailable",
        )

    def test_match_is_only_a_candidate_and_prior_mismatch_beats_later_range(
        self,
    ) -> None:
        y = (36, 200007)
        result = assess((8,), y, 4, trace((36, 200007)))
        self.assertEqual(
            (result.kind, result.statement), ("conformance", build_statement((8,), y))
        )
        fail = assess(
            (8,), y, 4, trace((99,), 1, 3), failure=Unavailable("spool_failure")
        )
        self.assertEqual(fail.kind, "deviation")

    def test_full_window_transition_at_final_served_token(self) -> None:
        prompt = (123,) * 1022
        served = (55, 56)
        choices = (0,) * 1021 + (55, 57, 88)
        result = assess(prompt, served, 2, trace(choices))
        self.assertEqual(result.divergence, Divergence(1, 57))
        self.assertEqual(result.statement, build_statement(prompt, (55, 57)))
        matched = (0,) * 1021 + served
        self.assertEqual(
            assess(
                prompt,
                served,
                2,
                trace(matched, 1023, 8),
                failure=Unavailable("spool_failure"),
            ).kind,
            "excused_range",
        )
        self.assertEqual(
            assess(
                prompt,
                served,
                2,
                trace(matched, 1022, 8),
                failure=Unavailable("spool_failure"),
            ).kind,
            "unavailable",
        )

    def test_changed_or_partial_reference_traces_cannot_support_a_claim(self) -> None:
        for damaged in (
            ReferenceTrace((9,)),
            ReferenceTrace((9,) * 1024, None, 1),
            ReferenceTrace((9,) * 2, 3, 1),
            ReferenceTrace((9,) * 1023 + (False,)),
        ):
            scorer = Mock(score=Mock(return_value=damaged))
            self.assertEqual(assess((1,), (9,), 1, scorer).kind, "unavailable")
        with self.assertRaises(ValueError):
            assess((1,) * 1023, (9,), 2, Mock())
