"""Check failure accounting and offline policy fixtures without external runtimes."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from auditor.intake import IntakeError
from redteam import transcript_cases as cases


class TranscriptCaseTests(unittest.TestCase):
    def test_missing_pinned_assets_fail_the_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(OSError):
            cases.run_cases(Path(directory))

    def test_twenty_paired_statement_and_commitment_policy_observations(self) -> None:
        self.assertEqual(len(set(cases._CASES)), 20)
        for index in range(len(cases._CASES)):
            with self.subTest(index=index):
                self.assertEqual(cases._proof_policy(index), "0/CONFORMS")
                self.assertEqual(
                    cases._proof_policy(index, adjacent=True), "20/PROOF_REJECTED"
                )
                self.assertEqual(
                    cases._proof_policy(index, foreign=True), "30/NO_VERDICT"
                )

    def test_an_unexpected_observation_or_honest_failure_cannot_pass(self) -> None:
        counts = cases._Observations("R12", "12/TEXT_MISMATCH", "30/RECEIPT_VERIFIED")
        counts.record("12/TEXT_MISMATCH", "30/RECEIPT_VERIFIED")
        counts.record("30/RECEIPT_VERIFIED", "unexpected_holder_result")
        result = counts.report()
        self.assertEqual(
            (
                result["caught"],
                result["trials"],
                result["honest_passed"],
                result["honest_controls"],
            ),
            (1, 2, 1, 2),
        )
        self.assertEqual(
            result["observed"], {"12/TEXT_MISMATCH": 1, "30/RECEIPT_VERIFIED": 1}
        )
        self.assertEqual(
            result["honest_observed"],
            {"30/RECEIPT_VERIFIED": 1, "unexpected_holder_result": 1},
        )

    def test_unexpected_intake_or_holder_diagnostics_are_bounded(self) -> None:
        intake = Mock()
        intake.submit.side_effect = IntakeError(503, "private-test-detail")
        self.assertEqual(
            cases._intake(intake, "test", {}, 0), "unexpected_intake_result"
        )
        with patch.object(
            cases,
            "verify",
            return_value=Mock(exit_code=70, outcome="private-test-detail"),
        ):
            self.assertEqual(
                cases._holder({}, {}, Path(".")), "unexpected_holder_result"
            )


if __name__ == "__main__":
    unittest.main()
