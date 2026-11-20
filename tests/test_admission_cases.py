"""Offline R19 regression evidence and accounting for failed checks."""

import unittest
from unittest.mock import patch

from redteam import admission_cases

BOUNDARY = "429/rate_limited + bounded_queue"
ELIGIBLE = "202/pending + independent_handle"
CHECKS = (
    "holder_boundaries",
    "transcript_boundaries",
    "retry_after_verified",
    "durable_queue_verified",
    "dedup_verified",
    "rollovers_verified",
)


class AdmissionCaseTests(unittest.TestCase):
    def test_twenty_signed_quota_boundaries_and_independent_eligible_controls(
        self,
    ) -> None:
        self.assertEqual(
            admission_cases.run_admission_cases(),
            [
                {
                    "scenario": "R19",
                    "trials": 20,
                    "caught": 20,
                    "expected": BOUNDARY,
                    "observed": {BOUNDARY: 20},
                    "honest_controls": 20,
                    "honest_passed": 20,
                    "honest_expected": ELIGIBLE,
                    "honest_observed": {ELIGIBLE: 20},
                    **dict.fromkeys(CHECKS, 20),
                }
            ],
        )

    def test_failed_checks_and_controls_reduce_their_own_counts(self) -> None:
        def observations(number: int) -> tuple[dict[str, bool], bool]:
            checks = dict.fromkeys(CHECKS, True)
            checks["retry_after_verified"] = number != 0
            return checks, number != 1

        with patch.object(admission_cases, "_case", side_effect=observations):
            [row] = admission_cases.run_admission_cases()
        self.assertEqual(
            (row["trials"], row["caught"], row["retry_after_verified"]), (20, 19, 19)
        )
        self.assertEqual(row["observed"], {BOUNDARY: 19, "BOUNDARY_CHECK_FAILED": 1})
        self.assertEqual((row["honest_controls"], row["honest_passed"]), (20, 19))
        self.assertEqual(
            row["honest_observed"], {ELIGIBLE: 19, "ELIGIBLE_CONTROL_FAILED": 1}
        )
        self.assertTrue(
            all(row[name] == 20 for name in CHECKS if name != "retry_after_verified")
        )

    def test_only_exact_quota_status_code_and_retry_after_count(self) -> None:
        for status, header, code in (
            (503, "3600", "rate_limited"),
            (429, None, "rate_limited"),
            (429, "3599", "rate_limited"),
            (429, "3600", "verifier_unavailable"),
        ):
            with self.subTest(status=status, header=header, code=code):
                reply = admission_cases._Reply(
                    status, header, {"error": {"code": code}}
                )
                self.assertFalse(reply.limited(3600))


if __name__ == "__main__":
    unittest.main()
