"""Fail closed on inconsistent counts and keep diagnostics out of the public report."""

import copy
import unittest
from typing import Any

from redteam.evidence_regressions import summarize


class EvidenceReportTests(unittest.TestCase):
    def test_contract_counts_omit_unexpected_private_diagnostics(self) -> None:
        contract = {"R16": ("omitted_promise", "included")}
        row: dict[str, Any] = {
            "scenario": "R16",
            "trials": 20,
            "caught": 20,
            "honest_controls": 20,
            "honest_passed": 20,
            "expected": "omitted_promise",
            "honest_expected": "included",
            "observed": {"omitted_promise": 20},
            "honest_observed": {"included": 20},
        }
        self.assertTrue(summarize([row], contract)[0]["passed"])
        rejected = copy.deepcopy(row)
        rejected.update(
            caught=19, observed={"omitted_promise": 19, "private-marker": 1}
        )
        public = summarize([rejected], contract)
        self.assertIs(public[0]["passed"], False)
        self.assertNotIn("private-marker", repr(public))
        for wrong in (
            {"caught": 20},
            {"trials": True},
            {"honest_controls": 0},
            {"trials": 19},
            {"honest_observed": {"included": False}},
            {"expected": "private-marker"},
        ):
            with self.subTest(field=next(iter(wrong))), self.assertRaises(ValueError):
                summarize([{**rejected, **wrong}], contract)
        with self.assertRaises(ValueError):
            summarize([row, row], contract)
