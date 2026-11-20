"""CPU-only checks for fixed, explicitly synthetic reply and F9 policy fixtures."""

import hashlib
import json
import struct
import unittest
from unittest.mock import patch

from prover.reference import ReferenceTrace
from prover.request import END_TOKENS, WINDOW, build_statement
from redteam import model_cases as cases


class ModelCasesTests(unittest.TestCase):
    def test_every_scenario_and_honest_control_yields_its_required_outcome(
        self,
    ) -> None:
        summaries = {row["scenario"]: row for row in cases.run_model_cases()}
        self.assertEqual(set(summaries), {*(f"R{i}" for i in range(1, 10)), "R18"})
        for name, row in summaries.items():
            with self.subTest(scenario=name):
                self.assertEqual(
                    (
                        row["caught"],
                        row["trials"],
                        row["honest_controls"],
                        row["honest_passed"],
                    ),
                    (20, 20, 20, 20),
                )
                self.assertEqual(
                    row["observed"], {"INCOMPLETE" if name == "R8" else "DEVIATES": 20}
                )
                self.assertEqual(row["honest_observed"], {"CONFORMS": 20})
        long = summaries["R18"]
        self.assertEqual(
            (
                long["selected_long"],
                long["short_controls"],
                long["short_conforms"],
                long["selection_divisor"],
            ),
            (20, 20, 20, 1),
        )

    def test_fixed_candidate_shapes_and_independent_first_difference_oracles(
        self,
    ) -> None:
        honest_eos = set()
        data = cases._read(cases._CORPUS)
        for row in map(json.loads, data.splitlines()):
            honest = row["honest_reply"]
            candidates = row["candidates"]
            self.assertEqual(len(row["long_prompt"]) + row["budget"], WINDOW)
            if len(honest) < row["budget"]:
                honest_eos.add(honest[-1])
            self.assertEqual(
                len({tuple(candidates[f"R{n}"]["reply"]) for n in range(1, 6)}), 5
            )
            premature = candidates["R7"]["reply"]
            self.assertIn(premature[-1], END_TOKENS)
            self.assertLess(len(premature), len(honest))
            incomplete = candidates["R8"]["reply"]
            self.assertTrue(END_TOKENS.isdisjoint(incomplete))
            self.assertLess(len(incomplete), row["budget"])
            self.assertEqual(len(candidates["R9"]["reply"]), len(honest))
            self.assertEqual(
                sum(
                    a != b
                    for a, b in zip(candidates["R9"]["reply"], honest, strict=True)
                ),
                1,
            )
            middle = candidates["R6"]["first_difference"]
            self.assertTrue(0 < middle < len(honest) - 1)
            self.assertEqual(candidates["R18"]["short_reply"], honest)
            for label, candidate in candidates.items():
                if label == "R8":
                    self.assertIsNone(candidate["corrected_sha256"])
                    continue
                first = next(
                    i
                    for i, (a, b) in enumerate(
                        zip(candidate["reply"], candidate["choices"], strict=True)
                    )
                    if a != b
                )
                self.assertEqual(first, candidate["first_difference"])
                prefix = row["long_prompt"] if label == "R18" else row["prompt"]
                fixed = build_statement(
                    prefix, [*candidate["reply"][:first], candidate["choices"][first]]
                )
                self.assertEqual(
                    hashlib.sha256(fixed).hexdigest(), candidate["corrected_sha256"]
                )
        self.assertEqual(honest_eos, END_TOKENS)

    def test_trace_is_bound_to_exact_padded_input_and_stale_terminal_record_fails(
        self,
    ) -> None:
        row = json.loads(cases._read(cases._CORPUS).splitlines()[0])
        candidate = row["candidates"]["R6"]
        trace = cases._RecordedTrace(
            candidate["input_sha256"], ReferenceTrace((1,) * WINDOW)
        )
        wire = build_statement(row["prompt"], row["honest_reply"])
        with self.assertRaises(ValueError):
            trace.score(struct.unpack_from(f"<{WINDOW}I", wire))
        records = json.loads(cases._read(cases._RECORDS))["records"]
        p = tuple(row["prompt"])
        reply = tuple(candidate["reply"])
        first = candidate["first_difference"]
        required = f"{len(p) - 1},{len(p) + first}"
        records[required] = records[next(key for key in records if key != required)]
        observed = cases._evaluate(
            p,
            reply,
            row["budget"],
            tuple(candidate["choices"]),
            candidate["input_sha256"],
            candidate["corrected_sha256"],
            first,
            records,
        )
        self.assertEqual(observed, "PROOF_POLICY_MISMATCH")

    def test_long_rows_require_actual_beacon_selection(self) -> None:
        with patch.object(cases, "select_round", return_value={1: False}) as selection:
            long = cases.run_model_cases()[-1]
        self.assertEqual(selection.call_count, 20)
        self.assertEqual(long["selected_long"], 0)
        self.assertEqual(long["caught"], 0)
        self.assertEqual(long["observed"], {"NOT_SELECTED": 20})
        self.assertEqual(long["short_conforms"], 20)


if __name__ == "__main__":
    unittest.main()
