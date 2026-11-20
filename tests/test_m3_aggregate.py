"""M3 aggregate gate invariants for counts, fixture provenance and controls."""

import copy
import hashlib
import json
import platform
import tempfile
import unittest
from pathlib import Path
from typing import Any

from redteam.aggregate import checked_report
from redteam.evidence_regressions import (
    ADMISSION_CONTRACT,
    CONTRACT,
    MODEL_CONTRACT,
    SUITES,
)

_REVISION = "ace0" * 10
_DAY_CHECKS = (
    "holder_boundaries",
    "transcript_boundaries",
    "retry_after_verified",
    "durable_queue_verified",
    "dedup_verified",
    "rollovers_verified",
)


class M3AggregateTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.reports: dict[str, dict[str, Any]] = {}
        self.all_inputs: dict[str, str] = {}
        self.environment = {
            "python": platform.python_version(),
            "machine": platform.machine(),
        }
        contracts = {
            "model": MODEL_CONTRACT,
            "admission": ADMISSION_CONTRACT,
            "evidence": CONTRACT,
        }
        for name, spec in SUITES.items():
            hashes = {}
            for source in spec.fixtures:
                path = self.root / source
                path.parent.mkdir(parents=True, exist_ok=True)
                public = ("synthetic public fixture for " + source).encode()
                path.write_bytes(public)
                hashes[source] = hashlib.sha256(public).hexdigest()
            self.all_inputs.update(hashes)
            rows = []
            for ident, (label, honest) in reversed(contracts[name].items()):
                row: dict[str, object] = {
                    "scenario": ident,
                    "expected": label,
                    "honest_expected": honest,
                    "trials": 20,
                    "caught": 20,
                    "honest_controls": 20,
                    "honest_passed": 20,
                    "passed": True,
                }
                if ident == "R18":
                    row.update(
                        selection_divisor=1,
                        selected_long=20,
                        short_controls=20,
                        short_conforms=20,
                    )
                if ident == "R19":
                    row.update(dict.fromkeys(_DAY_CHECKS, 20))
                rows.append(row)
            self.reports[name] = {
                "schema_version": 1,
                "source_revision": _REVISION,
                "status": "passed",
                "environment": self.environment.copy(),
                "execution": spec.execution,
                "scope": spec.scope,
                "scenarios": rows,
                "fixture_sha256": hashes,
            }

    def reject(
        self, reports: dict[str, dict[str, Any]], revision: str = _REVISION
    ) -> None:
        with self.assertRaises(ValueError) as ctx:
            checked_report(reports, revision=revision, root=self.root)
        self.assertNotIn("private-sentinel", str(ctx.exception))

    def test_all_nineteen_in_numeric_order_and_canonical_file_digest(self) -> None:
        report = checked_report(self.reports, revision=_REVISION, root=self.root)
        self.assertEqual(
            set(report), {"scenarios", "totals", "fixture_digest", "environment"}
        )
        rows = report["scenarios"]
        assert isinstance(rows, list)
        self.assertEqual([r["scenario"] for r in rows], [f"R{i}" for i in range(1, 20)])
        self.assertEqual(
            report["totals"],
            {
                "scenarios": 19,
                "trials": 380,
                "caught": 380,
                "missed": 0,
                "honest_controls": 380,
                "honest_passed": 380,
                "false_positives": 0,
            },
        )
        self.assertEqual(report["environment"], self.environment)
        public_inputs = json.dumps(
            self.all_inputs, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        self.assertEqual(
            report["fixture_digest"], hashlib.sha256(public_inputs).hexdigest()
        )
        self.assertEqual(rows[17]["short_conforms"], 20)
        self.assertEqual(rows[18]["dedup_verified"], 20)

    def test_missing_unknown_and_duplicated_scenarios_or_suites(self) -> None:
        two_only = self.reports.copy()
        del two_only["admission"]
        self.reject(two_only)
        self.reject({**self.reports, "private-sentinel": self.reports["admission"]})
        for change in ("missing", "duplicate", "unknown", "wrong_suite", "not_row"):
            with self.subTest(change=change):
                reports = copy.deepcopy(self.reports)
                rows = reports["evidence"]["scenarios"]
                if change == "missing":
                    rows.pop()
                elif change == "duplicate":
                    rows[1] = rows[0]
                elif change == "unknown":
                    rows[0]["scenario"] = "private-sentinel"
                elif change == "wrong_suite":
                    rows[0] = reports["model"]["scenarios"][0]
                else:
                    rows[0] = None
                self.reject(reports)

    def test_wrong_outcome_labels_counts_and_passing_flags(self) -> None:
        for patch in (
            {"expected": "private-sentinel"},
            {"honest_expected": "private-sentinel"},
            {"trials": 19, "caught": 19},
            {"honest_controls": 19, "honest_passed": 19},
            {"trials": True},
            {"caught": 20.0},
            {"honest_passed": 19},
            {"caught": 19},
            {"caught": 21},
            {"passed": 1},
            {"passed": False},
            {"extra_detail": "private-sentinel"},
        ):
            with self.subTest(patch=patch):
                reports = copy.deepcopy(self.reports)
                reports["evidence"]["scenarios"][0].update(patch)
                self.reject(reports)

    def test_consistent_inflated_counts_exceed_the_actual_fixed_corpus(self) -> None:
        for name, ident, extra in (
            ("model", "R1", {"trials": 21, "caught": 21}),
            ("evidence", "R14", {"honest_controls": 2000, "honest_passed": 2000}),
            ("model", "R18", {"short_controls": 21, "short_conforms": 21}),
        ):
            with self.subTest(ident=ident):
                reports = copy.deepcopy(self.reports)
                row = next(
                    row
                    for row in reports[name]["scenarios"]
                    if row["scenario"] == ident
                )
                row.update(extra)
                self.reject(reports)

    def test_every_long_prompt_and_admission_subcheck_must_pass(self) -> None:
        for ident, field, wrong in (
            ("R18", "selected_long", 19),
            ("R18", "short_controls", 19),
            ("R18", "short_conforms", 19),
            ("R18", "selection_divisor", True),
            ("R18", "selection_divisor", 2),
            *(("R19", field, 19) for field in _DAY_CHECKS),
            ("R19", "dedup_verified", 20.0),
        ):
            with self.subTest(field=field, wrong=wrong):
                reports = copy.deepcopy(self.reports)
                name = "model" if ident == "R18" else "admission"
                row = next(
                    row
                    for row in reports[name]["scenarios"]
                    if row["scenario"] == ident
                )
                row[field] = wrong
                self.reject(reports)
                del row[field]
                self.reject(reports)

    def test_suite_provenance_environment_status_and_revision(self) -> None:
        for patch in (
            {"schema_version": True},
            {"status": "incomplete"},
            {"execution": SUITES["model"].execution},
            {"scope": "R19"},
            {"source_revision": "0" * 40},
            {"environment": {"machine": "unknown"}},
            {"environment": {**self.environment, "python": "private-sentinel"}},
            {"reason": "private-sentinel"},
        ):
            with self.subTest(patch=patch):
                reports = copy.deepcopy(self.reports)
                reports["evidence"].update(patch)
                self.reject(reports)
        for revision in ("", "abc123", "Z" * 40, _REVISION.upper()):
            with self.subTest(revision=revision):
                self.reject(self.reports, revision)

    def test_all_declared_file_hashes_must_match_actual_file_contents(self) -> None:
        for name, spec in SUITES.items():
            for source in spec.fixtures:
                with self.subTest(source=source):
                    reports = copy.deepcopy(self.reports)
                    reports[name]["fixture_sha256"][source] = "0" * 64
                    self.reject(reports)
                    del reports[name]["fixture_sha256"][source]
                    self.reject(reports)
        self.reports["model"]["fixture_sha256"]["private-sentinel"] = "0" * 64
        self.reject(self.reports)
        del self.reports["model"]["fixture_sha256"]["private-sentinel"]
        path = self.root / SUITES["model"].fixtures[0]
        path.write_bytes(b"changed bytes")
        self.reject(self.reports)
        path.unlink()
        self.reject(self.reports)


if __name__ == "__main__":
    unittest.main()
