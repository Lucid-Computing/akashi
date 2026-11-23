"""Exercise the public release evidence contract with isolated, synthetic records."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from release.evidence import MILESTONES, checked_files, linked


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


from tests.test_release_soak import soak_fixture


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        self.revision = "1" * 40
        self.primary = digest(b"synthetic original startup")
        self.reports: dict[str, dict[str, Any]] = {}
        self.manifest: dict[str, Any] = {
            "schema_version": 1,
            "candidate_revision": self.revision,
            "milestones": {},
        }
        for index, milestone in enumerate(MILESTONES, start=2):
            source = str(index) * 40
            report: dict[str, Any] = {
                "gate": milestone,
                "schema_version": 1,
                "status": "passed",
            }
            if milestone == "M1":
                report["source"] = {"commit": source, "dirty": False}
            else:
                report["source_revision"] = source
            self.reports[milestone] = report
            self.manifest["milestones"][milestone] = {"source_revision": source}
        self.reports["M0"]["platform"] = {
            "eligible_startup_sha256": self.primary,
            "serving_eligibility_scope": "primary_engine_only",
        }
        self.reports["M3"]["dirty"] = False
        # Only public prerequisites actually consumed by linked(); full gate checks the richer producer reports.
        self.reports["M2"]["checks"] = {
            **dict.fromkeys(
                (
                    "elapsed_age_verified",
                    "separate_cpu_verifier",
                    "reference_trace_bound",
                    "receipt_and_verdict_signatures_verified",
                    "eligible_primary_and_original_proof_bound",
                    "corrected_prefix_matches_proof",
                    "capability_isolation_checked",
                ),
                True,
            ),
            "challenge_clock": "elapsed_wall_clock",
            "actual_elapsed_seconds": 259201,
            "challenge_age_seconds": 259201,
            "conformance_exit": 0,
            "deviation_exit": 21,
        }
        self.reports["M4"].update(
            eligible_startup_sha256=self.primary,
            active_startup_sha256=digest(b"synthetic fresh startup"),
            archive_sha256=digest(b"synthetic M4 archive"),
            **soak_fixture(),
        )
        self.pins: dict[str, str] = {}
        for name in MILESTONES:
            if name in ("M2", "M4"):
                previous = ("M0", "M1") if name == "M2" else MILESTONES[:-1]
                self.reports[name]["milestone_evidence_sha256"] = {
                    k: self.pins[k] for k in previous
                }
            self.pin(name)
        self.manifest_path = self.directory / "manifest.json"
        self.anchor = self.write_manifest()

    def pin(self, name: str) -> None:
        raw = encoded(self.reports[name])
        self.pins[name] = digest(raw)
        self.manifest["milestones"][name]["sha256"] = self.pins[name]
        (self.directory / (name.lower() + ".json")).write_bytes(raw)

    def write_manifest(self) -> str:
        raw = encoded(self.manifest)
        self.manifest_path.write_bytes(raw)
        return digest(raw)

    def test_valid_public_shape_with_distinct_candidate_and_milestone_revisions(
        self,
    ) -> None:
        reports, hashes = checked_files(self.directory, self.anchor, self.revision)
        self.assertEqual(reports, self.reports)
        self.assertEqual(hashes, self.pins)
        linked(reports, hashes)

    def test_requires_independent_manifest_pin_and_all_files(self) -> None:
        with self.assertRaisesRegex(ValueError, "untrusted"):
            checked_files(self.directory, "0" * 64, self.revision)
        with self.assertRaisesRegex(ValueError, "candidate"):
            checked_files(self.directory, self.anchor, "f" * 40)
        (self.directory / "m1.json").unlink()
        with self.assertRaises(FileNotFoundError):
            checked_files(self.directory, self.anchor, self.revision)
        self.manifest_path.unlink()
        with self.assertRaises(FileNotFoundError):
            checked_files(self.directory, self.anchor, self.revision)

    def test_hash_mismatch_and_replacement_with_other_source_or_failed_report(
        self,
    ) -> None:
        file = self.directory / "m1.json"
        file.write_bytes(file.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            checked_files(self.directory, self.anchor, self.revision)
        self.pin("M1")
        for name, field, wrong in (
            ("M0", "source_revision", "d" * 40),
            ("M1", "source", {"commit": "e" * 40}),
            ("M3", "gate", "M4"),
            ("M2", "status", "incomplete"),
            ("M4", "schema_version", True),
        ):
            with self.subTest(name=name, field=field):
                self.set_file_temporarily(name, field, wrong)

    def set_file_temporarily(self, name: str, field: str, wrong: object) -> None:
        original = self.reports[name][field]
        try:
            self.reports[name][field] = wrong
            self.pin(name)
            with self.assertRaisesRegex(ValueError, "mismatched milestone"):
                checked_files(self.directory, self.write_manifest(), self.revision)
        finally:
            self.reports[name][field] = original
            self.pin(name)

    def test_manifest_shape_and_duplicate_keys(self) -> None:
        self.manifest["milestones"]["M5"] = self.manifest["milestones"]["M4"]
        with self.assertRaisesRegex(ValueError, "milestone set"):
            checked_files(self.directory, self.write_manifest(), self.revision)
        del self.manifest["milestones"]["M5"]
        raw = encoded(self.manifest).replace(
            b'"schema_version": 1', b'"schema_version": 1, "schema_version": 2'
        )
        self.manifest_path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            checked_files(self.directory, digest(raw), self.revision)
        del self.manifest["milestones"]["M4"]
        with self.assertRaisesRegex(ValueError, "milestone set"):
            checked_files(self.directory, self.write_manifest(), self.revision)

    def test_stale_prerequisites_detected_even_with_current_file_hashes(self) -> None:
        self.reports["M0"]["old_run_counter"] = 1
        self.pin("M0")
        reports, hashes = checked_files(
            self.directory, self.write_manifest(), self.revision
        )
        with self.assertRaisesRegex(ValueError, "evidence chain"):
            linked(reports, hashes)
        # Updating only M2 also invalidates M4's recorded M2 digest.
        self.reports["M2"]["milestone_evidence_sha256"]["M0"] = self.pins["M0"]
        self.pin("M2")
        self.reports["M4"]["milestone_evidence_sha256"]["M0"] = self.pins["M0"]
        self.pin("M4")
        reports, hashes = checked_files(
            self.directory, self.write_manifest(), self.revision
        )
        with self.assertRaisesRegex(ValueError, "evidence chain"):
            linked(reports, hashes)

    def test_each_primary_elapsed_holder_and_outcome_claim(self) -> None:
        m2 = self.reports["M2"]["checks"]
        m4 = self.reports["M4"]
        counts = m4["checks"]
        cases = [
            (self.reports["M1"]["source"], "dirty", True),
            (self.reports["M3"], "dirty", True),
            (self.reports["M0"]["platform"], "serving_eligibility_scope", "any_engine"),
            (m4, "eligible_startup_sha256", digest(b"different primary")),
            (m2, "challenge_clock", "controlled_plus_three_days"),
            (m2, "actual_elapsed_seconds", 259199),
            (m2, "challenge_age_seconds", 259199),
            (m2, "elapsed_age_verified", False),
            (m2, "separate_cpu_verifier", False),
            (m2, "receipt_and_verdict_signatures_verified", False),
            (m2, "eligible_primary_and_original_proof_bound", False),
            (m2, "corrected_prefix_matches_proof", False),
            (m2, "reference_trace_bound", False),
            (m2, "capability_isolation_checked", False),
            (m2, "conformance_exit", False),
            (m2, "deviation_exit", 0),
            (m4["timing"], "elapsed_seconds", 259199),
            (m4["timing"]["resources"], "prover", "missing"),
            (counts, "holder_native_verifications", 0),
            (counts, "holder_native_verifications", 5),
            (counts, "holder_native_verifications", True),
            (counts, "holder_operation", "in_process"),
            (counts, "router", "external_operator"),
            (counts, "unexplained_errors", 1),
            (counts, "attempted", 4),
            (counts, "selected", 3),
            (counts, "unwarranted_fraction", 0),
            (counts, "terminal_verdicts", {"CONFORMS": 3, "UNAVAILABLE": 1}),
            (counts, "terminal_verdicts", {"CONFORMS": 2, "EXCUSED_RANGE": 1}),
            (counts["oq8"], "fraction", 0.0),
            (counts["oq8"], "sampled", 5),
            (counts, "log_root", "private identifier"),
            (m4, "archive_sha256", "unavailable"),
        ]
        for row, field, value in cases:
            with self.subTest(field=field, value=value):
                original = row[field]
                try:
                    row[field] = value
                    with self.assertRaises(ValueError):
                        linked(self.reports, self.pins)
                finally:
                    row[field] = original


if __name__ == "__main__":
    unittest.main()
