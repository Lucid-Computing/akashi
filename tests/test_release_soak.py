"""Check publicly visible invariants of the M4 signed-history and resource summary."""

from __future__ import annotations

import unittest
from typing import Any

from release.soak_report import check_soak


def soak_fixture() -> dict[str, Any]:
    hours = 72
    resources: dict[str, Any] = {}
    for role in ("gateway", "auditor", "engine", "prover"):
        partial = role == "prover"
        row: dict[str, Any] = {
            "fd_basis": "exact_visible_plus_native_fdsize"
            if partial
            else "exact_open_descriptors",
            "min_exact_fd_processes": int(not partial),
            "peak_exact_fd_processes": 1,
            "final_exact_fd_processes": int(not partial),
            "protected_fd_processes": int(partial),
        }
        for prefix, rss, fds, slots in (
            ("warm_peak", 12, 5, 64),
            ("peak", 18, 8, 128),
            ("final", 10, 4, 64),
        ):
            row[prefix + "_rss_bytes"] = rss
            row[prefix + "_gpu_bytes"] = int(role in {"engine", "prover"}) * (1 << 20)
            if partial:
                row[prefix + "_exact_fds_visible"] = None if prefix == "final" else fds
                row[prefix + "_protected_fd_slots"] = slots
            else:
                row[prefix + "_fds"] = fds
        resources[role] = row
    return {
        "evaluation_revision": "ab" * 20,
        "execution": "elapsed physical all-audit soak with local opaque router",
        "timing": {
            "elapsed_seconds": hours * 3600.0,
            "start_utc": "2020-01-01T00:00:00+00:00",
            "end_utc": "2020-01-04T00:00:00+00:00",
            "resource_observations": hours * 12 + 1,
            "resources": resources,
        },
        "checks": {
            "attempted": 10,
            "warranted": 8,
            "unwarranted": 2,
            "selected": 8,
            "terminal_verdicts": {"CONFORMS": 7, "EXCUSED_RANGE": 1},
            "unwarranted_fraction": 2 / 10,
            "unexplained_errors": 0,
            "holder_native_verifications": 2,
            "holder_operation": "separate_local_process",
            "router": "local_opaque_mock",
            "log_root": "ab" * 32,
            "shape_counts": {
                "empty_system": 2,
                "long_single": 2,
                "multi_turn": 2,
                "system_user": 2,
            },
            "observed_reply_range": [1, 256],
            "padding_token_range": [0, 966],
            "oq8": {"sampled": 8, "excused_range": 1, "fraction": 1 / 8},
            "observed_capacity": {
                "requests_per_hour": 10 / hours,
                "warranted_per_hour": 8 / hours,
                "synthetic_requests_in_flight_limit": 1,
            },
        },
    }


class ReleaseSoakTests(unittest.TestCase):
    def test_protected_and_exact_coverage(self) -> None:
        r = soak_fixture()
        check_soak(r)
        partial = r["timing"]["resources"]["prover"]
        partial["peak_exact_fd_processes"] = 0
        partial["warm_peak_exact_fds_visible"] = partial["peak_exact_fds_visible"] = (
            None
        )
        check_soak(r)
        legacy = r["timing"]["resources"]["gateway"]
        for field in (
            "min_exact_fd_processes",
            "peak_exact_fd_processes",
            "final_exact_fd_processes",
            "protected_fd_processes",
        ):
            del legacy[field]
        check_soak(r)

    def test_rejects_short_synthetic_or_unobserved_runs(self) -> None:
        for key, value in (
            ("start_utc", "2020-01-02T00:00:00Z"),
            ("end_utc", "2999-01-01T00:00:00Z"),
            ("end_utc", "2020-01-07T00:00:00"),
            ("end_utc", 123),
            ("elapsed_seconds", 3),
            ("elapsed_seconds", float("nan")),
            ("elapsed_seconds", float("inf")),
            ("resource_observations", 860),
            ("resource_observations", True),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                r = soak_fixture()
                r["timing"][key] = value
                check_soak(r)

    def test_rejects_mixed_role_basis_and_retained_growth(self) -> None:
        for role, key, value in (
            ("prover", "final_protected_fd_slots", 65),
            ("prover", "final_exact_fds_visible", 0),
            ("prover", "protected_fd_processes", True),
            ("prover", "final_fds", 64),
            ("prover", "peak_exact_fds_visible", None),
            ("prover", "warm_peak_exact_fds_visible", 9),
            ("prover", "min_exact_fd_processes", 1),
            ("engine", "final_rss_bytes", 13),
            ("engine", "warm_peak_rss_bytes", None),
            ("engine", "peak_gpu_bytes", 0),
            ("gateway", "peak_gpu_bytes", 64),
            ("gateway", "fd_basis", "exact_visible_plus_native_fdsize"),
            ("auditor", "final_fds", True),
            ("engine", "peak_fds", -1),
        ):
            with (
                self.subTest(role=role, key=key, value=value),
                self.assertRaises(ValueError),
            ):
                r = soak_fixture()
                r["timing"]["resources"][role][key] = value
                check_soak(r)

    def test_checks_round_robin_counts_signed_outcomes_bounds_and_rates(self) -> None:
        for key, value in (
            ("attempted", True),
            ("attempted", 9),
            ("selected", 7),
            ("unexplained_errors", 1),
            ("holder_native_verifications", 5),
            ("terminal_verdicts", {"CONFORMS": 7, "ERROR": 1}),
            ("terminal_verdicts", {"CONFORMS": 7, "EXCUSED_RANGE": True}),
            (
                "shape_counts",
                {
                    "empty_system": 1,
                    "long_single": 1,
                    "multi_turn": 4,
                    "system_user": 2,
                },
            ),
            ("observed_reply_range", [False, 256]),
            ("observed_reply_range", [1, 255]),
            ("padding_token_range", [1, 967]),
            ("padding_token_range", [0, 974]),
            ("oq8", {"sampled": 8, "excused_range": True, "fraction": 0.125}),
            ("oq8", {"sampled": 8, "excused_range": 1, "fraction": 0.0}),
            ("unwarranted_fraction", float("nan")),
            ("holder_operation", "same_process"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                r = soak_fixture()
                r["checks"][key] = value
                check_soak(r)
        for key, value in (
            ("requests_per_hour", float("inf")),
            ("warranted_per_hour", 0),
            ("synthetic_requests_in_flight_limit", True),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                r = soak_fixture()
                r["checks"]["observed_capacity"][key] = value
                check_soak(r)

    def test_requires_each_observed_role_and_its_metrics(self) -> None:
        r = soak_fixture()
        del r["timing"]["resources"]["gateway"]["final_fds"]
        with self.assertRaises(ValueError):
            check_soak(r)
        r = soak_fixture()
        del r["timing"]["resources"]["auditor"]
        with self.assertRaises(ValueError):
            check_soak(r)
