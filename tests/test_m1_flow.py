"""Evidence and failure controls for the isolated direct-mode milestone fixture."""

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from auditor.selections import Selections
from prover.mock import MockEvidence
from tests.m1_flow import GateFlowError, run_flow


class M1FlowTests(unittest.TestCase):
    def test_missing_assets_fail_with_public_error(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="PRIVATE-PATH-") as directory,
            self.assertRaises(GateFlowError) as caught,
        ):
            run_flow(Path(directory))
        self.assertEqual(str(caught.exception), "Isolated Mode D fixture failed")

    @unittest.skipUnless(
        os.environ.get("AKASHI_RENDER_ASSETS"), "requires pinned renderer assets"
    )
    def test_public_evidence_matches_full_fixture(self) -> None:
        self.assertEqual(
            run_flow(Path(os.environ["AKASHI_RENDER_ASSETS"])),
            {
                "mode": "D",
                "engine": "mock",
                "prover": "mock",
                "fixture_sha256": "81351f916dc325432d1191c96281f3c3169b4049bbf3978a898a95350b248b8b",
                "logged": 3,
                "promises_verified": 3,
                "handed_off": 1,
                "mock_proofs": 1,
                "failure_controls": 2,
                "unselected": 1,
                "recomputed": 3,
                "selected": 1,
                "gaps": 1,
            },
        )

    @unittest.skipUnless(
        os.environ.get("AKASHI_RENDER_ASSETS"), "requires pinned renderer assets"
    )
    def test_external_client_rejects_changed_shadow_decision(self) -> None:
        original = Selections.page

        def changed(records: Selections, cursor: int, limit: int) -> dict[str, Any]:
            page = original(records, cursor, limit)
            if cursor == 1:
                row = page["selections"][0]
                row["shadow_selected"] = not row["shadow_selected"]
            return page

        with (
            patch.object(Selections, "page", changed),
            self.assertRaises(GateFlowError),
        ):
            run_flow(Path(os.environ["AKASHI_RENDER_ASSETS"]))

    @unittest.skipUnless(
        os.environ.get("AKASHI_RENDER_ASSETS"), "requires pinned renderer assets"
    )
    def test_worker_evidence_must_bind_exact_private_statement(self) -> None:
        with (
            patch(
                "tests.m1_flow.MockProver.prove", return_value=MockEvidence("00" * 32)
            ),
            self.assertRaises(GateFlowError),
        ):
            run_flow(Path(os.environ["AKASHI_RENDER_ASSETS"]))
