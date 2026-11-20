"""Bounded wire evidence, verifier exit mapping and optional #25 integration."""

from __future__ import annotations

import base64
import importlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from prover.request import build_statement
from prover.scoring import Divergence, deviation_statement
from verifier.holder_proof import _check_evidence, check_proof

_PROMPT, _REPLY = (10, 11), (12, 13)
_EXACT = build_statement(_PROMPT, _REPLY)
_DIFF = Divergence(1, 14)
_CHANGED = deviation_statement(_PROMPT, _REPLY, _DIFF)
_PROOF = b"private-proof-fixture"


def _wire(*, deviation: bool = False) -> dict[str, object]:
    evidence: dict[str, object] = {
        "kind": "deviation" if deviation else "conformance",
        "statement": (_CHANGED if deviation else _EXACT).hex(),
        "proof": base64.b64encode(_PROOF).decode("ascii"),
    }
    if deviation:
        evidence.update(index=1, expected=14)
    return evidence


def _config(folder: Path) -> dict[str, object]:
    return {
        **{
            field: str(folder / field)
            for field in ("binary", "manifest", "config_dir", "public_key_dir")
        },
        "timeout_seconds": 8,
        "memory_bytes": 1024,
        "max_proof_bytes": len(_PROOF),
    }


class HolderProofTests(unittest.TestCase):
    def test_exit_mapping_and_exact_evidence_bytes(self) -> None:
        for is_diff in (False, True):
            for outcome, status in (
                ("verified", (21, "DEVIATES") if is_diff else (0, "CONFORMS")),
                ("rejected", (20, "PROOF_REJECTED")),
                ("statement_mismatch", (20, "PROOF_REJECTED")),
                ("unavailable", (30, "NO_VERDICT")),
                ("disagreement", (30, "VERIFIER_DISAGREEMENT")),
                ("incomplete", (13, "INCOMPLETE")),
                ("unexpected-private-output", (30, "NO_VERDICT")),
            ):
                checker = Mock(return_value=outcome)
                self.assertEqual(
                    _check_evidence(
                        _wire(deviation=is_diff),
                        _REPLY,
                        max_proof_bytes=len(_PROOF),
                        verify=checker,
                    ),
                    status,
                )
                evidence, divergence = checker.call_args.args
                self.assertEqual(
                    (evidence.statement, evidence.y, evidence.proof),
                    (_CHANGED if is_diff else _EXACT, bytes(4), _PROOF),
                )
                self.assertEqual(divergence, _DIFF if is_diff else None)
                self.assertNotIn("private-proof-fixture", repr(evidence))

    def test_rejects_oversized_evidence_before_decoding(self) -> None:
        checker = Mock()
        for prefix in (b"a", b"ab", b"abc"):
            evidence = {**_wire(), "proof": base64.b64encode(prefix).decode()}
            with patch(
                "verifier.holder_proof.base64.b64decode", side_effect=AssertionError
            ):
                self.assertEqual(
                    _check_evidence(
                        evidence,
                        _REPLY,
                        max_proof_bytes=len(prefix) - 1,
                        verify=checker,
                    )[0],
                    20,
                )
        checker.assert_not_called()

    def test_rejects_noncanonical_or_ambiguous_fields(self) -> None:
        checker = Mock()
        for evidence in (
            [],
            {**_wire(), "key": "private"},
            {**_wire(), "expected": 14},
            {**_wire(), "kind": "private"},
            {**_wire(), "statement": "aa"},
            {**_wire(), "statement": _EXACT.hex().upper()},
            {**_wire(), "y": "00 00 00"},
            {**_wire(), "y": "01000000"},
            *(
                {**_wire(), "proof": bad}
                for bad in ("", "A", "YQ=\n", "YR==", "////====", "__==", None)
            ),
            {**_wire(deviation=True), "index": True},
            {**_wire(deviation=True), "index": 2},
            {**_wire(deviation=True), "expected": 202048},
            {**_wire(deviation=True), "expected": False},
            {**_wire(deviation=True), "expected": _REPLY[1]},
        ):
            self.assertEqual(
                _check_evidence(evidence, _REPLY, max_proof_bytes=100, verify=checker),
                (20, "PROOF_REJECTED"),
            )
        checker.assert_not_called()

    def test_missing_tooling_or_backend_failure_is_redacted(self) -> None:
        self.assertEqual(
            _check_evidence(None, _REPLY, max_proof_bytes=100, verify=Mock()),
            (30, "NO_VERDICT"),
        )
        crashing = Mock(side_effect=RuntimeError("private-proof-fixture"))
        self.assertEqual(
            _check_evidence(_wire(), _REPLY, max_proof_bytes=100, verify=crashing),
            (30, "NO_VERDICT"),
        )
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory).resolve())
            with patch(
                "verifier.holder_proof.importlib.import_module",
                side_effect=ImportError("private"),
            ):
                self.assertEqual(
                    check_proof(_PROMPT, _REPLY, 2, _wire(), runtime=config),
                    (30, "NO_VERDICT"),
                )
            for invalid in (
                None,
                {},
                {**config, "memory_bytes": True},
                {**config, "max_proof_bytes": -1},
            ):
                self.assertEqual(
                    check_proof(_PROMPT, _REPLY, 2, _wire(), runtime=invalid),
                    (30, "NO_VERDICT"),
                )


@unittest.skipUnless(
    importlib.util.find_spec("verifier.proof"), "requires deployed #25 verifier"
)
class PinnedHolderAdapterTests(unittest.TestCase):
    def test_reconstructs_exact_and_corrected_statements_before_native_or_lean(
        self,
    ) -> None:
        backend = importlib.import_module("verifier.proof")
        with tempfile.TemporaryDirectory() as directory:
            config = _config(Path(directory).resolve())
            with patch.object(
                backend.NativeVerifier, "check", return_value="verified"
            ) as native:
                self.assertEqual(
                    check_proof(_PROMPT, _REPLY, 2, _wire(), runtime=config),
                    (0, "CONFORMS"),
                )
                native.assert_called_once_with(_EXACT, bytes(4), _PROOF)
                self.assertEqual(
                    check_proof(
                        _PROMPT, _REPLY, 2, {**_wire(), "y": "00000000"}, runtime=config
                    ),
                    (0, "CONFORMS"),
                )
                self.assertEqual(
                    check_proof(
                        _PROMPT, _REPLY, 2, _wire(deviation=True), runtime=config
                    ),
                    (21, "DEVIATES"),
                )
                native.assert_called_with(_CHANGED, bytes(4), _PROOF)
                native.reset_mock()
                for invalid in (
                    {**_wire(), "y": "01000000"},
                    {**_wire(), "statement": _CHANGED.hex()},
                    {**_wire(deviation=True), "statement": _EXACT.hex()},
                ):
                    self.assertEqual(
                        check_proof(_PROMPT, _REPLY, 2, invalid, runtime=config)[0], 20
                    )
                self.assertEqual(
                    check_proof(_PROMPT, _REPLY, 3, _wire(), runtime=config)[0], 13
                )
                native.assert_not_called()
                for bad in (
                    {**config, "binary": "relative"},
                    {**config, "timeout_seconds": True},
                    {**config, "lean": {}},
                ):
                    self.assertEqual(
                        check_proof(_PROMPT, _REPLY, 2, _wire(), runtime=bad)[0], 30
                    )
                native.assert_not_called()
                config["lean"] = {
                    "checkout": directory,
                    "lake": directory,
                    "temp": directory,
                    "timeout_seconds": 1,
                }
                with patch.object(
                    backend.LeanVerifier, "check", return_value="rejected"
                ) as lean:
                    record = Mock()
                    self.assertEqual(
                        check_proof(
                            _PROMPT,
                            _REPLY,
                            2,
                            _wire(),
                            runtime=config,
                            record_disagreement=record,
                        ),
                        (30, "VERIFIER_DISAGREEMENT"),
                    )
                    record.assert_called_once_with("verified", "rejected")
                    lean.assert_called_once_with(_EXACT, bytes(4), _PROOF)


if __name__ == "__main__":
    unittest.main()
