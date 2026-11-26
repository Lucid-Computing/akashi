"""Exercise the private M2 record contract with synthetic, identifiable token positions."""

import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from prover.reference import ReferenceScorer, ReferenceTrace
from prover.request import build_statement
from tools import m2_reference


class M2ReferenceTests(unittest.TestCase):
    prompt = (8, 12)
    original = build_statement(prompt, (34,))
    # The substituted engine emits (sum(prompt) + 1) % 512.
    changed = build_statement(prompt, (21,))
    inputs = (8, 12, 21) + (0,) * 1021
    trace = ReferenceTrace((7, 34) + (11,) * 1022)

    def test_scores_substitute_with_padding_binds_both_distinct_statements(
        self,
    ) -> None:
        scorer = Mock()
        scorer.score.return_value = self.trace
        record = m2_reference.observe(self.original, scorer)
        scorer.score.assert_called_once_with(self.inputs)
        self.assertEqual(
            record["original_statement_sha256"],
            hashlib.sha256(self.original).hexdigest(),
        )
        self.assertEqual(
            record["substitute_statement_sha256"],
            hashlib.sha256(self.changed).hexdigest(),
        )
        self.assertEqual(record["choices"], list(self.trace.choices))
        self.assertIsNone(record["range_position"])
        self.assertIsNone(record["range_condition"])
        bound = m2_reference.BoundTrace(self.inputs, self.trace)
        self.assertEqual(bound.score(self.inputs), self.trace)
        with self.assertRaises(ValueError):
            bound.score((8, 12, 34) + (0,) * 1021)

    def test_invalid_captures_never_reach_scorer(self) -> None:
        bad_pad = bytearray(self.original)
        struct.pack_into("<I", bad_pad, 1023 * 4, 1)
        bad_id = bytearray(self.original)
        struct.pack_into("<I", bad_id, 0, 202048)
        examples = [
            self.original + b"x",
            bytes(bad_pad),
            bytes(bad_id),
            build_statement(self.prompt, (34, 35)),
            self.changed,
        ]
        for example in examples:
            with self.subTest(size=len(example)):
                scorer = Mock()
                with self.assertRaises((ValueError, struct.error)):
                    m2_reference.observe(example, scorer)
                scorer.score.assert_not_called()

    def test_requires_corrected_first_token_before_any_range_fault(self) -> None:
        for trace in (
            ReferenceTrace((11, 21) + (11,) * 1022),
            ReferenceTrace((11, 35) + (11,) * 1022),
            ReferenceTrace((11,), 1, 8),
            ReferenceTrace((11, 34), 2, 9),
        ):
            with self.subTest(position=trace.range_position):
                scorer = Mock()
                scorer.score.return_value = trace
                with self.assertRaises(ValueError):
                    m2_reference.observe(self.original, scorer)
        scorer = Mock()
        scorer.score.return_value = ReferenceTrace((7, 34), 2, 8)
        record = m2_reference.observe(self.original, scorer)
        self.assertEqual((record["range_position"], record["range_condition"]), (2, 8))
        self.assertEqual(record["choices"], [7, 34])

    def test_fingerprint_uses_the_physical_host_and_m2_domain(self) -> None:
        machine = b"0123456789abcdef0123456789abcdef"
        with patch.object(
            Path, "read_bytes", autospec=True, return_value=machine + b"\n"
        ) as read:
            self.assertEqual(
                m2_reference.host_id(),
                hashlib.sha256(b"akashi/m2-host/1" + machine).hexdigest(),
            )
        read.assert_called_once_with(Path("/etc/machine-id"))
        for invalid in (b"", b"uninitialized", b"G" * 32, machine + b"0"):
            with (
                self.subTest(invalid=invalid),
                patch.object(Path, "read_bytes", return_value=invalid),
                self.assertRaises(ValueError),
            ):
                m2_reference.host_id()

    def test_cli_loads_protected_inputs_and_creates_exclusive_private_trace(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original, output = root / "original", root / "trace"
            original.write_bytes(self.original)
            args = [
                "m2-reference",
                "--model",
                str(root / "model"),
                "--manifest",
                str(root / "manifest"),
                "--rebuild",
                str(root / "rebuild"),
                "--statement",
                str(original),
                "--output",
                str(output),
            ]
            scorer = Mock()
            scorer.score.return_value = self.trace
            mask = os.umask(0o077)
            try:
                with (
                    patch.object(sys, "argv", args),
                    patch.object(ReferenceScorer, "load", return_value=scorer) as load,
                    patch.object(m2_reference, "host_id", return_value="f" * 64),
                    redirect_stdout(io.StringIO()) as progress,
                ):
                    self.assertEqual(m2_reference.main(), 0)
                    load.assert_called_once_with(
                        root / "model",
                        root / "manifest",
                        rebuild_report=root / "rebuild",
                    )
                    first = output.read_bytes()
                    with self.assertRaises(FileExistsError):
                        m2_reference.main()
                    self.assertEqual(output.read_bytes(), first)
            finally:
                os.umask(mask)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            record = json.loads(first)
            self.assertEqual(record["source_host"], "f" * 64)
            self.assertEqual(record["choices"], list(self.trace.choices))
            self.assertNotIn(str(record["choices"]), progress.getvalue())
