"""Pinned CPU scorer controls plus optional actual FlashProve recorded reference vectors."""

import hashlib
import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch

from prover.reference import (
    ReferenceScorer,
    ReferenceTrace,
    ReferenceUnavailable,
    _runtime,
)
from prover.runtime import REVISION
from prover.submission import COMMITMENT


class Fault(Exception):
    def __init__(self, position: int, condition: int) -> None:
        self.position, self.condition = position, condition


class ReferenceTests(unittest.TestCase):
    def test_chunk_fault_preserves_only_the_original_prefix_and_frees_cache(
        self,
    ) -> None:
        seq = SimpleNamespace(length=0, failure=None)
        model = Mock(parameters=SimpleNamespace(T=6, V=50))
        model.new_sequence.return_value = seq
        observed: list[int] = []

        def extend(seq: Any, chunk: tuple[int, ...], *, record: Any) -> Any:
            observed.extend(chunk)
            seq.length += len(chunk)
            choices = Mock()
            choices.tolist.return_value = [19, 9, 7]
            record("first_choice", None, choices)
            if seq.length == 6:
                seq.failure = Fault(4, 3)
                raise seq.failure
            return choices

        model.extend.side_effect = extend
        scorer = ReferenceScorer(model, Fault, 3)
        self.assertEqual(
            scorer.score((1, 2, 3, 4, 0, 0)), ReferenceTrace((19, 9, 7, 19), 4, 3)
        )
        self.assertEqual(observed, [1, 2, 3, 4, 0, 0])
        model.free.assert_called_once_with(seq)

    def test_generic_failure_and_impossible_typed_evidence_are_unavailable(
        self,
    ) -> None:
        for exc in (
            OSError("position 5 private-token"),
            Fault(5, 8),
            Fault(0, 9),
            Fault(0, 1),
        ):
            seq = SimpleNamespace(length=2, failure=exc)
            model = Mock(parameters=SimpleNamespace(T=2, V=9))
            model.new_sequence.return_value = seq
            model.extend.side_effect = exc
            scorer = ReferenceScorer(model, Fault, 2)
            with (
                self.subTest(fault=type(exc)),
                self.assertRaises(ReferenceUnavailable) as caught,
            ):
                scorer.score((1, 0))
            self.assertEqual(str(caught.exception), "Reference execution unavailable")
            self.assertFalse(hasattr(caught.exception, "position"))
            model.free.assert_called_once_with(seq)
        for tokens in ((True, 0), (1,), (-1, 1), (9, 0)):
            with self.subTest(tokens=tokens), self.assertRaises(ValueError):
                scorer.score(tokens)

    def test_loader_requires_independent_f4_manifest_and_verified_gguf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model_dir = root / "model"
            model_dir.mkdir()
            config = model_dir / "integer_model.json"
            settings = {
                "weights": "blocks",
                "weight_settings": {"blocks": "gguf", "verify_sums": True},
            }
            config.write_text(json.dumps(settings))
            files = {
                "integer_model.json": hashlib.sha256(config.read_bytes()).hexdigest(),
                "policy.txt": "11" * 32,
                "fold.txt": "22" * 32,
                "wsums.txt": "689cd1d0e84e6c6059cd1c4056c8532a436d88f7fa3803d835d2964be33eb519",
                "KL.bin": "df29bd823d62431945c3124138ed52e1f677db9224c4196505a91663ac48ab1a",
            }
            observed = {
                "model/wsums.txt": files["wsums.txt"],
                "config/KL.bin": files["KL.bin"],
                "commitment-id": COMMITMENT,
                "ivk/key.bin": "178d8814def56f88fae45f273c7f70152dac887ddc9075b6aca2f895c24c7c38",
                "ivk/leaf/0.bin": "e9dea311bb78bba70e6ec5db0196d5c4eba57498b0e8e4321d313025896c8dd0",
            }
            doc = {
                "schema_version": 1,
                "flashprove_revision": REVISION,
                "commitment_id": COMMITMENT,
                "sha256": files,
            }
            manifest, report = root / "manifest", root / "rebuild"
            manifest.write_text(json.dumps(doc))
            report.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "published_commitment": COMMITMENT,
                        "passed": True,
                        "observed": observed,
                    }
                )
            )
            runtime = Mock()
            runtime.load_from_folder.return_value.weights.sums_verified = True
            runtime.load_from_folder.return_value.parameters = SimpleNamespace(
                T=1024, V=202048
            )
            with patch("prover.reference._runtime", return_value=runtime):
                ReferenceScorer.load(model_dir, manifest, rebuild_report=report)
                runtime.load_from_folder.assert_called_once_with(
                    model_dir, "cpu", {"sha256": files}
                )
                for updates in (
                    {"commitment_id": "00" * 32},
                    {"flashprove_revision": "abc"},
                    {"sha256": files | {"wsums.txt": "00" * 32}},
                ):
                    with (
                        self.subTest(fields=updates.keys()),
                        self.assertRaises(ReferenceUnavailable),
                    ):
                        manifest.write_text(json.dumps(doc | updates))
                        ReferenceScorer.load(model_dir, manifest, rebuild_report=report)
                settings["weight_settings"] = {"blocks": "gguf", "verify_sums": False}
                config.write_text(json.dumps(settings))
                files["integer_model.json"] = hashlib.sha256(
                    config.read_bytes()
                ).hexdigest()
                manifest.write_text(json.dumps(doc))
                with self.assertRaises(ReferenceUnavailable):
                    ReferenceScorer.load(model_dir, manifest, rebuild_report=report)
                self.assertEqual(runtime.load_from_folder.call_count, 1)


@unittest.skipUnless(
    os.environ.get("AKASHI_FLASHPROVE_SOURCE"),
    "requires pinned FlashProve checkout and CPU PyTorch environment",
)
class UpstreamReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        # First case in upstream's recorded_values.tsv was independently evaluated.
        self.tiny = (
            Path(os.environ["AKASHI_FLASHPROVE_SOURCE"])
            / "integrations/vllm/integer_model/tests/configurations/tiny_without_clamps"
        )
        for name, digest in (
            (
                "policy.txt",
                "01033b80265249edf96f5cd94c6a89936093bbd2c6f2524f2ea28fca3cec3c44",
            ),
            (
                "KL.bin",
                "aa1351cb29201bd41eca78c6114dd15c49c4136765a7a23e398e9317ffa158e3",
            ),
        ):
            self.assertEqual(
                hashlib.sha256((self.tiny / name).read_bytes()).hexdigest(), digest
            )
        self.runtime = _runtime()
        self.torch = importlib.import_module("torch")
        original_threads = self.torch.get_num_threads()
        self.torch.set_num_threads(1)
        self.addCleanup(self.torch.set_num_threads, original_threads)
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        model_dir = Path(folder.name)
        for name in ("policy.txt", "KL.bin"):
            (model_dir / name).write_bytes((self.tiny / name).read_bytes())
        (model_dir / "integer_model.json").write_text(
            json.dumps({"weights": "synthetic"})
        )
        files = {
            file.name: hashlib.sha256(file.read_bytes()).hexdigest()
            for file in model_dir.iterdir()
        }
        self.model = self.runtime.load_from_folder(model_dir, "cpu", {"sha256": files})
        self.weights = self.model.weights
        self.tokens = (
            5,
            106,
            81,
            77,
            148,
            25,
            124,
            69,
            171,
            55,
            34,
            136,
            196,
            61,
            150,
            9,
        )
        self.choices = (
            9,
            126,
            20,
            127,
            184,
            124,
            69,
            171,
            55,
            34,
            136,
            196,
            100,
            197,
            120,
            76,
        )

    def test_teacher_forced_choices_match_upstream_independent_record(self) -> None:
        for chunk in (1, 5, 16):
            with self.subTest(chunk=chunk):
                result = ReferenceScorer(
                    self.model, self.runtime.RangeConditionFailed, chunk
                ).score(self.tokens)
                self.assertEqual(result, ReferenceTrace(self.choices))

    def test_real_range_exception_at_first_padding_row(self) -> None:
        # On the toy model alone, a synthetic zero-token embedding exceeds the four-limb
        # bound (condition 8). All original nonzero rows still have their recorded choices.
        original = self.weights.embedding_rows

        def pad_fault(ids: Any) -> Any:
            rows = original(ids).to(self.torch.int64)
            rows[ids == 0] = 1 << 40
            return rows

        with patch.object(self.weights, "embedding_rows", pad_fault):
            for chunk in (1, 5, 16):
                with self.subTest(chunk=chunk):
                    scorer = ReferenceScorer(
                        self.model, self.runtime.RangeConditionFailed, chunk
                    )
                    self.assertEqual(
                        scorer.score(self.tokens[:7] + (0,) * 9),
                        ReferenceTrace(self.choices[:7], 7, 8),
                    )

        self.assertEqual(scorer.score(self.tokens), ReferenceTrace(self.choices))

    def test_greedy_ties_choose_the_lowest_token_id(self) -> None:
        original = self.weights.matrix

        def tied(name: str, *args: Any, **kwargs: Any) -> Any:
            weights = original(name, *args, **kwargs)
            return self.torch.zeros_like(weights) if name == "Wh" else weights

        with patch.object(self.weights, "matrix", tied):
            scorer = ReferenceScorer(self.model, self.runtime.RangeConditionFailed, 16)
            self.assertEqual(scorer.score(self.tokens), ReferenceTrace((0,) * 16))
