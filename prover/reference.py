"""Private teacher-forced scoring with the pinned FlashProve integer-model CPU runtime."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import os
import re
import stat
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

from prover.request import VOCABULARY_SIZE, WINDOW
from prover.runtime import REVISION
from prover.submission import COMMITMENT, trusted_directory

# All Python sources in the integer_model package at REVISION, hashed by _runtime.
_PACKAGE_SHA256 = "2d2c37a94e0d01f6b2c7463904737fc34ab0de74d19a4aea954c04ee46cd5d03"
# examples/maverick/expected.txt at REVISION.
_WSUMS = "689cd1d0e84e6c6059cd1c4056c8532a436d88f7fa3803d835d2964be33eb519"
_KL = "df29bd823d62431945c3124138ed52e1f677db9224c4196505a91663ac48ab1a"
_FILES = {"integer_model.json", "policy.txt", "KL.bin", "wsums.txt", "fold.txt"}


class ReferenceUnavailable(RuntimeError):
    """Reference provenance, scoring or range attribution could not be established."""


@dataclass(frozen=True, repr=False)
class ReferenceTrace:
    """Private choices at input positions strictly before the first failed range check."""

    choices: tuple[int, ...]
    range_position: int | None = None
    range_condition: int | None = None


def _read(path: Path) -> bytes:
    with trusted_directory(path.parent) as directory:
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in (0, os.geteuid())
                or metadata.st_mode & 0o022
            ):
                raise ReferenceUnavailable("Untrusted reference artifact")
            return stream.read()


def _runtime() -> ModuleType:
    if sys.version_info[:2] != (3, 13) or any(
        importlib.metadata.version(package).partition("+")[0] != version
        for package, version in (
            ("integer-model", "0.16.0"),
            ("torch", "2.13.0"),
            ("numpy", "2.4.6"),
        )
    ):
        raise ReferenceUnavailable(
            "Reference package versions differ from the pinned runtime"
        )
    folder = Path(
        str(
            importlib.metadata.distribution("integer-model").locate_file(
                "integer_model"
            )
        )
    )
    spec = importlib.util.find_spec("integer_model")
    if spec is None or spec.origin != str(folder / "__init__.py"):
        raise ReferenceUnavailable("Unexpected integer-model import origin")
    digest = hashlib.sha256()
    for source in sorted(folder.iterdir()):
        if source.name == "__pycache__":
            continue
        if source.suffix != ".py":
            raise ReferenceUnavailable("Unexpected integer-model package entry")
        digest.update(
            source.name.encode("ascii")
            + b"\x00"
            + hashlib.sha256(_read(source)).digest()
        )
    if digest.hexdigest() != _PACKAGE_SHA256:
        raise ReferenceUnavailable(
            "Integer-model sources differ from the pinned revision"
        )
    return importlib.import_module("integer_model")


def _manifest(model_dir: Path, path: Path, rebuild_report: Path) -> dict[str, str]:
    if (
        not model_dir.is_absolute()
        or not path.is_absolute()
        or not rebuild_report.is_absolute()
        or path.resolve().is_relative_to(model_dir.resolve())
        or rebuild_report.resolve().is_relative_to(model_dir.resolve())
    ):
        raise ReferenceUnavailable("Independent model provenance is required")
    report = json.loads(_read(rebuild_report))
    expected = {
        "model/wsums.txt": _WSUMS,
        "config/KL.bin": _KL,
        "commitment-id": COMMITMENT,
        "ivk/key.bin": "178d8814def56f88fae45f273c7f70152dac887ddc9075b6aca2f895c24c7c38",
        "ivk/leaf/0.bin": "e9dea311bb78bba70e6ec5db0196d5c4eba57498b0e8e4321d313025896c8dd0",
    }
    if (
        type(report.get("schema_version")) is not int
        or report["schema_version"] != 1
        or report.get("published_commitment") != COMMITMENT
        or report.get("passed") is not True
        or not isinstance(report.get("observed"), dict)
        or any(report["observed"].get(k) != v for k, v in expected.items())
    ):
        raise ReferenceUnavailable("Successful F4 rebuild evidence required")
    doc = json.loads(_read(path))
    if (
        type(doc.get("schema_version")) is not int
        or doc["schema_version"] != 1
        or doc.get("commitment_id") != COMMITMENT
        or doc.get("flashprove_revision") != REVISION
    ):
        raise ReferenceUnavailable("Unrecognized reference model provenance")
    files = doc["sha256"]
    if (
        not isinstance(files, dict)
        or files.keys() != _FILES
        or files.get("wsums.txt") != _WSUMS
        or files.get("KL.bin") != _KL
        or any(
            not isinstance(v, str) or not re.fullmatch("[0-9a-f]{64}", v)
            for v in files.values()
        )
    ):
        raise ReferenceUnavailable("Incomplete or inconsistent reference digests")
    raw = _read(model_dir / "integer_model.json")
    if hashlib.sha256(raw).hexdigest() != files["integer_model.json"]:
        raise ReferenceUnavailable("Model settings differ from the protected manifest")
    model = json.loads(raw)
    weights = model.get("weight_settings")
    if (
        model.get("weights") != "blocks"
        or not isinstance(weights, dict)
        or weights.get("blocks") != "gguf"
        or weights.get("verify_sums") is not True
    ):
        raise ReferenceUnavailable("Every GGUF tensor must be verified")
    return dict(files)


@dataclass(repr=False)
class ReferenceScorer:
    """Load once per isolated reference worker. Each call scores a fresh private sequence."""

    _model: Any
    _range_failure: type[Exception]
    _chunk_size: int
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    @classmethod
    def load(
        cls,
        model_dir: Path,
        manifest: Path,
        *,
        rebuild_report: Path,
        chunk_size: int = WINDOW,
    ) -> ReferenceScorer:
        """Load the real F4 GGUF through upstream's five-file and per-tensor verification."""
        if type(chunk_size) is not int or not 1 <= chunk_size <= WINDOW:
            raise ValueError("Invalid reference chunk size")
        try:
            digests = _manifest(model_dir, manifest, rebuild_report)
            runtime = _runtime()
            model = runtime.load_from_folder(model_dir, "cpu", {"sha256": digests})
            if model.weights.sums_verified is not True:
                raise ReferenceUnavailable("Pinned tensor verification incomplete")
            if (model.parameters.T, model.parameters.V) != (WINDOW, VOCABULARY_SIZE):
                raise ReferenceUnavailable(
                    "Reference shape differs from the commitment"
                )
            return cls(model, runtime.RangeConditionFailed, chunk_size)
        except Exception:  # noqa: BLE001 -- runtime errors may expose host paths.
            raise ReferenceUnavailable("Pinned reference model unavailable") from None

    def score(self, tokens: tuple[int, ...]) -> ReferenceTrace:
        """Return the choice predicting token p+1 at p, including all padding inputs."""
        p = self._model.parameters
        if (
            not isinstance(tokens, tuple)
            or len(tokens) != p.T
            or any(type(i) is not int or not 0 <= i < p.V for i in tokens)
        ):
            raise ValueError("Expected one complete reference token window")
        try:
            with self._lock:
                seq = self._model.new_sequence()
                try:
                    return self._score(seq, tokens)
                finally:
                    self._model.free(seq)
        except Exception:  # noqa: BLE001 -- preserve neither device diagnostics nor private tokens.
            raise ReferenceUnavailable("Reference execution unavailable") from None

    def _score(self, seq: Any, tokens: tuple[int, ...]) -> ReferenceTrace:
        choices: list[int] = []
        recorded: list[Any] = []

        def observe(name: str, layer: int | None, value: Any) -> None:
            if name == "first_choice" and layer is None:
                recorded.append(value)

        for start in range(0, len(tokens), self._chunk_size):
            chunk = tokens[start : start + self._chunk_size]
            # extend() records first_choice before raising a typed range fault. Causality
            # makes earlier rows valid; entries at/after the first fault are unusable.
            recorded.clear()
            position = condition = None
            try:
                output = self._model.extend(seq, chunk, record=observe)
            except self._range_failure as fault:
                position = getattr(fault, "position", None)
                condition = getattr(fault, "condition", None)
                if (
                    type(position) is not int
                    or not start <= position < start + len(chunk)
                    or type(condition) is not int
                    or not 1 <= condition <= 8
                    or seq.failure is not fault
                    or len(recorded) != 1
                ):
                    raise ReferenceUnavailable(
                        "Invalid reference range evidence"
                    ) from None
                output = recorded[0]
            values = output.tolist()
            if (
                seq.length != start + len(chunk)
                or not isinstance(values, list)
                or len(values) != len(chunk)
            ):
                raise ReferenceUnavailable("Incomplete reference choices")
            valid = values if position is None else values[: position - start]
            if any(
                type(token) is not int or not 0 <= token < self._model.parameters.V
                for token in valid
            ):
                raise ReferenceUnavailable("Invalid reference choice")
            choices.extend(valid)
            if position is not None:
                return ReferenceTrace(tuple(choices), position, condition)
        return ReferenceTrace(tuple(choices))
