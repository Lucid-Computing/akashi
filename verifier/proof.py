"""Positional FlashProve verification against independently provisioned public inputs."""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import struct
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol

from prover.artifacts import (
    SpoolError,
    private_directory,
    sha256_stream,
    trusted_directory,
    trusted_file,
)
from prover.request import (
    COMMITMENT,
    REVISION,
    VOCABULARY_SIZE,
    WINDOW,
    CandidateProof,
    Divergence,
    build_statement,
    deviation_statement,
    reply_complete,
)
from tools.check_hardware import check_verifier_cpu
from verifier.native_output import Outcome, native_outcome

if TYPE_CHECKING:
    from verifier.lean import LeanConfig

# Published F4 values, examples/maverick/expected.txt.
_PUBLIC = {
    "config/KL.bin": "df29bd823d62431945c3124138ed52e1f677db9224c4196505a91663ac48ab1a",
    "ivk/key.bin": "178d8814def56f88fae45f273c7f70152dac887ddc9075b6aca2f895c24c7c38",
    "ivk/leaf/0.bin": "e9dea311bb78bba70e6ec5db0196d5c4eba57498b0e8e4321d313025896c8dd0",
}
_ATTESTED = {"cp_verify", "config/policy.txt", "config/layout.txt"}


class ProofChecker(Protocol):
    def check(self, statement: bytes, y: bytes, proof: bytes) -> Outcome: ...


@dataclass(frozen=True)
class Verification:
    outcome: Literal[
        "verified",
        "rejected",
        "unavailable",
        "statement_mismatch",
        "incomplete",
        "disagreement",
    ]
    primary: Outcome | None = None
    secondary: Outcome | None = None


def verify_reply(
    prompt: tuple[int, ...],
    served: tuple[int, ...],
    max_tokens: int,
    candidate: CandidateProof | None,
    primary: ProofChecker,
    *,
    divergence: Divergence | None = None,
    secondary: ProofChecker | None = None,
) -> Verification:
    """Compare private evidence with the holder's reconstruction before running either verifier."""
    if type(max_tokens) is not int or not 1 <= max_tokens <= min(
        256, WINDOW - len(prompt)
    ):
        return Verification("statement_mismatch")
    if not served:
        return Verification("incomplete")
    try:
        statement = (
            build_statement(prompt, served)
            if divergence is None
            else deviation_statement(prompt, served, divergence)
        )
    except (ValueError, TypeError):
        return Verification("statement_mismatch")
    if not reply_complete(served, max_tokens):
        return Verification("incomplete")
    if candidate is None or not candidate.proof:
        return Verification("unavailable")
    if candidate.statement != statement or candidate.y != bytes(4):
        return Verification("statement_mismatch")
    first = primary.check(statement, bytes(4), candidate.proof)
    if secondary is None:
        return Verification(first, first)
    other = secondary.check(statement, bytes(4), candidate.proof)
    return Verification(first if first == other else "disagreement", first, other)


@dataclass(frozen=True)
class NativeVerifier:
    binary: Path
    manifest: Path
    config_dir: Path
    public_key_dir: Path
    timeout_seconds: float
    memory_bytes: int
    max_proof_bytes: int

    def __post_init__(self) -> None:
        if (
            not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or any(
                type(n) is not int or n <= 0
                for n in (self.memory_bytes, self.max_proof_bytes)
            )
            or not all(
                p.is_absolute()
                for p in (
                    self.binary,
                    self.manifest,
                    self.config_dir,
                    self.public_key_dir,
                )
            )
        ):
            raise ValueError(
                "Explicit verifier paths and positive host limits are required"
            )

    @contextmanager
    def workspace(self) -> Iterator[Path]:
        parent = Path(tempfile.gettempdir())
        with (
            trusted_directory(parent),
            tempfile.TemporaryDirectory(prefix="akashi-verify-", dir=parent) as private,
        ):
            yield Path(private)

    def stage(
        self, work: Path, statement: bytes, y: bytes, proof: bytes
    ) -> tuple[dict[str, str], str]:
        """Snapshot verifier-only inputs in a private directory shared with the chosen backend."""
        with private_directory(work):
            if any(work.iterdir()):
                raise ValueError("An empty private verification directory is required")
        if (
            len(statement) != (WINDOW + 2) * 4
            or len(y) != 4
            or not 1 <= len(proof) <= self.max_proof_bytes
        ):
            raise ValueError("Invalid verifier inputs")
        words = struct.unpack(f"<{WINDOW + 2}I", statement)
        r, e = words[-2:]
        if (
            not 0 <= r < e <= WINDOW
            or max(words[:-2]) >= VOCABULARY_SIZE
            or (e < WINDOW and y != bytes(4))
            or int.from_bytes(y, "little") >= VOCABULARY_SIZE
        ):
            raise ValueError("Invalid verifier statement")
        with trusted_file(self.manifest) as stream:
            manifest = json.load(stream)
        if (
            not isinstance(manifest, dict)
            or type(manifest.get("schema_version")) is not int
            or manifest["schema_version"] != 1
            or manifest.get("flashprove_revision") != REVISION
            or manifest.get("commitment_id") != COMMITMENT
        ):
            raise ValueError("Invalid verifier provisioning manifest")
        digests = manifest.get("sha256")
        if (
            not isinstance(digests, dict)
            or digests.keys() != _ATTESTED
            or any(
                not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v)
                for v in digests.values()
            )
        ):
            raise ValueError("Missing verifier attestation")
        for folder in ("config", "ivk", "ivk/leaf"):
            (work / folder).mkdir(mode=0o700)
        # cp_verify authenticates additional leaves against the trusted key. F4 publishes leaf zero.
        leaf = (
            int.from_bytes(proof[8:12], "little")
            if proof.startswith(b"CPPF") and len(proof) >= 12
            else 0
        )
        inputs = {
            "config/policy.txt": self.config_dir / "policy.txt",
            "config/layout.txt": self.config_dir / "layout.txt",
            "config/KL.bin": self.config_dir / "KL.bin",
            "ivk/key.bin": self.public_key_dir / "key.bin",
            f"ivk/leaf/{leaf}.bin": self.public_key_dir / "leaf" / f"{leaf}.bin",
        }
        for name, source in inputs.items():
            with trusted_file(source) as src, (work / name).open("xb") as dest:
                shutil.copyfileobj(src, dest)
            expected = _PUBLIC.get(name, digests.get(name))
            if expected is not None:
                with (work / name).open("rb") as copied:
                    if sha256_stream(copied) != expected:
                        raise ValueError(
                            "Public verification files differ from the pinned inputs"
                        )
        for filename, data in (
            ("request.bin", statement),
            ("y.bin", y),
            ("proof.bin", proof),
            ("commitment.id", (COMMITMENT + "\n").encode()),
        ):
            (work / filename).write_bytes(data)
        wanted = {"version", "C", "theta", "cap", "s", "sh", "sT", "F", "record"}
        policy = {}
        for line in (work / "config/policy.txt").read_text("ascii").splitlines():
            pair = line.split()
            if pair and pair[0] in wanted:
                if len(pair) != 2 or pair[0] in policy:
                    raise ValueError("Invalid policy")
                policy[pair[0]] = pair[1]
        if (
            policy.keys() != wanted
            or not re.fullmatch("[0-9]+", policy["s"])
            or (
                policy["C"],
                policy["theta"],
                policy["cap"],
                policy["sh"],
                policy["sT"],
                policy["F"],
                policy["record"],
            )
            != ("256", "256", "0", "8", "4", "24", "1")
        ):
            raise ValueError("Exact-match verification policy required")
        return policy, digests["cp_verify"]

    def check(self, statement: bytes, y: bytes, proof: bytes) -> Outcome:
        try:
            check_verifier_cpu()
            with (
                self.workspace() as work,
                trusted_file(self.binary) as binary,
            ):
                policy, digest = self.stage(work, statement, y, proof)
                if sha256_stream(binary) != digest:
                    return "unavailable"
                fd = binary.fileno()
                args = [
                    "/usr/bin/prlimit",
                    f"--as={self.memory_bytes}",
                    "--core=0",
                    "--",
                    f"/proc/self/fd/{fd}",
                    "config",
                    "ivk",
                    "request.bin",
                    "y.bin",
                    "proof.bin",
                    "-id",
                    COMMITMENT,
                    "-q",
                ]
                with tempfile.TemporaryFile(dir=work) as output:
                    child = subprocess.Popen(
                        args,
                        pass_fds=(fd,),
                        cwd=work,
                        env={
                            "PATH": os.defpath,
                            "LC_ALL": "C",
                            "HOME": str(work),
                            "TMPDIR": str(work),
                        },
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    try:
                        code = child.wait(self.timeout_seconds)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        finally:
                            child.wait()
                        return "unavailable"
                    output.seek(0)
                    return native_outcome(code, output.read(), statement, proof, policy)
        except (
            OSError,
            SpoolError,
            ValueError,
            TypeError,
            KeyError,
            subprocess.SubprocessError,
        ):
            return "unavailable"


@dataclass(frozen=True)
class LeanVerifier:
    """Independent backend for the same authenticated F4 files and reconstructed request."""

    inputs: NativeVerifier
    runtime: LeanConfig
    timeout_seconds: float

    def check(self, statement: bytes, y: bytes, proof: bytes) -> Outcome:
        from verifier.lean import check_lean

        try:
            check_verifier_cpu()
            with self.inputs.workspace() as work:
                self.inputs.stage(work, statement, y, proof)
                return check_lean(
                    self.runtime, work, timeout_seconds=self.timeout_seconds
                )
        except (
            OSError,
            SpoolError,
            ValueError,
            TypeError,
            KeyError,
            subprocess.SubprocessError,
        ):
            return "unavailable"
