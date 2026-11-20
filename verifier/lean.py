"""Optional CPU cross-check with FlashProve's provisioned Lean verifier."""

from __future__ import annotations

import fcntl
import hashlib
import math
import os
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from prover.artifacts import sha256_stream, trusted_file
from prover.submission import COMMITMENT, SpoolError, trusted_directory
from tools.check_hardware import check_verifier_cpu
from verifier.native_output import Outcome

# At FlashProve 9e2bdd8ff5bf9c62f18263d7dac189b0400b260c. The hash covers every
# tracked file of the Lean library, frontend, parser, C++ table generator and includes.
_ROOTS = ("blocks", "docs/format", "lean", "prover", "tools", "verifier")
_SOURCE_SHA256 = "5f8f7e9e3e5244f803c85b31a7eb8884eb6dceceaad25850c74a9043988dc47b"


@dataclass(frozen=True)
class LeanConfig:
    checkout: Path
    lake: Path
    temp: Path


def _pinned_source(root: Path) -> bool:
    files: list[Path] = []
    for subtree in _ROOTS:
        for folder, dirs, names in os.walk(root / subtree):
            path = Path(folder)
            if path == root / "lean" and ".lake" in dirs:
                dirs.remove(
                    ".lake"
                )  # separately provisioned build of the pinned dependencies
            for entry in (path, *(path / d for d in dirs)):
                info = entry.lstat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022
                ):
                    return False
            files.extend(path / name for name in names)
    digest = hashlib.sha256()
    for file in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
        info = file.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022
        ):
            return False
        with file.open("rb") as stream:
            digest.update(
                file.relative_to(root).as_posix().encode()
                + b"\0"
                + bytes.fromhex(sha256_stream(stream))
            )
    return digest.hexdigest() == _SOURCE_SHA256


def _verdict(code: int, stdout: bytes) -> Outcome:
    if code == 0 and stdout == b"VERDICT: ACCEPT (exact match)\n":
        return "verified"
    if code == 1 and stdout == b"VERDICT: REJECT\n":
        return "rejected"
    return "unavailable"


def _stop(process: subprocess.Popen[bytes]) -> None:
    # The official shell's TERM trap forwards the signal to its active job. GNU
    # timeout starts additional groups inside our session; also terminate survivors.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    for entry in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = entry.read_bytes().rsplit(b") ", 1)[1].split()
            if int(fields[3]) == process.pid:
                os.kill(int(entry.parent.name), signal.SIGKILL)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    if process.poll() is None:
        process.kill()
    process.wait()


def _run(config: LeanConfig, work: Path, scratch: Path, deadline: float) -> Outcome:
    env = {
        "PATH": f"{config.lake.parent}:/usr/bin:/bin",
        "HOME": str(scratch),
        "TMPDIR": str(scratch),
        "LC_ALL": "C",
    }
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return "unavailable"
    lake = subprocess.run(
        [str(config.lake), "--version"],
        cwd=config.checkout / "lean",
        env=env,
        capture_output=True,
        timeout=remaining,
        check=False,
    )
    if lake.returncode or not lake.stdout.strip().endswith(b"(Lean version 4.29.1)"):
        return "unavailable"
    argv = [
        str(config.checkout / "tools/lean-verify/lean_verify.sh"),
        *[
            str(work / p)
            for p in (
                "config",
                "ivk",
                "request.bin",
                "y.bin",
                "proof.bin",
                "commitment.id",
            )
        ],
    ]
    with tempfile.TemporaryFile(dir=scratch) as stdout:
        proc = subprocess.Popen(
            argv,
            cwd=scratch,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            code = proc.wait(timeout=max(0, deadline - time.monotonic()))
        finally:
            if proc.poll() is None:
                _stop(proc)
        stdout.seek(0)
        return _verdict(code, stdout.read(64))


def check_lean(config: LeanConfig, work: Path, *, timeout_seconds: float) -> Outcome:
    """Check NativeVerifier's privately staged files. Only the script's one-line verdict escapes."""
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        return "unavailable"
    deadline = time.monotonic() + timeout_seconds
    try:
        check_verifier_cpu()
        if (
            not all(
                p.is_absolute()
                for p in (config.checkout, config.lake, config.temp, work)
            )
            or config.lake.name != "lake"
            or (work / "commitment.id").read_bytes()
            != (COMMITMENT + "\n").encode("ascii")
        ):
            return "unavailable"
        with (
            trusted_directory(config.checkout),
            trusted_file(config.lake),
            trusted_directory(config.temp) as tempfd,
            trusted_directory(config.checkout / "lean/.lake") as cache,
        ):
            attributes = os.fstat(tempfd)
            if (
                attributes.st_uid != os.geteuid()
                or attributes.st_mode & 0o077
                or os.fstat(cache).st_uid != os.geteuid()
            ):
                return "unavailable"
            # Upstream requires only one user of a compiled checkout at a time.
            fcntl.flock(cache, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not _pinned_source(config.checkout):
                return "unavailable"
            with tempfile.TemporaryDirectory(dir=config.temp) as tmp:
                return _run(config, work, Path(tmp), deadline)
    except (OSError, ValueError, SpoolError, subprocess.SubprocessError):
        return "unavailable"
