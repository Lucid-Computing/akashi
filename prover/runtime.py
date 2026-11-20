"""Launch the pinned single-request FlashProve service and stop it through its spool."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from prover.artifacts import sha256_stream, trusted_file
from prover.submission import (
    COMMITMENT,
    SpoolError,
    check_spool,
    guarded_spool,
    private_directory,
    trusted_directory,
)
from tools.check_hardware import check_hardware

REVISION = "9e2bdd8ff5bf9c62f18263d7dac189b0400b260c"
SEED_SHA256 = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
# cp_prove.cu --setting, base.cuh print_setting(-1), common/setting.h, blocks/frame/version.h.
SERVING_SETTING = (
    b"setting: field degree 3; requests: fold width 128, 5 repetitions mod q; "
    b"opening: fold width 168, 5 repetitions mod q; identities up to 2^28 keys; "
    b"folds inside 2^17; version word 825374792; a serving build\n"
)


class RuntimeUnavailable(RuntimeError):
    """A missing prerequisite, failed launch, stop or hold."""


@dataclass(frozen=True)
class RuntimeConfig:
    binary: Path
    build_manifest: Path
    secret_key: Path
    public_seed: Path
    spool: Path
    home: Path
    temp: Path
    gpu: int

    def command(self) -> list[str]:
        return [
            str(self.binary),
            "-isk",
            str(self.secret_key),
            "-public-weights",
            str(self.public_seed),
            "-spool",
            str(self.spool),
            "-batch",
            "1",
            "-in-step",
            "1",
            "-memory",
            "lean,tensor-rooms=8",
        ]


def _host(gpu: int) -> None:
    if os.geteuid() == 0:
        raise RuntimeUnavailable("Use the dedicated prover service account")
    check_hardware()
    name = subprocess.check_output(
        ["nvidia-smi", f"--id={gpu}", "--query-gpu=name", "--format=csv,noheader"],
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if not re.fullmatch(r"[^\n]*\bH100\b[^\n]*", name.strip()):
        raise RuntimeUnavailable("Configured proving device is not the measured H100")


def _pin(binary: BinaryIO, config: RuntimeConfig) -> None:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        fields = dict(pairs)
        if len(fields) != len(pairs):
            raise RuntimeUnavailable("Duplicate prover build field")
        return fields

    with trusted_file(config.build_manifest) as manifest:
        doc = json.load(manifest, object_pairs_hook=unique)
    if (
        not isinstance(doc, dict)
        or type(doc.get("schema_version")) is not int
        or doc["schema_version"] != 1
        or doc.get("flashprove_revision") != REVISION
        or doc.get("commitment_id") != COMMITMENT
        or doc.get("cp_prove_sha256")
        != sha256_stream(binary)
    ):
        raise RuntimeUnavailable(
            "Prover build attestation does not match this executable"
        )
    with trusted_file(config.public_seed) as seed:
        if sha256_stream(seed) != SEED_SHA256:
            raise RuntimeUnavailable("Wrong published Maverick seed")


def _executable(fd: int) -> str:
    # F31 and cp_prove's own reduced-environment re-exec both require Linux /proc.
    return f"/proc/self/fd/{fd}"


def _empty_file(directory: int, name: str) -> None:
    try:
        marker = os.open(
            name,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
    except FileExistsError:
        if name == "stop":
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return  # cp_prove consumed it concurrently; the caller checks exit and retries.
            if not stat.S_ISREG(info.st_mode) or info.st_size:
                raise RuntimeUnavailable("Invalid spool stop marker")
        return
    try:
        os.fsync(marker)
    finally:
        os.close(marker)
    os.fsync(directory)


class ProverProcess:
    """Supervise one process. A live PID supplies no proof or readiness indication."""

    def __init__(self, child: subprocess.Popen[bytes], spool_fd: int) -> None:
        self._child = child
        self._spool_fd = spool_fd
        self._lock = threading.Lock()
        self._exited = threading.Event()
        self._hold_error = False
        threading.Thread(target=self._watch, name="prover-exit", daemon=True).start()

    @classmethod
    def start(cls, config: RuntimeConfig) -> ProverProcess:
        if (
            type(config.gpu) is not int
            or config.gpu < 0
            or not all(
                p.is_absolute()
                for p in (
                    config.binary,
                    config.build_manifest,
                    config.secret_key,
                    config.public_seed,
                    config.spool,
                    config.home,
                    config.temp,
                )
            )
        ):
            raise RuntimeUnavailable("Invalid prover host configuration")
        try:
            _host(config.gpu)
            for folder in (config.home, config.temp):
                with private_directory(folder):
                    pass
            # An actual cp_commit ISK contains seed.bin and isk.txt. Its contents
            # remain untouched: cp_prove validates the key/counter and takes its lock.
            with trusted_directory(config.secret_key.parent) as parent:
                key_dir = os.open(
                    config.secret_key.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
                try:
                    info = os.fstat(key_dir)
                    if (
                        info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) != 0o700
                    ):
                        raise RuntimeUnavailable(
                            "Invalid prover key directory ownership or mode"
                        )
                finally:
                    os.close(key_dir)
            environment = {
                "CUDA_VISIBLE_DEVICES": str(config.gpu),
                "HOME": str(config.home),
                "TMPDIR": str(config.temp),
            }
            with guarded_spool(config.spool) as spool, trusted_file(config.binary) as binary:
                _pin(binary, config)
                # Execute the verified inode even if the deployment pathname is swapped.
                fd = binary.fileno()
                executable = _executable(fd)
                binary.seek(0)
                probe = subprocess.run(
                    [str(config.binary), "--setting"],
                    executable=executable,
                    pass_fds=(fd,),
                    cwd=config.home,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                if probe.returncode or probe.stdout != SERVING_SETTING:
                    raise RuntimeUnavailable(
                        "cp_prove does not report the pinned serving build"
                    )
                binary.seek(0)
                check_spool(spool)
                child = subprocess.Popen(
                    config.command(),
                    executable=executable,
                    pass_fds=(fd,),
                    cwd=config.home,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return cls(child, os.dup(spool))
        except RuntimeUnavailable:
            raise
        except (SpoolError, OSError, ValueError, subprocess.SubprocessError):
            raise RuntimeUnavailable("Prover prerequisites unavailable") from None

    def _watch(self) -> None:
        code = self._child.wait()
        with self._lock:
            try:
                if code != 0:
                    _empty_file(self._spool_fd, "hold")
            except OSError:
                self._hold_error = True
            finally:
                os.close(self._spool_fd)
                self._exited.set()

    def poll(self) -> int | None:
        if not self._exited.is_set():
            return None
        if self._hold_error:
            raise RuntimeUnavailable("Failed to place exited prover on hold")
        return self._child.returncode

    def stop(self, *, timeout: float, poll_seconds: float) -> int:
        """Finish the in-flight batch. A timeout leaves the process under supervision."""
        if any(not math.isfinite(n) or n <= 0 for n in (timeout, poll_seconds)):
            raise ValueError("Positive finite stop intervals required")
        deadline = time.monotonic() + timeout
        while not self._exited.is_set():
            with self._lock:
                if not self._exited.is_set() and self._child.poll() is None:
                    _empty_file(self._spool_fd, "stop")
            left = deadline - time.monotonic()
            if left <= 0 and not self._exited.is_set():
                raise TimeoutError("Prover has not finished its graceful stop")
            self._exited.wait(min(max(left, 0), poll_seconds))
        result = self.poll()
        assert result is not None
        return result
