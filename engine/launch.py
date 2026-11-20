"""Start the pinned integer engine and collect per-process RFC-0001 gate evidence."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engine.adapter import Canary, StartupEvidence

REVISION = "9e2bdd8ff5bf9c62f18263d7dac189b0400b260c"
COMMITMENT = "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46"
# FlashProve examples/maverick/expected.txt at REVISION.
F4 = {
    "model/wsums.txt": "689cd1d0e84e6c6059cd1c4056c8532a436d88f7fa3803d835d2964be33eb519",
    "config/KL.bin": "df29bd823d62431945c3124138ed52e1f677db9224c4196505a91663ac48ab1a",
    "ivk/key.bin": "178d8814def56f88fae45f273c7f70152dac887ddc9075b6aca2f895c24c7c38",
    "ivk/leaf/0.bin": "e9dea311bb78bba70e6ec5db0196d5c4eba57498b0e8e4321d313025896c8dd0",
    "commitment-id": COMMITMENT,
}
FILES = ("integer_model.json", "policy.txt", "KL.bin", "wsums.txt", "fold.txt")
FILE_LINE = (
    b"Verified: these files have the given SHA-256 digests: "
    + ", ".join(FILES).encode()
    + b"."
)
TENSOR_LINE = (
    b"Verified: every weight tensor has the SHA-256 that wsums.txt lists for it."
)
PACKAGE = Path("integrations/vllm/integer_model")


class LaunchError(RuntimeError):
    """Bounded diagnostic suitable for startup status."""


@dataclass(frozen=True)
class LaunchConfig:
    model: Path
    references: Path
    rebuild_report: Path
    rebuild_work: Path
    source: Path
    venv: Path
    home: Path
    temp: Path
    canary_file: Path
    dtype: str
    shutdown_grace_seconds: float


def _json(path: Path) -> dict[str, Any]:
    def unique(items: list[tuple[str, Any]]) -> dict[str, Any]:
        data = dict(items)
        if len(data) != len(items):
            raise LaunchError("Duplicate JSON member in engine configuration")
        return data

    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=unique)
    except (ValueError, OSError):
        raise LaunchError("Missing or invalid engine configuration") from None
    if not isinstance(value, dict):
        raise LaunchError("Invalid engine configuration")
    return value


def _trusted_file(path: Path) -> None:
    mode = path.lstat()
    if (
        not stat.S_ISREG(mode.st_mode)
        or mode.st_uid not in (0, os.geteuid())
        or mode.st_mode & 0o022
    ):
        raise LaunchError(
            "Engine evidence must be an administrator- or service-owned regular file"
        )


def _digest(path: Path) -> str:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise LaunchError("Invalid engine input file")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def load_canaries(config: LaunchConfig) -> tuple[Canary, ...]:
    _trusted_file(config.canary_file)
    doc = _json(config.canary_file)
    rows = doc.get("canaries")
    if (
        config.dtype not in ("float32", "bfloat16", "float16")
        or doc.get("dtype") != config.dtype
        or doc.get("commitment_id") != COMMITMENT
        or not isinstance(rows, list)
        or len(rows) != 3
    ):
        raise LaunchError("Missing measured dtype or three commitment-matched canaries")
    result = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "prompt",
            "max_tokens",
            "expected",
        }:
            raise LaunchError("Invalid measured canary")
        prompt, budget, expected = row["prompt"], row["max_tokens"], row["expected"]
        if (
            not isinstance(prompt, list)
            or not prompt
            or not isinstance(expected, list)
            or not expected
            or type(budget) is not int
            or not 1 <= len(expected) <= budget <= 256
            or len(prompt) + budget > 1024
            or any(
                type(x) is not int or not 0 <= x < 202048 for x in (*prompt, *expected)
            )
        ):
            raise LaunchError("Invalid measured canary")
        result.append(Canary(tuple(prompt), budget, tuple(expected)))
    if len({item.prompt for item in result}) != 3:
        raise LaunchError("Measured canary prompts must be distinct")
    return tuple(result)


def verify_artifacts(config: LaunchConfig) -> None:
    _trusted_file(config.rebuild_report)
    report = _json(config.rebuild_report)
    observed = report.get("observed")
    if (
        type(report.get("schema_version")) is not int
        or report["schema_version"] != 1
        or report.get("passed") is not True
        or report.get("published_commitment") != COMMITMENT
        or not isinstance(observed, dict)
        or any(observed.get(k) != v for k, v in F4.items())
    ):
        raise LaunchError("Missing successful F4 rebuild evidence")
    model = config.model.resolve(strict=True)
    refs = config.references.resolve(strict=True)
    if model == refs or refs.is_relative_to(model):
        raise LaunchError("Reference directory must be independent of the model")
    model_doc = _json(model / "integer_model.json")
    settings = model_doc.get("weight_settings")
    if (
        model_doc.get("weights") != "blocks"
        or not isinstance(settings, dict)
        or settings.get("blocks") != "gguf"
        or settings.get("verify_sums") is not True
        or not isinstance(settings.get("setup_folder"), str)
    ):
        raise LaunchError("GGUF tensor verification must be enabled")
    setup = (model / settings["setup_folder"]).resolve(strict=True)
    shards = settings.get("shards")
    names = [
        f"Llama-4-Maverick-17B-128E-Instruct-UD-Q4_K_XL-{n:05d}-of-00005.gguf"
        for n in range(1, 6)
    ]
    if not isinstance(shards, list) or len(shards) != 5:
        raise LaunchError("Missing pinned GGUF shards")
    for name, supplied in zip(names, shards, strict=True):
        if (
            not isinstance(supplied, str)
            or Path(supplied).name != name
            or not (model / supplied).is_file()
        ):
            raise LaunchError("Missing pinned GGUF shard")
    fit = config.rebuild_work / "run/fit.1"
    for name in FILES:
        actual = (model if name in FILES[:3] else setup) / name
        ref = refs / name
        if ref.samefile(actual) or _digest(actual) != _digest(ref):
            raise LaunchError(
                "Reference copies must independently match the engine files"
            )
        if name != "integer_model.json":
            fitted = (
                "config/" if name in ("KL.bin", "policy.txt") else "model/"
            ) + name
            value = _digest(fit / fitted)
            if value != _digest(ref) or (fitted in F4 and F4[fitted] != value):
                raise LaunchError("Engine files differ from the F4 rebuild")
    for name in ("ivk/key.bin", "ivk/leaf/0.bin"):
        if _digest(config.rebuild_work / "run/commitment.1" / name) != F4[name]:
            raise LaunchError("Rebuilt public verification keys differ from F4")
    hf = _json(model / "config.json")
    if (
        hf.get("architectures") != ["IntegerModelForCausalLM"]
        or hf.get("vocab_size") != 202048
        or hf.get("max_position_embeddings") != 1024
        or hf.get("eos_token_id") != [200001, 200007, 200008]
        or (model / "generation_config.json").exists()
    ):
        raise LaunchError(
            "Model directory does not match the pinned token configuration"
        )


def _environment(c: LaunchConfig) -> dict[str, str]:
    return {
        "PATH": f"{c.venv / 'bin'}:/usr/local/cuda/bin:/usr/bin:/bin",
        "HOME": str(c.home),
        "TMPDIR": str(c.temp),
        "LC_ALL": "C",
        "CUDA_VISIBLE_DEVICES": "0",
        "VLLM_USE_V2_MODEL_RUNNER": "1",
        "VLLM_NO_USAGE_STATS": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUNBUFFERED": "1",
        "GLOO_SOCKET_IFNAME": "lo",
    }


def _python(c: LaunchConfig, work: Path) -> list[str]:
    return [
        str(c.venv / "bin/python"),
        "-I",
        "-B",
        "-u",
        "-X",
        f"pycache_prefix={work / 'pycache'}",
    ]


def _checked(argv: list[str], cwd: Path, env: dict[str, str], label: str) -> None:
    code = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode
    if code != 0:
        raise LaunchError(label)


# Compare the installed distributions with the *same pinned sources* pytest will exercise.
_RUNTIME = """import hashlib, importlib.metadata as md, importlib.util, pathlib, platform, sys
import torch
src = pathlib.Path(sys.argv[1])
def require(ok):
    if not ok: raise SystemExit(1)
require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and sys.version_info[:2] == (3, 13))
for name, expected in [('vllm','0.29.0'), ('torch','2.13.0'), ('integer-model','0.16.0'), ('pytest','9.0.3')]:
    require(md.version(name).split('+')[0] == expected)
require(torch.cuda.is_available() and torch.cuda.device_count() == 1 and 'H100' in torch.cuda.get_device_name(0))
for name in ('integer_model','integer_model_vllm'):
    installed = pathlib.Path(importlib.util.find_spec(name).origin).parent
    def files(directory):
        return {p.relative_to(directory): hashlib.sha256(p.read_bytes()).digest() for p in directory.rglob('*.py')}
    require(files(src / name) == files(installed))
"""


def _pytest_passed(report: Path, expected: set[str]) -> None:
    try:
        root = ET.parse(report).getroot()
    except (OSError, ET.ParseError):
        raise LaunchError("Missing float64 test report") from None
    cases = list(root.iter("testcase"))
    names = [case.get("name", "") for case in cases]
    if (
        not expected
        or len(names) != len(expected)
        or set(names) != expected
        or any(
            not case.get("classname", "").endswith("test_arithmetic_edges")
            or any(case.find(k) is not None for k in ("skipped", "failure", "error"))
            for case in cases
        )
    ):
        raise LaunchError("Serving GPU float64 cases were missing, skipped or failed")


def verify_gpu(c: LaunchConfig, work: Path) -> None:
    env = _environment(c)
    py = _python(c, work)
    hardware = Path(__file__).resolve().parents[1] / "tools/check_hardware.py"
    _checked(
        [*py, str(hardware)], work, env, "Serving host does not meet F31 prerequisites"
    )
    repo = work / "source"
    git = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null"]
    git_env = {
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    _checked(
        [
            *git,
            "clone",
            "--local",
            "--no-hardlinks",
            "--no-checkout",
            "--",
            str(c.source),
            str(repo),
        ],
        work,
        git_env,
        "Pinned FlashProve source unavailable",
    )
    _checked(
        [*git, "checkout", "--detach", REVISION],
        repo,
        git_env,
        "Pinned FlashProve revision unavailable",
    )
    pkg = repo / PACKAGE
    _checked(
        [*py, "-c", _RUNTIME, str(pkg)],
        work,
        env,
        "Serving GPU, runtime or installed plugin differs from pin",
    )
    test_file = "tests/test_arithmetic_edges.py"
    test_env = {
        **env,
        "INTEGER_MODEL_TEST_DEVICE": "cuda",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    collect = subprocess.run(
        [
            *py,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            test_file,
        ],
        cwd=pkg,
        env=test_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    prefix = (test_file + "::").encode()
    expected = {
        line[len(prefix) :].decode("ascii")
        for line in collect.stdout.splitlines()
        if line.startswith(prefix)
    }
    if collect.returncode != 0 or not expected:
        raise LaunchError("Could not enumerate pinned float64 cases")
    report = work / "float64.xml"
    _checked(
        [
            *py,
            "-m",
            "pytest",
            "-rs",
            "-p",
            "no:cacheprovider",
            "--basetemp",
            str(work / "pytest"),
            "--junitxml",
            str(report),
            test_file,
        ],
        pkg,
        test_env,
        "Serving GPU float64 test failed",
    )
    _pytest_passed(report, expected)


def command(c: LaunchConfig, work: Path) -> list[str]:
    loader = json.dumps(
        {"reference_directory": str(c.references), "reference_files": 5},
        separators=(",", ":"),
    )
    return [
        *_python(c, work),
        str(c.venv / "bin/vllm"),
        "serve",
        str(c.model),
        "--served-model-name",
        "maverick-int",
        "--host",
        "127.0.0.1",
        "--load-format",
        "integer_model",
        "--max-num-seqs",
        "1",
        "--max-model-len",
        "1024",
        "--no-enable-prefix-caching",
        "--enforce-eager",
        "--generation-config",
        "vllm",
        "--fingerprint-mode",
        "none",
        "--max-logprobs",
        "0",
        "--disable-uvicorn-access-log",
        "--dtype",
        c.dtype,
        "--model-loader-extra-config",
        loader,
    ]


class StartupTracker:
    """One tracker per child. The sole owner of the child's pipe feeds complete lines."""

    def __init__(self, instance: str) -> None:
        self.instance = instance
        self._files = False
        self._tensors = False

    def observe(self, line: bytes) -> None:
        # vLLM can prepend a colored process name, level, timestamp and [loader.py:line].
        line = re.sub(rb"\x1b\[[0-9;]*m", b"", line).rstrip(b"\r\n")
        for marker in (FILE_LINE, TENSOR_LINE):
            if not line.endswith(marker):
                continue
            prefix = line[: -len(marker)]
            if prefix and not re.fullmatch(
                rb"[^\r\n]*\bINFO\b[^\r\n]*\[loader\.py:\d+\] ", prefix
            ):
                continue
            if marker == FILE_LINE:
                self._files = True
            elif self._files:
                self._tensors = True

    def evidence(self) -> StartupEvidence:
        if not (self._files and self._tensors):
            raise LaunchError(
                "Current process has not verified every reference and tensor"
            )
        return StartupEvidence(self.instance, COMMITMENT, True, True, True, True)


@dataclass
class StartedEngine:
    process: subprocess.Popen[bytes]
    instance: str
    startup: StartupTracker
    canaries: tuple[Canary, ...]
    _work: tempfile.TemporaryDirectory[str]

    shutdown_grace_seconds: float
    _closed: bool = field(default=False, init=False)

    def close(self) -> None:
        if self._closed:
            return
        deadline = time.monotonic() + self.shutdown_grace_seconds
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=self.shutdown_grace_seconds)
            except subprocess.TimeoutExpired:
                pass
            # Worker descendants can outlive the process that vLLM started first.
            while (remaining := deadline - time.monotonic()) > 0:
                os.killpg(self.process.pid, 0)
                time.sleep(min(remaining, 0.05))
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            self.process.wait()
            if self.process.stdout is not None:
                self.process.stdout.close()
            self._work.cleanup()
            self._closed = True


def start(config: LaunchConfig) -> StartedEngine:
    if (
        not math.isfinite(config.shutdown_grace_seconds)
        or config.shutdown_grace_seconds <= 0
    ):
        raise LaunchError("A positive finite engine shutdown grace is required")
    for value in (
        config.model,
        config.references,
        config.rebuild_report,
        config.rebuild_work,
        config.source,
        config.venv,
        config.home,
        config.temp,
        config.canary_file,
    ):
        if not value.is_absolute():
            raise LaunchError("Engine configuration paths must be absolute")
    if os.geteuid() == 0:
        raise LaunchError("Run the integer engine as its dedicated non-root account")
    for directory in (config.home, config.temp):
        mode = directory.lstat()
        if (
            not stat.S_ISDIR(mode.st_mode)
            or mode.st_uid != os.geteuid()
            or mode.st_mode & 0o077
        ):
            raise LaunchError(
                "Engine HOME and TMPDIR must be private service directories"
            )
    if not os.statvfs(config.model).f_flag & os.ST_RDONLY:
        raise LaunchError("A read-only model mount is required")
    canaries = load_canaries(config)
    verify_artifacts(config)
    temp = tempfile.TemporaryDirectory(dir=config.temp)
    try:
        work = Path(temp.name)
        verify_gpu(config, work)
        instance = uuid.uuid4().hex
        proc = subprocess.Popen(
            command(config, work),
            env=_environment(config),
            cwd=work,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        return StartedEngine(
            proc,
            instance,
            StartupTracker(instance),
            canaries,
            temp,
            config.shutdown_grace_seconds,
        )
    except BaseException:
        temp.cleanup()
        raise
