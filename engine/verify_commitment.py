"""Rebuild the pinned public Maverick commitment using provisioned local inputs."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

REVISION = "9e2bdd8ff5bf9c62f18263d7dac189b0400b260c"
COMMITMENT = "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46"
# SET_SHA256 in the pinned scales/make_calibration_set.py
CALIBRATION = "a2ce04bd55b1b6fa2b9148744e087f5a2a484c1b3d525ea9fb2fc1ab8c6c2c02"
EXAMPLE = Path("examples/maverick")


class RebuildFailure(Exception):
    """A public input name or stage diagnostic safe to include in the evidence."""


def git(directory: Path, *args: str) -> bytes:
    # Limit Git to this checkout and its actual commit objects.
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *args],
            cwd=directory,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        raise RebuildFailure("FlashProve checkout") from None


def digests(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (\S+)", line)
        if not match or match[2] in values:
            raise RebuildFailure("digest inventory")
        values[match[2]] = match[1]
    return values


def rebuild(source: Path, weights: Path, work: Path, observed: dict[str, str]) -> None:
    if git(source, "rev-parse", "HEAD").strip().decode() != REVISION:
        raise RebuildFailure("FlashProve revision")
    if git(source, "status", "--porcelain", "--ignored", "--untracked-files=all"):
        raise RebuildFailure(
            "FlashProve checkout must be clean, including ignored files"
        )
    if not weights.is_dir():
        raise RebuildFailure("weights directory")
    if work.is_relative_to(weights) or work.is_relative_to(source):
        raise RebuildFailure("work directory must be separate from inputs")
    try:
        work.mkdir(mode=0o700)
    except OSError:
        raise RebuildFailure(
            "work directory must be new with a writable parent"
        ) from None
    # Build the pinned objects in isolation from local Git index flags and working-tree files.
    git(
        work,
        "clone",
        "--local",
        "--no-hardlinks",
        "--no-checkout",
        "--",
        str(source),
        "source",
    )
    checkout = work / "source"
    git(checkout, "checkout", "--detach", REVISION)
    shards = digests(checkout / EXAMPLE / "weights.sha256")
    expected = digests(checkout / EXAMPLE / "expected.txt")
    if expected.get("commitment-id") != COMMITMENT:
        raise RebuildFailure("published commitment")
    for name in (
        *shards,
        *(name + ".weights-are-public" for name in shards),
        "calibration_set.npy",
    ):
        if (weights / name).is_symlink() or not (weights / name).is_file():
            raise RebuildFailure(name)
    observed["public-seed.bin"] = hashlib.sha256(
        (checkout / EXAMPLE / "public-seed.bin").read_bytes()
    ).hexdigest()
    calibration = weights / "calibration_set.npy"
    if calibration.stat().st_size != 131200:  # pinned run.sh stage_needs
        raise RebuildFailure("calibration_set.npy")
    observed["calibration_set.npy"] = hashlib.sha256(
        calibration.read_bytes()
    ).hexdigest()
    if observed["calibration_set.npy"] != CALIBRATION:
        raise RebuildFailure("calibration_set.npy")
    run_dir = work / "run"
    env = {
        key: os.environ[key]
        for key in ("PATH", "CUDA_VISIBLE_DEVICES")
        if key in os.environ
    }
    env["LC_ALL"] = "C"
    for stage in ("needs", "build", "checksums", "fit", "commit", "compare"):
        # Upstream logs can contain local paths and model-derived data. Keep them in private work.
        with (work / f"{stage}.log").open("xb") as log:
            status = subprocess.run(
                [
                    str(EXAMPLE / "run.sh"),
                    stage,
                    str(run_dir),
                    "--weights",
                    str(weights),
                ],
                cwd=checkout,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            ).returncode
        if stage == "checksums":
            if status == 0:
                observed.update(shards)  # sha256sum -c succeeded for every pinned shard
            else:
                checks = run_dir / "logs/checksums.1.log"
                if checks.is_file():
                    lines = checks.read_bytes().splitlines()
                    for name in shards:
                        if f"{name}: FAILED".encode() in lines:
                            raise RebuildFailure(name)
        if stage == "compare":
            made = run_dir / "logs/made.1.log"
            if made.is_file():
                actual = digests(made)
                for name, digest in expected.items():
                    if name not in actual:
                        raise RebuildFailure(name)
                    observed[name] = actual[name]
                    if actual[name] != digest:
                        raise RebuildFailure(name)
            elif status == 0:
                raise RebuildFailure("comparison evidence")
        if status:
            raise RebuildFailure(f"FlashProve stage {stage} (exit {status})")


def main() -> int:
    parser = argparse.ArgumentParser(
        usage=f"%(prog)s [--flashprove PATH] [--weights PATH] [--work PATH]\npublished commitment: {COMMITMENT}",
        description=__doc__,
    )
    parser.add_argument("--flashprove", type=Path, default=os.getenv("FLASH_PROVE_DIR"))
    parser.add_argument("--weights", type=Path, default=os.getenv("WEIGHTS_DIR"))
    parser.add_argument("--work", type=Path, default=os.getenv("COMMITMENT_WORK_DIR"))
    args = parser.parse_args()
    observed: dict[str, str] = {}
    report: dict[str, object] = {
        "schema_version": 1,
        "published_commitment": COMMITMENT,
        "passed": False,
        "observed": observed,
    }
    try:
        for value, name in (
            (args.flashprove, "--flashprove"),
            (args.weights, "--weights"),
            (args.work, "--work"),
        ):
            if value is None:
                raise RebuildFailure(name)
        rebuild(
            args.flashprove.resolve(),
            args.weights.resolve(),
            args.work.resolve(),
            observed,
        )
    except RebuildFailure as error:
        report["failing_input"] = str(error)
    except (OSError, UnicodeError) as error:
        report["failing_input"] = f"local artifact I/O ({type(error).__name__})"
    else:
        report["passed"] = True
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
