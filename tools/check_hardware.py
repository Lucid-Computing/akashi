#!/usr/bin/env python3
"""Check the real engine/prover host prerequisites in facts-register.md F31."""

import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def output(*command: str) -> str:
    return subprocess.check_output(
        command, text=True, stderr=subprocess.DEVNULL
    ).strip()


def check_hardware() -> None:
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        raise ValueError("requires x86-64 Linux")

    flags = re.findall(
        r"^flags\s*:\s*(.*)$", Path("/proc/cpuinfo").read_text(), re.MULTILINE
    )
    if not flags or any("sha_ni" not in row.split() for row in flags):
        raise ValueError("requires x86 SHA extensions")
    if sys.version_info[:2] != (3, 13):
        raise ValueError("requires Python 3.13")

    gpus = output("nvidia-smi", "--query-gpu=name", "--format=csv,noheader")
    if not re.search(r"\bH100\b", gpus):
        raise ValueError("requires an NVIDIA H100")
    for compiler in ("gcc", "g++"):
        if output(compiler, "-dumpfullversion").split(".")[0] != "13":
            raise ValueError(f"requires {compiler} 13")

    nvcc = shutil.which("nvcc")
    if nvcc is None:
        raise ValueError("requires nvcc on PATH")
    manifest = Path(nvcc).resolve().parents[1] / "version.json"
    toolkit = json.loads(manifest.read_text())
    if toolkit["cuda"]["version"] != "13.2.2":
        raise ValueError("requires CUDA Toolkit 13.2 Update 2")


if __name__ == "__main__":
    try:
        check_hardware()
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.CalledProcessError,
    ) as error:
        sys.exit(f"Hardware preflight failed: {error}")
    print("F31 host preflight passed. Model and proof gates require separate runs.")
