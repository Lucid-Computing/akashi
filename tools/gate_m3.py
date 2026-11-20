"""Run the isolated R1–R19 controls and archive their checked, redacted reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tools.gate_m1 import ROOT, _write


def gate(directory: Path) -> bool:
    target = directory / "m3.json"
    result: dict[str, object] = {
        "schema_version": 1,
        "gate": "M3",
        "execution": "CPU defensive regression fixtures",
        "status": "incomplete",
    }
    _write(target, result)
    stage = "source"
    try:
        from redteam.aggregate import checked_report
        from redteam.evidence_regressions import SUITES
        from redteam.evidence_regressions import gate as run_suite

        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        result.update(
            source_revision=revision,
            dirty=bool(
                subprocess.check_output(
                    ["git", "status", "--porcelain", "--untracked-files=normal"],
                    cwd=ROOT,
                )
            ),
        )
        stage = "regression_suites"
        reports: dict[str, dict[str, Any]] = {}
        digests: dict[str, str] = {}
        failed: list[str] = []
        with tempfile.TemporaryDirectory(dir=directory) as tmp:
            for suite in SUITES:
                name = f"m3-{suite}.json"
                part = Path(tmp) / name
                if not run_suite(part, suite=suite):
                    failed.append(suite)
                raw = part.read_bytes()
                reports[suite] = json.loads(raw)
                digests[name] = hashlib.sha256(raw).hexdigest()
                os.replace(part, directory / name)
        result["artifacts"] = digests
        if failed:
            result.update(status="failed", failed_suites=failed)
        else:
            stage = "aggregate"
            result.update(checked_report(reports, revision=revision, root=ROOT))
            result["status"] = "passed"
    except (
        ImportError,
        KeyError,
        TypeError,
        ValueError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        result.update(failed_stage=stage, reason=type(exc).__name__)
    _write(target, result)
    return result["status"] == "passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/gates")
    directory = parser.parse_args().directory
    passed = gate(directory)
    print(
        f"M3 {'passed' if passed else 'did not pass'}. Evidence is in {directory / 'm3.json'}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
