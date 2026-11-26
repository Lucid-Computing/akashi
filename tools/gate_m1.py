"""Run the CPU M1 gate and atomically record redacted evidence from public test fixtures."""

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import subprocess
import tempfile
import unittest
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
VECTORS = {
    "renderer": ("tests.test_renderer", "tests.test_render_goldens"),
    "commitment": ("tests.test_receipts",),
    "log": ("tests.test_merkle_vectors", "tests.test_log_verification"),
    "beacon": ("tests.test_beacon",),
    "proof_request": ("tests.test_proof_request",),
    "pickup": ("tests.test_pickup_crypto",),
}


MODE_D_EXPECTED: dict[str, object] = {
    "mode": "D",
    "engine": "mock",
    "prover": "mock",
    "logged": 3,
    "promises_verified": 3,
    "selected": 1,
    "unselected": 1,
    "gaps": 1,
    "handed_off": 1,
    "mock_proofs": 1,
    "recomputed": 3,
    "failure_controls": 2,
}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, report: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=path.parent, mode="w", encoding="utf8", delete=False
    ) as f:
        try:
            json.dump(report, f, sort_keys=True, indent=2, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
            os.replace(f.name, path)
        finally:
            Path(f.name).unlink(missing_ok=True)


def _assets(directory: Path, manifest: dict[str, Any]) -> Path:
    supplied = os.environ.get("AKASHI_RENDER_ASSETS")
    root = Path(supplied) if supplied else directory
    for name in ("tokenizer.json", "tokenizer_config.json"):
        if not supplied:
            url = f"https://huggingface.co/{manifest['asset_repository']}/resolve/{manifest['asset_revision']}/{name}"
            subprocess.run(
                [
                    "curl",
                    "--fail",
                    "--location",
                    "--silent",
                    "--show-error",
                    "--retry",
                    "3",
                    url,
                    "--output",
                    str(root / name),
                ],
                check=True,
            )
        if _digest(root / name) != manifest["assets"][name]:
            raise ValueError("Pinned renderer digest mismatch")
    return root


def gate(output: Path) -> bool:
    suites: dict[str, object] = {}
    report: dict[str, object] = {
        "schema_version": 1,
        "gate": "M1",
        "execution": "CPU mock",
        "status": "running",
        "vectors": suites,
    }
    _write(output, report)
    stage = "environment"
    try:
        manifest = json.loads((FIXTURES / "render-goldens/manifest.json").read_text())
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT
            )
        )
        report["source"] = {
            "commit": revision,
            "dirty": dirty,
            "flashprove_commit": manifest["flashprove_revision"],
        }
        report["environment"] = {
            "python": platform.python_version(),
            "os": platform.system(),
            "machine": platform.machine(),
            "packages": {
                pkg: importlib.metadata.version(pkg)
                for pkg in (
                    "cryptography",
                    "tokenizers",
                    "py-ecc",
                    "PyNaCl",
                    "rfc8785",
                    "Jinja2",
                )
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            stage = "renderer_assets"
            assets = _assets(Path(tmp), manifest)
            # unittest decorators in the existing renderer suites inspect this variable at import.
            with patch.dict(os.environ, {"AKASHI_RENDER_ASSETS": str(assets)}):
                for stage, modules in VECTORS.items():
                    suite = unittest.defaultTestLoader.loadTestsFromNames(list(modules))
                    result = unittest.TextTestRunner(
                        stream=io.StringIO(), verbosity=0
                    ).run(suite)
                    good = (
                        result.wasSuccessful()
                        and result.testsRun > 0
                        and not result.skipped
                    )
                    suites[stage] = {
                        "tests": result.testsRun,
                        "skipped": len(result.skipped),
                        "passed": bool(good),
                        "public_fixture_sources": {
                            mod: _digest(ROOT / (mod.replace(".", "/") + ".py"))
                            for mod in modules
                        },
                    }
                    if not good:
                        raise ValueError("Required vector failed or skipped")
                stage = "mode_d_flow"
                from tests.m1_flow import run_flow

                observed = run_flow(assets)
                expected = MODE_D_EXPECTED
                fixture_hash = observed.get("fixture_sha256")
                if (
                    observed.keys() != expected.keys() | {"fixture_sha256"}
                    or any(
                        type(observed[k]) is not type(v) or observed[k] != v
                        for k, v in expected.items()
                    )
                    or not isinstance(fixture_hash, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", fixture_hash)
                ):
                    raise ValueError("CPU flow differs from the fixed fixture contract")
                report["mode_d"] = {"expected": expected, "observed": observed}
        stage = "fixture_inventory"
        from tests.test_proof_request import VECTORS as STATEMENTS

        report["public_fixtures"] = {
            "renderer": {
                "cases": manifest["cases"],
                "corpus_sha256": _digest(FIXTURES / "render-goldens/chat.jsonl"),
                "asset_revision": manifest["asset_revision"],
                "assets": manifest["assets"],
            },
            "merkle_sha256": _digest(FIXTURES / "merkle-v1.json"),
            "pickup_sha256": _digest(FIXTURES / "pickup-v1.json"),
            "nonce_free_statement_sha256": {
                name: hashlib.sha256(reference).hexdigest()
                for name, _, _, reference in STATEMENTS
            },
        }
        report["status"] = "passed"
    except Exception:  # noqa: BLE001 -- record the failing gate without serializing diagnostics or private data.
        report.update(status="failed", failed_stage=stage)
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    _write(output, report)
    return report["status"] == "passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/gates/m1.json")
    output = parser.parse_args().output
    passed = gate(output)
    print(f"M1 {'passed' if passed else 'failed'}. Evidence is in {output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
