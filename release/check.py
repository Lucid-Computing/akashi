"""Produce a checksum-indexed local candidate only after validating its evidence."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from release.evidence import (
    MILESTONES,
    checked_files,
    document,
    fingerprint,
    require,
    sha,
    verify,
)
from tools.gate_m1 import ROOT, _write


def encoded(data: object) -> bytes:
    return (json.dumps(data, allow_nan=False, sort_keys=True, indent=2) + "\n").encode()


def check_source() -> str:
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT
    ):
        raise ValueError("candidate source has local changes")
    require(fingerprint(revision, 40), "missing source revision")
    return revision


def write_archive(target: Path, files: dict[str, bytes]) -> str:
    require(
        all(
            name
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", name)
            and ".." not in Path(name).parts
            and not name.endswith("/")
            for name in files
        )
        and "SHA256SUMS" not in files,
        "unsafe candidate member",
    )
    sums = "".join(
        f"{sha(data)}  {name}\n" for name, data in sorted(files.items())
    ).encode("ascii")
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted({**files, "SHA256SUMS": sums}.items()):
            entry = zipfile.ZipInfo(name)
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    digest = hashlib.sha256()
    with target.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def qualify(directory: Path | None, trusted: str | None, output: Path) -> bool:
    output.mkdir(parents=True, exist_ok=True)
    path = output / "status.json"
    target = output / "candidate.zip"
    with (output / ".release-check.lock").open("a+b") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        # A failed retry must not leave a publishable bundle from an older candidate.
        target.unlink(missing_ok=True)
        report: dict[str, Any] = {
            "schema_version": 1,
            "gate": "release",
            "status": "incomplete",
        }
        _write(path, report)
        stage = "evidence_inputs"
        try:
            missing = [
                n
                for n in MILESTONES
                if directory is None
                or not (directory / (n.lower() + ".json")).is_file()
            ]
            if missing:
                report["missing_milestones"] = missing
                raise ValueError("missing milestone inputs")
            if directory is None or not trusted:
                raise ValueError("missing trusted input manifest")
            stage = "candidate_source"
            revision = check_source()
            stage = "reviewed_manifest"
            checked_files(directory, trusted, revision)
            stage = "source_and_package_checks"
            subprocess.run(
                [
                    "make",
                    "docs-check",
                    "lint",
                    "test-private-operations",
                    "gate-m1",
                    "gate-m3",
                    "test-package",
                ],
                cwd=ROOT,
                check=True,
            )
            package = document((ROOT / "build/gates/package.json").read_bytes())
            require(
                type(package["schema_version"]) is int
                and package["schema_version"] == 1
                and package["gate"] == "package"
                and package["status"] == "passed"
                and package["source_revision"] == revision
                and package["receipt_exit"] == 30
                and package["altered_receipt_exit"] == 10,
                "clean installation missing",
            )
            stage = "milestone_chain"
            conclusions = verify(directory, trusted, revision, package)
            stage = "distribution"
            from tools.package_verifier import inspect_wheel

            name = package["wheel"]
            require(
                isinstance(name, str)
                and re.fullmatch(
                    r"akashi_verify-[A-Za-z0-9_.]+-py3-none-linux_x86_64\.whl", name
                ),
                "invalid wheel filename",
            )
            wheel = ROOT / "build/package" / name
            inspected = inspect_wheel(wheel)
            require(
                all(package[key] == value for key, value in inspected.items()),
                "package inventory differs",
            )
            files = {
                name: wheel.read_bytes(),
                "requirements.txt": (
                    ROOT / "build/package/requirements.txt"
                ).read_bytes(),
                "verifier-install-v1.json": (
                    ROOT / "build/package/verifier-install-v1.json"
                ).read_bytes(),
                "CHANGELOG.md": (ROOT / "CHANGELOG.md").read_bytes(),
                "SECURITY.md": (ROOT / "SECURITY.md").read_bytes(),
                "native-build.json": (
                    ROOT / "distribution/verifier/evidence/native-build.json"
                ).read_bytes(),
                "native-clean-install.json": (
                    ROOT / "distribution/verifier/evidence/native-clean-install.json"
                ).read_bytes(),
            }
            require(
                sha(files[name]) == package["wheel_sha256"]
                and sha(files["requirements.txt"]) == package["lock_sha256"]
                and sha(files["verifier-install-v1.json"]) == package["fixture_sha256"]
                and b"mailto:abdel@lucidcomputing.ai" in files["SECURITY.md"],
                "distribution or security contact differs",
            )
            inventory = package["installed_dependencies"]
            require(
                isinstance(inventory, list)
                and inventory
                and all(
                    item["name"]
                    and item["version"]
                    and (
                        item["license_expression"]
                        or item["license_classifiers"]
                        or item["license_files_sha256"]
                    )
                    for item in inventory
                ),
                "dependency license inventory incomplete",
            )
            files["dependencies.json"] = encoded(
                {
                    "schema_version": 1,
                    "installation_platform": package["install_platform"],
                    "packages": inventory,
                    "wheel_members": inspected["files"],
                }
            )
            source = {
                "schema_version": 1,
                "source_revision": revision,
                "source_url": "https://github.com/Lucid-Computing/akashi/tree/"
                + revision,
                "wheel_sha256": package["wheel_sha256"],
                "locked_requirements_sha256": package["lock_sha256"],
                **conclusions,
            }
            files["provenance.json"] = encoded(source)
            require(check_source() == revision, "source changed during build")
            with tempfile.TemporaryDirectory(dir=output) as scratch:
                archive = Path(scratch) / "candidate.zip"
                checksum = write_archive(archive, files)
                os.replace(archive, target)
            report.update(
                status="passed",
                source_revision=revision,
                candidate_sha256=checksum,
                evidence_manifest_sha256=trusted,
            )
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            IndexError,
            StopIteration,
            OverflowError,
            OSError,
            ImportError,
            RuntimeError,
            subprocess.SubprocessError,
            zipfile.BadZipFile,
        ) as exc:
            target.unlink(missing_ok=True)
            report.update(failed_stage=stage, error=type(exc).__name__)
        _write(path, report)
        return bool(report["status"] == "passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence", type=Path, default=os.environ.get("AKASHI_RELEASE_EVIDENCE")
    )
    parser.add_argument(
        "--manifest-sha256", default=os.environ.get("AKASHI_RELEASE_MANIFEST_SHA256")
    )
    parser.add_argument("--output", type=Path, default=ROOT / "build/release")
    args = parser.parse_args()
    passed = qualify(args.evidence, args.manifest_sha256, args.output)
    print(
        f"Release candidate {'passed' if passed else 'incomplete'}. See {args.output / 'status.json'}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
