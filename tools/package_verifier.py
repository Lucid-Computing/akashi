"""Build the public Linux verifier wheel and exercise an isolated installation."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement

from tools.check_pins import check_pins
from tools.gate_m1 import ROOT, _write
from verifier.proof import _PUBLIC

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

PROJECT = ROOT / "distribution/verifier"
FIXTURE = ROOT / "tests/fixtures/verifier-install-v1.json"
NATIVE_HASH = "7f9efc1e86a848a3715c6cc870e465ac2a1c5e8fd1eac09e4809023de7604394"
MANIFEST_HASH = "bac8d289baba16119ba8cf4a82ae1d0a46d47c78b0fff128dc138b35e1dd7643"


def require(ok: object, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_wheel(path: Path) -> dict[str, Any]:
    with (PROJECT / "pyproject.toml").open("rb") as stream:
        conf = tomllib.load(stream)
    declared = conf["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        info = next(
            name.removesuffix("/WHEEL")
            for name in names
            if name.endswith(".dist-info/WHEEL")
        )
        expected = {
            f"{info}/{entry}"
            for entry in ("WHEEL", "METADATA", "RECORD", "entry_points.txt")
        }
        for notice in conf["project"]["license-files"]:
            require(
                Path(notice).parent == Path("licenses") and "*" not in notice,
                "Notice must be explicitly named",
            )
            source = PROJECT / notice
            dest = f"{info}/licenses/licenses/{source.name}"
            require(
                source.is_file()
                and not source.is_symlink()
                and wheel.read(dest) == source.read_bytes(),
                "Missing notice",
            )
            expected.add(dest)
        for source_name, dest in declared.items():
            source = (PROJECT / source_name).resolve(strict=True)
            if source_name.startswith("native/"):
                approved = {
                    *_PUBLIC,
                    "cp_verify",
                    "manifest.json",
                    "config/layout.txt",
                    "config/policy.txt",
                }
                require(
                    source_name.removeprefix("native/") in approved
                    and dest == "verifier/" + source_name,
                    "Unexpected native payload",
                )
            else:
                require(
                    source_name == "../../" + dest
                    and len(Path(dest).parts) == 2
                    and Path(dest).parts[0]
                    in {"auditor", "gateway", "log", "prover", "tools", "verifier"}
                    and (dest.endswith(".py") or dest == "verifier/py.typed"),
                    "Only verifier source modules may accompany the measured native files",
                )
            require(
                source.is_relative_to(ROOT)
                and source.is_file()
                and wheel.read(dest) == source.read_bytes(),
                "Wheel differs from reviewed source",
            )
            expected.add(dest)
        require(
            len(names) == len(expected) and set(names) == expected,
            "Unexpected wheel member",
        )
        metadata = BytesParser().parsebytes(wheel.read(f"{info}/METADATA"))
        require(
            metadata["Name"] == "akashi-verify"
            and metadata["Version"] == conf["project"]["version"],
            "Wheel identity mismatch",
        )
        requirements = {Requirement(s) for s in metadata.get_all("Requires-Dist", [])}
        require(
            requirements == {Requirement(s) for s in conf["project"]["dependencies"]},
            "Wheel dependencies changed",
        )
        tag = BytesParser().parsebytes(wheel.read(f"{info}/WHEEL"))
        require(
            tag.get_all("Tag") == ["py3-none-linux_x86_64"]
            and tag["Root-Is-Purelib"] == "false",
            "Wrong wheel architecture",
        )
        records = list(
            csv.reader(io.StringIO(wheel.read(f"{info}/RECORD").decode("utf8")))
        )
        require(
            len(records) == len(expected) and {r[0] for r in records} == expected,
            "Incomplete wheel RECORD",
        )
        for member, encoded, size in records:
            if member == f"{info}/RECORD":
                require((encoded, size) == ("", ""), "Invalid wheel RECORD self-entry")
                continue
            data = wheel.read(member)
            wanted = (
                base64.urlsafe_b64encode(hashlib.sha256(data).digest())
                .decode()
                .rstrip("=")
            )
            require(
                encoded == "sha256=" + wanted and size == str(len(data)),
                "Invalid wheel member digest",
            )
        native = wheel.read("verifier/native/cp_verify")
        require(
            native[:6] == b"\x7fELF\x02\x01"
            and native[18:20] == b"\x3e\x00"
            and wheel.getinfo("verifier/native/cp_verify").external_attr >> 16
            & stat.S_IXUSR,
            "Expected executable x86-64 ELF",
        )
        raw = wheel.read("verifier/native/manifest.json")
        require(sha(raw) == MANIFEST_HASH, "Unrecognized measured F4 manifest")
        public = {**_PUBLIC, **json.loads(raw)["sha256"]}
        require(
            public["cp_verify"] == NATIVE_HASH
            and all(
                sha(wheel.read("verifier/native/" + n)) == h for n, h in public.items()
            ),
            "Unrecognized public asset",
        )
    return {
        "files": sorted(names),
        "native_inputs_sha256": public,
        "wheel_sha256": sha(path.read_bytes()),
    }


def clean_install(uv: str, wheel: Path, lock: Path, folder: Path) -> dict[str, Any]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH"}
        and not k.startswith("AKASHI_")
    }
    env["PYTHONNOUSERSITE"] = "1"
    venv = folder / "install"
    python = venv / "bin/python"

    def run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args, env=env, cwd=folder, text=True, check=check, capture_output=True
        )

    run([uv, "venv", "--no-project", "--python", sys.executable, str(venv)])
    run(
        [
            uv,
            "pip",
            "install",
            "--python",
            str(python),
            "--require-hashes",
            "--only-binary",
            ":all:",
            "-r",
            str(lock),
        ]
    )
    run([uv, "pip", "check", "--python", str(python)])
    native_host = (platform.system(), platform.machine()) == ("Linux", "x86_64")
    # Cross-install the Linux wheel solely to check the portable receipt path on macOS.
    override = [] if native_host else ["--python-platform", "x86_64-unknown-linux-gnu"]
    run(
        [
            uv,
            "pip",
            "install",
            "--python",
            str(python),
            "--no-deps",
            *override,
            str(wheel),
        ]
    )
    if native_host:
        run([uv, "pip", "check", "--python", str(python)])
    cli = str(venv / "bin/akashi")
    run([cli, "verify", "--help"])
    fixture = json.loads(FIXTURE.read_bytes())
    for key in ("bundle", "descriptor", "checkpoint"):
        (folder / (key + ".json")).write_text(json.dumps(fixture[key]))
    args = [
        cli,
        "verify",
        "bundle.json",
        "--descriptor",
        "descriptor.json",
        "--checkpoint",
        "checkpoint.json",
        "--observed-at",
        fixture["observed_at"],
        "--receipt-only",
    ]
    result = run(args, check=False)
    require(
        result.returncode == 30
        and json.loads(result.stdout)["outcome"] == "RECEIPT_VERIFIED",
        "Installed verifier failed signed receipt",
    )
    bundle = fixture["bundle"]
    bundle["verification"]["receipt"]["promise_sig"] = "00" * 64
    (folder / "bundle.json").write_text(json.dumps(bundle))
    result = run(args, check=False)
    require(result.returncode == 10, "Invalid signed receipt accepted")
    inspector = folder / "installed_inventory.py"
    shutil.copyfile(ROOT / "tools/installed_inventory.py", inspector)
    inventory = run([str(python), "-I", str(inspector)])
    return {
        "installed_dependencies": json.loads(inventory.stdout),
        "receipt_exit": 30,
        "altered_receipt_exit": 10,
        "install_platform": platform.system() + "-" + platform.machine(),
        "native_wheel_host": native_host,
    }


def build() -> None:
    output = ROOT / "build/package"
    output.mkdir(parents=True, exist_ok=True)
    report_path = ROOT / "build/gates/package.json"
    report: dict[str, Any] = {
        "schema_version": 1,
        "gate": "package",
        "status": "incomplete",
    }
    _write(report_path, report)
    uv = shutil.which("uv")
    if not uv:
        raise RuntimeError("Missing pinned uv")
    check_pins(PROJECT / "pyproject.toml")
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        subprocess.run(
            [
                uv,
                "build",
                "--wheel",
                "--no-build-isolation",
                "--python",
                sys.executable,
                "--out-dir",
                str(stage),
                str(PROJECT),
            ],
            cwd=ROOT,
            check=True,
        )
        (wheel,) = stage.glob("*.whl")
        checked = inspect_wheel(wheel)
        with tempfile.TemporaryDirectory(dir=stage) as negative:
            extra = Path(negative) / wheel.name
            shutil.copyfile(wheel, extra)
            with zipfile.ZipFile(extra, "a") as archive:
                archive.writestr("unexpected-install-fixture.txt", "synthetic control")
            try:
                inspect_wheel(extra)
            except ValueError:
                pass
            else:
                raise ValueError("Inventory accepted an unlisted member")
        lock = stage / "requirements.txt"
        subprocess.run(
            [
                uv,
                "export",
                "--locked",
                "--no-dev",
                "--prune",
                "pynacl",
                "--prune",
                "rfc8785",
                "--no-emit-project",
                "--no-header",
                "--output-file",
                str(lock),
            ],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        install = clean_install(uv, wheel, lock, stage)
        shutil.copyfile(wheel, output / wheel.name)
        shutil.copyfile(lock, output / lock.name)
        shutil.copyfile(FIXTURE, output / FIXTURE.name)
        report.update(
            status="passed",
            source_revision=subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            wheel=wheel.name,
            fixture_sha256=sha(FIXTURE.read_bytes()),
            lock_sha256=sha(lock.read_bytes()),
            **checked,
            **install,
        )
        _write(report_path, report)
        print(
            "Installed wheel accepted the signed fixture and rejected the changed signature."
        )


if __name__ == "__main__":
    build()
