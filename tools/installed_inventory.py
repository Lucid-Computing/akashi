"""Report package identities and license evidence from the clean verifier environment."""

import hashlib
import json
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

import verifier.cli
import verifier.proof


def inventory() -> list[dict[str, Any]]:
    prefix = Path(sys.prefix).resolve()
    for module in (verifier.cli, verifier.proof):
        if module.__file__ is None or not Path(
            module.__file__
        ).resolve().is_relative_to(prefix):
            raise RuntimeError(
                "Verifier was imported from outside the clean environment"
            )
    items = []
    for package in metadata.distributions():
        info = package.metadata
        files = {
            str(entry): hashlib.sha256(Path(entry.locate()).read_bytes()).hexdigest()
            for entry in (package.files or ())
            if ".dist-info/licenses/" in str(entry)
        }
        items.append(
            {
                "name": info["Name"],
                "version": package.version,
                "license_expression": info.get("License-Expression"),
                "license_classifiers": [
                    v
                    for v in info.get_all("Classifier", [])
                    if v.startswith("License ::")
                ],
                "license_files_sha256": files,
            }
        )
    return sorted(items, key=lambda item: str(item["name"]).lower())


if __name__ == "__main__":
    print(json.dumps(inventory()))
