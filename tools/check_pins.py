"""Require exact versions for declared runtime dependencies, including extras."""

import argparse
import sys
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def check_group(group: str, entries: object) -> None:
    if not isinstance(entries, list):
        raise TypeError(f"{group} must be an array")
    for index, entry in enumerate(entries):
        if not isinstance(entry, str):
            raise TypeError(f"{group}[{index}] must be a requirement string")
        try:
            requirement = Requirement(entry)
        except InvalidRequirement:
            raise ValueError(
                f"{group}[{index}] contains an invalid requirement"
            ) from None
        pins = list(requirement.specifier)
        if len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
            raise ValueError(
                f"{group}[{index}] must pin {requirement.name} to one exact version"
            )


def check_pins(path: Path) -> None:
    with path.open("rb") as stream:
        project = tomllib.load(stream).get("project")
    if not isinstance(project, dict):
        raise TypeError("missing [project] table")
    if {"dependencies", "optional-dependencies"}.intersection(
        project.get("dynamic", [])
    ):
        raise ValueError("runtime dependencies must be declared statically")
    check_group("project.dependencies", project.get("dependencies", []))
    extras = project.get("optional-dependencies", {})
    if not isinstance(extras, dict):
        raise TypeError("project.optional-dependencies must be a table")
    for name, entries in extras.items():
        check_group(f"project.optional-dependencies.{name}", entries)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=Path("pyproject.toml"))
    args = parser.parse_args()
    try:
        check_pins(args.path)
    except (TypeError, ValueError, OSError) as error:
        parser.exit(1, f"{args.path}: {error}\n")
