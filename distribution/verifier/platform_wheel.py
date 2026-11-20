"""Tag the wheel for its bundled ELF verifier, including when built on macOS."""

from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class PlatformWheel(BuildHookInterface):  # type: ignore[type-arg]
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        build_data["tag"] = "py3-none-linux_x86_64"
        build_data["pure_python"] = False
