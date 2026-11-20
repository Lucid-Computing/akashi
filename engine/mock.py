"""Deterministic CPU adapter for the M1 toy model in specs/build-plan.md."""

from dataclasses import dataclass
from typing import Literal

from engine.adapter import EngineIntegrityError, EngineResult, EngineUnavailable

__all__ = ["EngineIntegrityError", "EngineResult", "EngineUnavailable", "MockEngine"]


@dataclass(frozen=True)
class MockEngine:
    outcome: Literal["success", "integrity_error", "unavailable"] = "success"

    def __post_init__(self) -> None:
        if self.outcome not in ("success", "integrity_error", "unavailable"):
            raise ValueError("unknown mock engine outcome")

    def generate(self, prompt: tuple[int, ...], max_tokens: int) -> EngineResult:
        if not isinstance(prompt, tuple) or not prompt:
            raise ValueError("expected a nonempty token tuple")
        if type(max_tokens) is not int or not 1 <= max_tokens <= min(
            256, 1024 - len(prompt)
        ):
            raise ValueError("budget exceeds the request cap or window")
        if any(type(token) is not int or not 0 <= token < 202048 for token in prompt):
            raise ValueError("invalid prompt token ID")
        if self.outcome == "integrity_error":
            raise EngineIntegrityError("mock integrity check failed")
        if self.outcome == "unavailable":
            raise EngineUnavailable("mock engine unavailable")
        # Accept rendered context IDs; only the toy model's 512 output IDs are generated.
        first = sum(prompt) + 1
        tokens = tuple((first + offset) % 512 for offset in range(max_tokens))
        return EngineResult(tokens=tokens, integrity_window_closed=True)
