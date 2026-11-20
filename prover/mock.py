"""CPU fixture adapter for the M1 proof worker boundary (RFC-0006)."""

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Literal, Protocol, TypeVar

Evidence_co = TypeVar("Evidence_co", covariant=True)


class Prover(Protocol[Evidence_co]):
    def prove(self, statement: bytes) -> Evidence_co:
        """Process one holder's serialized statement."""
        ...


class ProofRejected(RuntimeError):
    """The proof tool rejected the job."""


class ProofTimeout(TimeoutError):
    """The job missed its proof deadline."""


@dataclass(frozen=True)
class MockEvidence:
    statement_sha256: str = field(repr=False)
    kind: Literal["mock"] = field(default="mock", init=False)


# F7–F8: the verifier gets T little-endian u32 IDs followed by r and e, without the spool nonce.
_WINDOW = 1024
_STATEMENT = struct.Struct(f"<{_WINDOW + 2}I")


@dataclass(frozen=True)
class MockProver:
    outcome: Literal["success", "rejection", "timeout"] = "success"

    def __post_init__(self) -> None:
        if self.outcome not in ("success", "rejection", "timeout"):
            raise ValueError("unknown mock prover outcome")

    def prove(self, statement: bytes) -> MockEvidence:
        if not isinstance(statement, bytes) or len(statement) != _STATEMENT.size:
            raise ValueError("expected a nonce-free whole-reply statement")
        words = _STATEMENT.unpack(statement)
        start, end = words[-2:]
        if not 0 <= start < end < _WINDOW:
            raise ValueError("invalid whole-reply range")
        if any(token >= 202048 for token in words[: end + 1]) or any(
            words[end + 1 : -2]
        ):
            raise ValueError("invalid token ID or padding")
        if self.outcome == "rejection":
            raise ProofRejected("mock proof tool rejected the job")
        if self.outcome == "timeout":
            raise ProofTimeout("mock proof deadline elapsed")
        return MockEvidence(hashlib.sha256(statement).hexdigest())
