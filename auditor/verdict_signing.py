"""Canonical signed public verdicts for RFC-0007."""

import re
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_DOMAIN = b"vig/verdict/1"
_REASONS = {
    "CONFORMS": {"exact_match"},
    "DEVIATES": {"first_divergence"},
    "INCOMPLETE": {"completion_rule"},
    "EXCUSED_RANGE": {"padding_range"},
    "UNAVAILABLE": {
        "selection_gap",
        "missing_handoff",
        "escrow_expired",
        "invalid_sample",
        "invalid_material",
        "prover_unavailable",
        "proof_rejected",
        "deadline_missed",
        "verifier_unavailable",
        "verifier_disagreement",
        "statement_mismatch",
    },
}
_FIELDS = {
    "version",
    "challenge_id",
    "transcript_commitment",
    "outcome",
    "reason",
    "verified_at",
    "auditor_key_id",
}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")


def _checked(value: object, *, signed: bool) -> dict[str, Any]:
    try:
        if not isinstance(value, dict):
            raise TypeError("Expected verdict object")
        outcome = value["outcome"]
        fields = _FIELDS | ({"signature"} if signed else set())
        if outcome in ("CONFORMS", "DEVIATES"):
            fields |= {"proof_sha256", "statement_sha256"}
        if (
            value.keys() != fields
            or value["version"] != "vig-verdict/1"
            or value["reason"] not in _REASONS[outcome]
            or str(uuid.UUID(value["challenge_id"])) != value["challenge_id"]
            or not _STAMP.fullmatch(value["verified_at"])
            or not isinstance(value["auditor_key_id"], str)
            or not value["auditor_key_id"]
            or any(
                not _DIGEST.fullmatch(value[k])
                for k in fields
                & {"transcript_commitment", "proof_sha256", "statement_sha256"}
            )
            or signed
            and not re.fullmatch(r"[0-9a-f]{128}", value["signature"])
        ):
            raise ValueError("Invalid public verdict")
        datetime.strptime(value["verified_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
    except (AttributeError, ValueError, TypeError, KeyError):
        raise ValueError("Invalid public verdict") from None
    return dict(value)


def public_verdict(value: object) -> dict[str, object]:
    """Reject unknown fields before emitting signed metadata."""
    return _checked(value, signed=True)


def sign_verdict(value: dict[str, object], key: Ed25519PrivateKey) -> dict[str, object]:
    checked = _checked(value, signed=False)
    return {**checked, "signature": key.sign(_DOMAIN + rfc8785.dumps(checked)).hex()}


def verify_signed(
    value: object, lookup_key: Callable[[str, str], bytes]
) -> dict[str, object]:
    checked = _checked(value, signed=True)
    signature = bytes.fromhex(checked.pop("signature"))
    try:
        key = Ed25519PublicKey.from_public_bytes(
            lookup_key("auditor", checked["auditor_key_id"])
        )
        key.verify(signature, _DOMAIN + rfc8785.dumps(checked))
    except (KeyError, TypeError, ValueError, InvalidSignature):
        raise ValueError("Unauthenticated public verdict") from None
    return {**checked, "signature": signature.hex()}
