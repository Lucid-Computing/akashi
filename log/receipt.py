"""Canonical v1 receipt preimages, public projection and Ed25519 promises (RFC-0004)."""

import hashlib
import re
import struct
from collections.abc import Mapping, Sequence
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# docs/spec/03-data-model.md gives the order of these unframed 32-byte fields.
_DIGEST_FIELDS = (
    "log_id",
    "commitment_id",
    "render_profile",
    "params_digest",
    "transcript_commitment",
)
_PUBLIC_FIELDS = (
    *_DIGEST_FIELDS,
    "beacon_round",
    "served_at",
    "endpoint_id",
    "request_id",
    "log_key_id",
    "sampling_mode",
    "leaf_hash",
)
_RECEIPT_FIELDS = frozenset((*_PUBLIC_FIELDS, "salt", "promise_sig"))
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"
)
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")


def _octets(value: object, size: int, name: str) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) != 2 * size
        or not re.fullmatch(r"[0-9a-f]+", value)
    ):
        raise ValueError(f"{name} must be {size} lowercase hex-encoded bytes")
    return bytes.fromhex(value)


def _uint(value: object, bits: int, name: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{name} must be an unsigned {bits}-bit integer")
    return value


def _frame(data: bytes) -> bytes:
    return struct.pack("<I", _uint(len(data), 32, "frame length")) + data


def params_digest(max_tokens: int) -> str:
    budget = _uint(max_tokens, 32, "max_tokens")
    if budget == 0:
        raise ValueError("max_tokens must be positive")
    return hashlib.sha256(struct.pack("<I", budget)).hexdigest()


def _token_frame(tokens: Sequence[int], limit: int) -> bytes:
    if not isinstance(tokens, Sequence) or isinstance(
        tokens, (str, bytes, bytearray, memoryview)
    ):
        raise TypeError("token IDs must be a sequence of integers")
    if not 1 <= len(tokens) <= limit:
        raise ValueError(
            "empty token sequence or transcript exceeds its window or budget"
        )
    values = tuple(tokens)
    if (
        len(values) > limit
        or not values
        or any(type(token) is not int or not 0 <= token < 202048 for token in values)
    ):
        raise ValueError("empty token sequence or invalid token ID")  # F37
    return _frame(struct.pack(f"<{len(values)}I", *values))


def transcript_commitment(
    commitment_id: str,
    render_profile: str,
    max_tokens: int,
    salt: str,
    prompt: Sequence[int],
    reply: Sequence[int],
) -> str:
    """Bind both token vectors with independent byte-length frames and the holder's salt."""
    params = bytes.fromhex(params_digest(max_tokens))
    return hashlib.sha256(
        b"vig/transcript/1"
        + _octets(commitment_id, 32, "commitment_id")
        + _octets(render_profile, 32, "render_profile")
        + params
        + _octets(salt, 32, "salt")
        + _token_frame(prompt, 1024 - max_tokens)  # parameters.md fixes the window
        + _token_frame(reply, max_tokens)
    ).hexdigest()


def _text(fields: Mapping[str, object], name: str) -> str:
    value = fields.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty string")
    return value


def leaf_hash(fields: Mapping[str, object]) -> str:
    """Hash the binding fields of an unsigned append, holder receipt or public log leaf."""
    if not isinstance(fields, Mapping):
        raise TypeError("leaf fields must be an object")
    fixed = b"".join(_octets(fields.get(name), 32, name) for name in _DIGEST_FIELDS)
    beacon_round = _uint(fields.get("beacon_round"), 64, "beacon_round")
    served_at = _text(fields, "served_at")
    if not _TIMESTAMP.fullmatch(served_at):
        raise ValueError("served_at must be a UTC timestamp with millisecond precision")
    try:
        datetime.strptime(served_at, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        raise ValueError("invalid served_at timestamp") from None
    endpoint = _text(fields, "endpoint_id")
    request_id = _text(fields, "request_id")
    if not _UUID.fullmatch(request_id):
        raise ValueError("request_id must be a canonical lowercase UUID")
    key_id = _text(fields, "log_key_id")
    mode = _text(fields, "sampling_mode")
    if mode not in ("live", "soak"):
        raise ValueError("unknown sampling_mode")
    try:
        framed = b"".join(
            _frame(value.encode("utf-8"))
            for value in (served_at, endpoint, request_id, key_id, mode)
        )
    except UnicodeEncodeError:
        raise ValueError("invalid UTF-8 in leaf metadata") from None
    return hashlib.sha256(
        b"vig/leaf/1" + fixed + struct.pack(">Q", beacon_round) + framed
    ).hexdigest()


def promise_preimage(log_id: str, leaf_hash: str) -> bytes:
    """Legacy PromiseReceipt signature domain from specs/receipt-log.md."""
    return (
        b"PromiseReceipt"
        + _octets(log_id, 32, "log_id")
        + _octets(leaf_hash, 32, "leaf_hash")
    )


def _checked_receipt(receipt: Mapping[str, object]) -> tuple[dict[str, object], bytes]:
    if not isinstance(receipt, Mapping):
        raise TypeError("receipt must be an object")
    fields = dict(receipt)
    if fields.keys() != _RECEIPT_FIELDS:
        raise ValueError("invalid receipt fields")
    _octets(fields["salt"], 32, "salt")
    if fields["leaf_hash"] != leaf_hash(fields):
        raise ValueError("leaf hash mismatch")
    signature = _octets(fields["promise_sig"], 64, "promise_sig")
    return fields, signature


def verify_promise(
    receipt: Mapping[str, object], *, log_id: str, log_key_id: str, public_key: bytes
) -> None:
    """Verify the bound delivery metadata against the caller's trusted log identity and key."""
    fields, signature = _checked_receipt(receipt)
    if log_id != fields["log_id"] or log_key_id != fields["log_key_id"]:
        raise ValueError("untrusted log identity or key ID")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("invalid Ed25519 public key")
    message = promise_preimage(log_id, _text(fields, "leaf_hash"))
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        raise ValueError("invalid promise signature") from None


def public_leaf(receipt: Mapping[str, object], leaf_index: int) -> dict[str, object]:
    """Project a receipt to its public fields after checking its schema and metadata hash."""
    fields, _ = _checked_receipt(receipt)
    return {
        **{name: fields[name] for name in _PUBLIC_FIELDS},
        "leaf_index": _uint(leaf_index, 64, "leaf_index"),
    }
