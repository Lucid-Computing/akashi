"""RFC-0010 sealed pickup. Receipt verification follows decryption at the holder."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import TypeAlias, cast

import rfc8785
from nacl import bindings
from nacl.exceptions import CryptoError

VERSION = "akashi-pickup/1"
_UINT32_MAX = (1 << 32) - 1
_VOCABULARY_SIZE = 202_048  # F37, specs/parameters.md
_JSON: TypeAlias = str | bool | int | float | None | list["_JSON"] | dict[str, "_JSON"]


class PickupError(ValueError):
    """Invalid pickup material, invalid wire encoding or failed authentication."""


def _octets(value: object, size: int | None = None) -> bytes:
    if not isinstance(value, str) or (size is not None and len(value) != 2 * size):
        raise PickupError("Invalid pickup octets")
    try:
        data = bytes.fromhex(value)
    except ValueError:
        raise PickupError("Invalid pickup octets") from None
    if data.hex() != value:
        raise PickupError("Invalid pickup octets")
    return data


def parse_holder_secret(user: object) -> bytes | None:
    """Extract an explicit v1 opt-in from an otherwise ordinary optional user field."""
    if user is None:
        return None
    if not isinstance(user, str):
        raise PickupError("Invalid user field")
    if not user.startswith("akashi-pickup/"):
        return None
    prefix = VERSION + ":"
    if not user.startswith(prefix):
        raise PickupError("Invalid pickup user field")
    return _octets(user[len(prefix) :], 32)


def _canonical(value: object) -> bytes:
    try:
        # The encoder validates the entire JSON value, including UTF-8 and numbers.
        return rfc8785.dumps(cast("_JSON", value))
    except (ValueError, RecursionError):
        raise PickupError("Invalid canonical pickup JSON") from None


def _frame(value: bytes) -> bytes:
    if len(value) > _UINT32_MAX:
        raise PickupError("Pickup input exceeds the frame length")
    return len(value).to_bytes(4, "little") + value


def _material(
    original_chat: object, budget: int, reply_text: str, holder_secret: bytes
) -> tuple[bytes, bytes]:
    if not isinstance(holder_secret, bytes) or len(holder_secret) != 32:
        raise PickupError("Invalid holder secret")
    if type(budget) is not int or not 1 <= budget <= _UINT32_MAX:
        raise PickupError("Invalid pickup budget")
    if not isinstance(original_chat, list) or not all(
        isinstance(m, dict) for m in original_chat
    ):
        raise PickupError("Invalid original chat")
    if not isinstance(reply_text, str):
        raise PickupError("Invalid reply text")
    try:
        reply = reply_text.encode("utf-8")
    except UnicodeEncodeError:
        raise PickupError("Invalid reply text") from None
    k = hashlib.sha256(
        b"akashi/pickup/v1"
        + holder_secret
        + _frame(_canonical(original_chat))
        + budget.to_bytes(4, "little")
        + _frame(reply)
    ).digest()
    return k, hashlib.sha256(b"id" + k).digest()


def lookup_id(
    original_chat: object, budget: int, reply_text: str, holder_secret: bytes
) -> str:
    """Compute the lowercase hex lookup digest using the holder's original inputs."""
    _, digest = _material(original_chat, budget, reply_text, holder_secret)
    return digest.hex()


def _key(k: bytes) -> bytes:
    # RFC 5869 extract with absent salt, followed by one 32-byte expand block.
    prk = hmac.digest(bytes(32), k, "sha256")
    return hmac.digest(prk, b"enc\x01", "sha256")


def _verification(value: object, digest: bytes) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("version") != "akashi/1":
        raise PickupError("Invalid verification object")
    if not isinstance(value.get("receipt"), dict):
        raise PickupError("Invalid verification receipt")
    for field in ("prompt_token_ids", "reply_token_ids"):
        ids = value.get(field)
        if (
            not isinstance(ids, list)
            or not ids
            or not all(type(i) is int and 0 <= i < _VOCABULARY_SIZE for i in ids)
        ):
            raise PickupError("Invalid verification token IDs")
    if "pickup_id" in value and _octets(value["pickup_id"], 32) != digest:
        raise PickupError("Invalid verification pickup ID")
    return value


def seal(
    verification: object,
    original_chat: object,
    budget: int,
    reply_text: str,
    holder_secret: bytes,
) -> tuple[str, dict[str, str]]:
    """Seal the canonical Verification object with a new nonce on every call."""
    k, digest = _material(original_chat, budget, reply_text, holder_secret)
    plaintext = _canonical(_verification(verification, digest))
    nonce = secrets.token_bytes(bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, VERSION.encode("utf-8") + digest, nonce, _key(k)
    )
    return digest.hex(), {
        "version": VERSION,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }


def _json_integer(text: str) -> int | float:
    # JCS can emit integral IEEE-754 doubles as integer literals beyond the safe
    # integer range. Parse these as doubles to round-trip the canonical bytes.
    number = int(text)
    return number if abs(number) <= (1 << 53) - 1 else float(text)


def envelope_parts(envelope: object) -> tuple[bytes, bytes]:
    """Decode the public framing without possessing any holder secrets."""
    if not isinstance(envelope, dict) or envelope.get("version") != VERSION:
        raise PickupError("Invalid pickup envelope")
    nonce = _octets(
        envelope.get("nonce"), bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    )
    ciphertext = _octets(envelope.get("ciphertext"))
    if len(ciphertext) < bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES:
        raise PickupError("Invalid pickup ciphertext")
    return nonce, ciphertext


def open(
    envelope: object,
    holder_secret: bytes,
    original_chat: object,
    budget: int,
    reply_text: str,
) -> dict[str, object]:
    """Authenticate and decode a pickup before independent receipt verification."""
    nonce, ciphertext = envelope_parts(envelope)
    k, digest = _material(original_chat, budget, reply_text, holder_secret)
    try:
        plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, VERSION.encode("utf-8") + digest, nonce, _key(k)
        )
    except CryptoError:
        raise PickupError("Pickup authentication failed") from None
    try:
        value = json.loads(plaintext.decode("utf-8"), parse_int=_json_integer)
    except (ValueError, RecursionError):
        raise PickupError("Invalid pickup plaintext") from None
    if _canonical(value) != plaintext:
        raise PickupError("Invalid canonical pickup plaintext")
    return _verification(value, digest)
