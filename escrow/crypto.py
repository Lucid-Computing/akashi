"""Private RFC-0005 storage envelopes and recipient-only selected transfers."""

import hashlib
import hmac
import secrets

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.secret import Aead

_RECORD_DATA = b"vig/escrow/1/data\x00"
_RECORD_KEY = b"vig/escrow/1/key\x00"
_TRANSFER_DATA = b"vig/escrow/1/transfer-data\x00"
_TRANSFER_KEY = b"vig/escrow/1/transfer-key\x00"


class EscrowCryptoError(ValueError):
    """Bounded local error safe to report without revealing the private input."""


def _context(metadata: bytes) -> bytes:
    if not isinstance(metadata, bytes) or not metadata:
        raise EscrowCryptoError("invalid escrow metadata")
    return hashlib.sha256(metadata).digest()


def seal_record(
    wrapping_key: bytes, metadata: bytes, plaintext: bytes
) -> tuple[bytes, bytes]:
    """Encrypt a record with a fresh key. Return ciphertext and its wrapped key slot."""
    context = _context(metadata)
    data_key = secrets.token_bytes(Aead.KEY_SIZE)
    try:
        ciphertext = Aead(data_key).encrypt(plaintext, _RECORD_DATA + context)
        key_slot = Aead(wrapping_key).encrypt(data_key, _RECORD_KEY + context)
    except (CryptoError, TypeError, ValueError):
        raise EscrowCryptoError("escrow encryption failed") from None
    return bytes(ciphertext), bytes(key_slot)


def open_record(
    wrapping_key: bytes, metadata: bytes, ciphertext: bytes, key_slot: bytes
) -> bytes:
    """Authenticate the key slot and payload against the same storage binding."""
    context = _context(metadata)
    try:
        data_key = Aead(wrapping_key).decrypt(key_slot, _RECORD_KEY + context)
        return Aead(data_key).decrypt(ciphertext, _RECORD_DATA + context)
    except (CryptoError, TypeError, ValueError):
        raise EscrowCryptoError("escrow authentication failed") from None


def transfer_record(
    wrapping_key: bytes,
    auditor_public_key: bytes,
    metadata: bytes,
    ciphertext: bytes,
    key_slot: bytes,
) -> tuple[bytes, bytes]:
    """Re-encrypt selected material for the pinned auditor's X25519 key."""
    plaintext = open_record(wrapping_key, metadata, ciphertext, key_slot)
    context = _context(metadata)
    transfer_key = secrets.token_bytes(Aead.KEY_SIZE)
    try:
        ciphertext = bytes(
            Aead(transfer_key).encrypt(plaintext, _TRANSFER_DATA + context)
        )
        recipient = SealedBox(PublicKey(auditor_public_key))
        key_slot = recipient.encrypt(_TRANSFER_KEY + context + transfer_key)
    except (CryptoError, TypeError, ValueError):
        raise EscrowCryptoError("escrow transfer encryption failed") from None
    return ciphertext, key_slot


def open_transfer(
    auditor_private_key: bytes, metadata: bytes, ciphertext: bytes, key_slot: bytes
) -> bytes:
    """Open an item from the authenticated outbox using the auditor's private key."""
    context = _context(metadata)
    try:
        unwrapped = SealedBox(PrivateKey(auditor_private_key)).decrypt(key_slot)
        binding, transfer_key = unwrapped[: -Aead.KEY_SIZE], unwrapped[-Aead.KEY_SIZE :]
        if not hmac.compare_digest(binding, _TRANSFER_KEY + context):
            raise EscrowCryptoError("escrow transfer authentication failed")
        return Aead(transfer_key).decrypt(ciphertext, _TRANSFER_DATA + context)
    except (CryptoError, TypeError, ValueError):
        raise EscrowCryptoError("escrow transfer authentication failed") from None
