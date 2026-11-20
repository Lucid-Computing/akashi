"""Assign and authenticate drand quicknet rounds for RFC-0005 sampling."""

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from py_ecc.bls.g2_primitives import subgroup_check
from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.bls.point_compression import decompress_G1, decompress_G2
from py_ecc.bls.typing import G1Compressed, G2Compressed
from py_ecc.optimized_bls12_381.optimized_curve import G2, is_inf
from py_ecc.optimized_bls12_381.optimized_pairing import pairing

# The quicknet /info document referenced by F36 (specs/facts-register.md).
_CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
_GROUP_HASH = "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e"
_PUBLIC_KEY = (
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c"
    "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5"
    "ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
)
_GENESIS_UNIX = 1692803367
_GENESIS = datetime.fromtimestamp(_GENESIS_UNIX, tz=timezone.utc)
_PERIOD = timedelta(seconds=3)
# drand/crypto/schemes.go, NewPedersenBLSUnchainedG1.
_DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"


def _elapsed(at: datetime) -> timedelta:
    if not isinstance(at, datetime) or at.utcoffset() is None:
        raise ValueError("a timezone-aware timestamp is required")
    return at - _GENESIS


def round_for(
    served_at: datetime,
    *,
    mmd: timedelta = timedelta(seconds=10),
    margin: timedelta = timedelta(seconds=3),
) -> int:
    """First round strictly after the configured merge delay and beacon margin."""
    if mmd < timedelta(0) or margin < timedelta(0):
        raise ValueError("merge delay and margin must be nonnegative")
    elapsed = _elapsed(served_at) + mmd + margin
    return max(1, elapsed // _PERIOD + 2)


def _round_number(value: object) -> int:
    if type(value) is not int or not 0 < value < 1 << 64:
        raise ValueError("round must be a positive uint64")
    return value


def round_is_open(assigned_round: int, at: datetime) -> bool:
    """At terminal release an already-open assigned round excludes the delivery."""
    return _round_number(assigned_round) <= _elapsed(at) // _PERIOD + 1


@lru_cache(maxsize=1)
def _verify_signature(number: int, signature: bytes) -> None:
    # Reuse the last authenticated round when sampling multiple receipts from the same round.
    key = decompress_G2(
        G2Compressed((int(_PUBLIC_KEY[:96], 16), int(_PUBLIC_KEY[96:], 16)))
    )
    sig = decompress_G1(G1Compressed(int.from_bytes(signature, "big")))
    if is_inf(sig) or not subgroup_check(sig) or is_inf(key) or not subgroup_check(key):
        raise ValueError("invalid quicknet group element")
    message = hashlib.sha256(number.to_bytes(8, "big")).digest()
    # py_ecc 8 requires a hash constructor but annotates it as a hash instance.
    point = hash_to_G1(message, _DST, hashlib.sha256)  # type: ignore[arg-type]
    if pairing(key, point) != pairing(G2, sig):
        raise ValueError("invalid quicknet round signature")


def verify_round(
    assigned_round: int, chain_info: Mapping[str, object], beacon: Mapping[str, object]
) -> bytes:
    """Verify quicknet /info and /public/{round}, returning the signed round's raw signature."""
    number = _round_number(assigned_round)
    metadata = chain_info.get("metadata")
    if (
        chain_info.get("hash") != _CHAIN_HASH
        or chain_info.get("public_key") != _PUBLIC_KEY
        or chain_info.get("groupHash") != _GROUP_HASH
        or chain_info.get("schemeID") != "bls-unchained-g1-rfc9380"
        or type(chain_info.get("period")) is not int
        or chain_info["period"] != 3
        or type(chain_info.get("genesis_time")) is not int
        or chain_info["genesis_time"] != _GENESIS_UNIX
        or not isinstance(metadata, Mapping)
        or metadata.get("beaconID") != "quicknet"
    ):
        raise ValueError("chain info differs from pinned quicknet parameters")
    if _round_number(beacon.get("round")) != number:
        raise ValueError("beacon response round does not match assigned round")
    encoded = beacon.get("signature")
    if not isinstance(encoded, str) or not re.fullmatch(r"[0-9a-f]{96}", encoded):
        raise ValueError("expected a canonical 48-byte signature")
    signature = bytes.fromhex(encoded)
    if (
        "randomness" in beacon
        and beacon["randomness"] != hashlib.sha256(signature).hexdigest()
    ):
        raise ValueError("beacon randomness does not match its signature")
    _verify_signature(number, signature)
    return signature


def select_round(
    transcript_commitment: bytes,
    assigned_round: int,
    chain_info: Mapping[str, object],
    beacon: Mapping[str, object],
) -> dict[int, bool]:
    """Compute all configured divisors over the same authenticated selection word."""
    if not isinstance(transcript_commitment, bytes) or len(transcript_commitment) != 32:
        raise ValueError("transcript commitment must be 32 bytes")
    signature = verify_round(assigned_round, chain_info, beacon)
    digest = hashlib.sha256(
        transcript_commitment + assigned_round.to_bytes(8, "big") + signature
    ).digest()
    word = int.from_bytes(digest[:4], "big")
    return {divisor: word % divisor == 0 for divisor in (1, 20, 1000)}
