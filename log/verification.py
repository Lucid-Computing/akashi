"""Verify anchored signed heads and RFC 6962 proofs without access to the log store."""

import hashlib
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from log.merkle import _parent, _split

_EMPTY = hashlib.sha256(b"").digest()
_HEX = re.compile(r"[0-9a-f]+")
_UTC_MS = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"
)
_HEAD_FIELDS = (
    "version",
    "log_id",
    "log_key_id",
    "tree_size",
    "timestamp",
    "root_hash",
    "signature",
)


def _bytes(value: object, length: int = 32) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) != 2 * length
        or not _HEX.fullmatch(value)
    ):
        raise ValueError("Invalid log evidence octets")
    return bytes.fromhex(value)


def _size(value: object) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError("Invalid unsigned tree size or index")
    return value


def verify_head(
    head: Mapping[str, object], *, log_id: str, lookup_key: Callable[[str, str], bytes]
) -> dict[str, object]:
    """Authenticate a head under a caller-pinned log and its role-scoped key history."""
    if not isinstance(head, Mapping):
        raise TypeError("Expected a signed tree head")
    fields = {name: head.get(name) for name in _HEAD_FIELDS}
    identity = _bytes(log_id)
    key_id = fields["log_key_id"]
    if (
        fields["version"] != "akashi-log/1"
        or fields["log_id"] != log_id
        or not isinstance(key_id, str)
        or not key_id
    ):
        raise ValueError("Untrusted log identity, version or key ID")
    size = _size(fields["tree_size"])
    root = _bytes(fields["root_hash"])
    signature = _bytes(fields["signature"], 64)
    timestamp = fields["timestamp"]
    if not isinstance(timestamp, str) or not _UTC_MS.fullmatch(timestamp):
        raise ValueError("Invalid signed head timestamp")
    try:
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        raise ValueError("Invalid signed head timestamp") from None
    try:
        key = lookup_key("log", key_id)
    except (KeyError, ValueError):
        raise ValueError("Unknown log signing key") from None
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Invalid trusted log signing key")
    message = (
        b"STH" + identity + size.to_bytes(8, "big") + timestamp.encode("ascii") + root
    )
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
    except InvalidSignature:
        raise ValueError("Invalid signed tree head signature") from None
    if size == 0 and root != _EMPTY:
        raise ValueError("Invalid empty tree root")
    return fields


def _nodes(path: Sequence[str], maximum: int) -> Iterator[bytes]:
    if (
        not isinstance(path, Sequence)
        or isinstance(path, (str, bytes, bytearray))
        or len(path) > maximum
    ):
        raise ValueError("Invalid Merkle path")
    return iter(tuple(_bytes(v) for v in path))


def _take(nodes: Iterator[bytes]) -> bytes:
    try:
        return next(nodes)
    except StopIteration:
        raise ValueError("Truncated Merkle path") from None


def verify_inclusion(
    leaf_hash: str, index: int, size: int, root_hash: str, path: Sequence[str]
) -> None:
    """Reconstruct the root from the signed leaf digest and bottom-up siblings."""
    if _size(index) >= _size(size):
        raise ValueError("Leaf index is outside the requested tree")
    root = _bytes(root_hash)
    leaf = hashlib.sha256(b"\x00" + _bytes(leaf_hash)).digest()
    nodes = _nodes(path, (size - 1).bit_length())

    def walk(i: int, width: int) -> bytes:
        if width == 1:
            return leaf
        left = _split(width)
        if i < left:
            return _parent(walk(i, left), _take(nodes))
        right = walk(i - left, width - left)
        return _parent(_take(nodes), right)

    if walk(index, size) != root or next(nodes, None) is not None:
        raise ValueError("Inclusion proof does not match the signed root and size")


def verify_consistency(
    old_size: int, new_size: int, old_root: str, new_root: str, path: Sequence[str]
) -> None:
    """Reconstruct both signed roots from the RFC 6962 prefix decomposition."""
    if _size(old_size) > _size(new_size):
        raise ValueError("Older tree exceeds the requested new tree")
    old, new = _bytes(old_root), _bytes(new_root)
    nodes = _nodes(path, (new_size - 1).bit_length() + 1)
    if old_size == 0 or old_size == new_size:
        if (
            (old_size == 0 and old != _EMPTY)
            or (old_size == new_size and old != new)
            or next(nodes, None) is not None
        ):
            raise ValueError("Invalid empty or equal-size consistency proof")
        return

    def walk(prefix: int, width: int, known_root: bool) -> tuple[bytes, bytes]:
        # Invert RFC 6962 SUBPROOF. The old signed root supplies the base only
        # when the prefix is itself the complete leftmost subtree.
        if prefix == width:
            base = old if known_root else _take(nodes)
            return base, base
        left = _split(width)
        if prefix <= left:
            prior, current = walk(prefix, left, known_root)
            return prior, _parent(current, _take(nodes))
        prior, current = walk(prefix - left, width - left, False)
        sibling = _take(nodes)
        return _parent(sibling, prior), _parent(sibling, current)

    if walk(old_size, new_size, True) != (old, new) or next(nodes, None) is not None:
        raise ValueError("Consistency proof does not match both signed roots and sizes")
