"""RFC 6962 Merkle roots and proofs over the 32-byte VIG public leaf digests."""

import hashlib
from collections.abc import Callable

# read(start, width) fetches an immutable complete subtree spanning those leaves.
ReadNode = Callable[[int, int], bytes]
_MAX_SIZE = (1 << 64) - 1
_EMPTY = hashlib.sha256(b"").digest()


def _size(value: int) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_SIZE:
        raise ValueError("expected an unsigned 64-bit tree size or index")


def _digest(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("expected a 32-byte binary digest")
    return value


def _parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def append_nodes(
    index: int, leaf_hash: bytes, read: ReadNode
) -> tuple[tuple[int, int, bytes], ...]:
    """Return (start, width, digest) for each node completed by this append."""
    _size(index)
    if index == _MAX_SIZE:
        raise ValueError("append would exceed the uint64 tree size")
    start = index
    width = 1
    digest = hashlib.sha256(b"\x00" + _digest(leaf_hash)).digest()
    nodes = [(start, width, digest)]
    while start & width:
        start -= width
        digest = _parent(_digest(read(start, width)), digest)
        width *= 2
        nodes.append((start, width, digest))
    return tuple(nodes)


def _split(width: int) -> int:
    """Largest power of two strictly smaller than width, for width > 1."""
    return 1 << ((width - 1).bit_length() - 1)


def _subtree(start: int, width: int, read: ReadNode) -> bytes:
    # RFC splits align with the complete subtrees persisted by append_nodes.
    if width & (width - 1) == 0:
        return _digest(read(start, width))
    left = _split(width)
    return _parent(
        _digest(read(start, left)), _subtree(start + left, width - left, read)
    )


def root_hash(size: int, read: ReadNode) -> bytes:
    """Return the historical root after exactly size leaves."""
    _size(size)
    return _subtree(0, size, read) if size else _EMPTY


def inclusion_path(index: int, size: int, read: ReadNode) -> tuple[bytes, ...]:
    """Return the leaf's sibling digests from the bottom of the tree upwards."""
    _size(index)
    _size(size)
    if index >= size:
        raise ValueError("leaf index is outside this tree")
    siblings = []
    start = 0
    while size > 1:
        left = _split(size)
        if index < start + left:
            siblings.append(_subtree(start + left, size - left, read))
            size = left
        else:
            siblings.append(_digest(read(start, left)))
            start += left
            size -= left
    return tuple(reversed(siblings))


def consistency_path(old_size: int, new_size: int, read: ReadNode) -> tuple[bytes, ...]:
    """Prove that the old root covers a prefix of the new tree (RFC 6962 §2.1.2)."""
    _size(old_size)
    _size(new_size)
    if old_size > new_size:
        raise ValueError("old tree size exceeds new tree size")
    if old_size == 0 or old_size == new_size:
        return ()
    start = 0
    siblings = []
    include_subroot = False
    while old_size != new_size:
        left = _split(new_size)
        if old_size <= left:
            siblings.append(_subtree(start + left, new_size - left, read))
            new_size = left
        else:
            # The next prefix is interior. Its root cannot be inferred from
            # the holder's old root, so RFC SUBPROOF includes it at the base.
            include_subroot = True
            siblings.append(_digest(read(start, left)))
            start += left
            old_size -= left
            new_size -= left
    if include_subroot:
        siblings.append(_subtree(start, new_size, read))
    return tuple(reversed(siblings))
