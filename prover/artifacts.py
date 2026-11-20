"""Read provisioned artifacts from owner-controlled files and directories."""

import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

_DIR = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY


class SpoolError(RuntimeError):
    """Spool permissions, identity, hold or durable publication state is invalid."""


def _ancestors(path: Path, links: int = 0) -> int:
    """Open trusted ancestors. Resolve owner-controlled system links such as macOS /tmp."""
    if links > 40 or ".." in path.parts or not path.is_absolute():
        raise SpoolError("Unsafe private directory ancestry")
    fd = os.open("/", _DIR)
    try:
        parent = Path("/")
        for name in path.parts[1:]:
            about = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if about.st_uid not in (0, os.geteuid()):
                raise SpoolError("Untrusted private directory ancestry")
            if stat.S_ISLNK(about.st_mode):
                target = Path(os.readlink(name, dir_fd=fd))
                child = _ancestors(parent / target, links + 1)
            else:
                child = os.open(name, _DIR, dir_fd=fd)
            os.close(fd)
            fd = child
            about = os.fstat(fd)
            if about.st_uid not in (0, os.geteuid()) or (
                about.st_mode & 0o022 and not about.st_mode & stat.S_ISVTX
            ):
                raise SpoolError("Writable private directory ancestry")
            parent /= name
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def trusted_directory(path: str | Path) -> Iterator[int]:
    """Open a read-only parent that trusted owners control, including its ancestry."""
    fd = _ancestors(Path(path).absolute())
    try:
        yield fd
    finally:
        os.close(fd)


@contextmanager
def private_directory(
    path: str | Path, *, parent_fd: int | None = None, create: bool = False
) -> Iterator[int]:
    """Yield a verified role-owned private directory descriptor; creation is single-level."""
    path = Path(path)
    if parent_fd is None:
        absolute = path.absolute()
        with (
            trusted_directory(absolute.parent) as fd,
            private_directory(absolute.name, parent_fd=fd, create=create) as child,
        ):
            yield child
        return
    if len(path.parts) != 1 or path.name in ("", ".", ".."):
        raise SpoolError("Invalid private subdirectory")
    if create:
        try:
            os.mkdir(path, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        else:
            os.fsync(parent_fd)
    fd = os.open(path, _DIR, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise SpoolError("Directory is not private to this role")
        for forbidden in ("seed.bin", "isk.txt"):
            if entry_exists(fd, forbidden):
                raise SpoolError("Refusing a secret-key directory")
        yield fd
    finally:
        os.close(fd)


def entry_exists(fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


@contextmanager
def trusted_file(path: Path) -> Iterator[BinaryIO]:
    # The operator provisions the artifact and manifest outside group/other-writable directories.
    with trusted_directory(path.parent) as parent:
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent
        )
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022
        ):
            raise PermissionError("Untrusted provisioned artifact")
        yield stream


def sha256_stream(stream: BinaryIO) -> str:
    h = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        h.update(block)
    return h.hexdigest()
