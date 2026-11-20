"""Read provisioned artifacts from owner-controlled files and directories."""

import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from prover.submission import trusted_directory


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
