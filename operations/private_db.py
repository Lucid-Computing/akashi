"""Require a role-owned database and an owner-only directory for its side files."""

import os
import stat
from pathlib import Path


def private_database_file(path: Path) -> None:
    directory = path.parent.lstat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != os.geteuid()
        or directory.st_mode & 0o077
    ):
        raise PermissionError("Private state requires a private role-owned directory")
    fd = os.open(path, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise PermissionError("Private state requires a private role-owned database")
    finally:
        os.close(fd)
