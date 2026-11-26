"""Preflight owner-only credentials before running a service under its own UID."""

import os
import pwd
import stat
import sys
from pathlib import Path


def check_directory(path: Path, uid: int, *, prover_keys: bool = False) -> None:
    info = path.lstat()
    if info.st_uid != uid or info.st_mode != stat.S_IFDIR | 0o700:
        raise ValueError("invalid credential directory")
    for child in path.iterdir():
        info = child.lstat()
        if prover_keys and stat.S_ISDIR(info.st_mode):
            check_directory(child, uid, prover_keys=True)
        elif (
            info.st_uid != uid
            or info.st_nlink != 1
            or info.st_mode != stat.S_IFREG | (0o400 if prover_keys else 0o600)
        ):
            raise ValueError("invalid credential file")


if __name__ == "__main__":
    try:
        role = sys.argv[1]
        uid = os.geteuid()
        if uid == 0 or pwd.getpwuid(uid).pw_name != f"akashi-{role}":
            raise ValueError("unexpected service account")
        check_directory(Path("/etc/akashi/keys") / role, uid)
        if role == "prover":
            check_directory(Path("/prover/keys"), uid, prover_keys=True)
    except (IndexError, KeyError, OSError, ValueError):
        sys.exit("Service credential ownership or permissions failed validation")
