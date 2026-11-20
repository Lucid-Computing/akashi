"""Wake the host's expiry worker when another process stages an earlier deadline."""

import errno
import fcntl
import os
import selectors
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path


class Wakeup:
    def __init__(self, database: Path) -> None:
        self.path = database.with_name(database.name + ".wake")
        with suppress(FileExistsError):
            os.mkfifo(self.path, 0o600)
        info = self.path.lstat()
        if (
            not stat.S_ISFIFO(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise PermissionError("expected a private role-owned escrow wakeup pipe")

    def set(self) -> None:
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                # The next supervised worker begins by reading durable deadlines.
                return
            raise
        try:
            with suppress(BlockingIOError, BrokenPipeError):
                os.write(fd, b".")
        finally:
            os.close(fd)

    @contextmanager
    def reader(self) -> Iterator[Callable[[float | None], None]]:
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock, "rb") as owner:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd = os.open(self.path, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(fd, selectors.EVENT_READ)

                    def wait(delay: float | None) -> None:
                        if selector.select(delay):
                            os.read(fd, 4096)

                    yield wait
            finally:
                os.close(fd)
