"""Observe the current vLLM process's synchronous stdout/stderr pipe at both request boundaries."""

import math
import os
import re
import selectors
import socket
import threading
import time
from collections.abc import Callable
from subprocess import Popen

from engine.adapter import Cursor, EngineUnavailable, Window

_ERROR = re.compile(rb"\b(?:ERROR|CRITICAL|FATAL)\b")


class ProcessLog:
    """Exclusively own a fresh child pipe. Keep fault positions and discard the actual lines."""

    def __init__(
        self,
        process: Popen[bytes],
        instance: str,
        observe: Callable[[bytes], None],
        *,
        max_line_bytes: int,
        checkpoint_timeout: float,
    ) -> None:
        if (
            process.stdout is None
            or type(max_line_bytes) is not int
            or max_line_bytes <= 0
        ):
            raise ValueError("expected a fresh engine pipe and a positive line limit")
        if not math.isfinite(checkpoint_timeout) or checkpoint_timeout <= 0:
            raise ValueError("expected a positive checkpoint timeout")
        self._process = process
        self._fd = process.stdout.fileno()
        os.set_blocking(self._fd, False)
        self._instance, self._observe = instance, observe
        self._line_limit, self._timeout = max_line_bytes, checkpoint_timeout
        self._lock = threading.Lock()
        self._closed = False
        self._covered = True
        self._position, self._last_error = 0, 0
        self._partial = b""
        self._stop, self._wake = socket.socketpair()
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()

    def _consume(self, data: bytes) -> None:
        if not self._covered:
            return
        lines = (self._partial + data).split(b"\n")
        self._partial = lines.pop()
        if len(self._partial) > self._line_limit or any(
            len(line) > self._line_limit for line in lines
        ):
            self._covered = False
            self._partial = b""
            return
        for line in lines:
            self._position += len(line) + 1
            if (
                _ERROR.search(line)
                or b"EngineCore encountered a fatal error" in line
                or (
                    b"WARNING" in line
                    and (
                        b"integer_model" in line
                        or b"vLLM served the token at position" in line
                    )
                )
            ):
                self._last_error = self._position
            self._observe(line)

    def _drain(self) -> None:
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            try:
                chunk = os.read(self._fd, 65536)
            except BlockingIOError:
                return
            if not chunk:
                self._closed = True
                break
            self._consume(chunk)
        self._covered = False

    def _monitor(self) -> None:
        try:
            with selectors.DefaultSelector() as reader:
                reader.register(self._fd, selectors.EVENT_READ)
                reader.register(self._stop, selectors.EVENT_READ)
                while True:
                    for key, _ in reader.select():
                        if key.fileobj is self._stop:
                            return
                        with self._lock:
                            self._drain()
                            if self._closed:
                                return
        except (OSError, ValueError, RuntimeError):
            pass
        finally:
            with self._lock:
                self._covered = False

    def _checkpoint(self) -> int:
        # The pinned plugin logs its fault synchronously before returning tokens. Drain the
        # original process pipe after the HTTP response; a copied or asynchronous log has no such fence.
        self._drain()
        if not self._covered or self._partial or self._process.poll() is not None:
            raise EngineUnavailable("engine log checkpoint unavailable")
        return self._position

    def begin(self) -> Cursor:
        with self._lock:
            return Cursor(self._instance, self._checkpoint())

    def finish(self, start: Cursor) -> Window:
        with self._lock:
            end = Cursor(self._instance, self._checkpoint())
            return Window(start, end, True, self._last_error > start.position)

    def close(self) -> None:
        if self._wake.fileno() == -1:
            return
        self._wake.sendall(b".")
        self._thread.join()
        self._stop.close()
        self._wake.close()
        with self._lock:
            self._covered = False
            self._partial = b""
