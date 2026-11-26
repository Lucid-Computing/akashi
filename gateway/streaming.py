"""Buffered SSE with one terminal verification and a cancellable, slot-owning worker."""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import CancelledError
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gateway.policy import Mode
    from gateway.serving import Completion, RequestControl

_COMMENT = b": keepalive\n\n"
_UNWARRANTED = b'data: {"verification":{"status":"unwarranted"}}\n\n'
_DONE = b"data: [DONE]\n\n"


def _data(event: dict[str, object]) -> bytes:
    return (
        b"data: "
        + json.dumps(event, separators=(",", ":"), allow_nan=False).encode("ascii")
        + b"\n\n"
    )


def _frames(completion: Completion, mode: Mode, usage: bool) -> tuple[bytes, bytes]:
    body = completion.body
    choices, verification = body["choices"], body["verification"]
    if (
        not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(choices[0], dict)
        or not isinstance(verification, dict)
        or verification.get("version") != "akashi/1"
        or not isinstance(verification.get("receipt"), dict)
    ):
        raise ValueError("Incomplete stream result")
    choice = choices[0]
    finish = choice.get("finish_reason")
    if finish not in ("stop", "length"):
        raise ValueError("Incomplete stream result")
    header = {k: body[k] for k in ("id", "created", "model")}
    delta: dict[str, object] = {"index": 0, "finish_reason": None}
    final: dict[str, object] = {"index": 0, "finish_reason": finish}
    if mode == "chat":
        header["object"] = "chat.completion.chunk"
        message = choice.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise ValueError("Missing decoded reply")
        delta["delta"] = {"role": "assistant", "content": message["content"]}
        final["delta"] = {}
    else:
        header["object"] = "text_completion"
        tokens = choice.get("token_ids")
        if (
            not isinstance(tokens, list)
            or not tokens
            or tokens != verification.get("reply_token_ids")
        ):
            raise ValueError("Missing raw reply")
        delta.update(text=None, token_ids=tokens)
        final.update(text=None, token_ids=[])
    terminal: dict[str, object] = {
        **header,
        "choices": [final],
        "verification": verification,
    }
    if usage:
        terminal["usage"] = body["usage"]
    return _data({**header, "choices": [delta]}), _data(terminal)


class StreamDelivery(Iterator[bytes]):
    def __init__(
        self,
        run: Callable[[], Completion],
        control: RequestControl,
        *,
        release: Callable[[], None],
        mode: Mode,
        include_usage: bool,
        heartbeat_seconds: float,
    ) -> None:
        if (
            type(heartbeat_seconds) not in (int, float)
            or not math.isfinite(heartbeat_seconds)
            or heartbeat_seconds <= 0
        ):
            raise ValueError("A finite positive heartbeat interval is required")
        self._run: Callable[[], Completion] | None = run
        self._control = control
        self._release = release
        self._mode = mode
        self._include_usage = include_usage
        self._heartbeat = heartbeat_seconds
        # The same condition wakes on completion, external cancellation and close.
        self._changed = control.queue.changed
        self._reader = threading.Lock()
        self._started = False
        self._finished = False
        self._closed = False
        self._guard: Callable[[], None] | None = None
        self._frames: tuple[bytes, bytes] | None = None
        self._next_frame = 0  # provisional, terminal, DONE, EOF
        self._next_beat = 0.0

    def _work(self, run: Callable[[], Completion]) -> None:
        frames = None
        guard = None
        try:
            try:
                self._control.check()
                completion = run()
                frames = _frames(completion, self._mode, self._include_usage)
                guard = completion.check_release
            finally:
                self._release()
        except Exception:  # noqa: BLE001 -- backend errors may contain private material.
            frames = None
        finally:
            with self._changed:
                if not self._closed and self._next_frame < 2:
                    self._frames, self._guard = frames, guard
                self._finished = True
                self._changed.notify_all()

    def _unwarranted(self) -> bytes:
        self._next_frame = 2
        self._frames = self._guard = None
        return _UNWARRANTED

    def __next__(self) -> bytes:
        with self._reader:
            return self._read()

    def _read(self) -> bytes:
        with self._changed:
            if self._closed or self._next_frame == 3:
                raise StopIteration
            if self._next_frame == 2:
                self._next_frame = 3
                return _DONE
            if not self._started:
                self._started = True
                run, self._run = self._run, None
                assert run is not None
                try:
                    self._control.check()
                    threading.Thread(
                        target=self._work, args=(run,), daemon=True, name="akashi-stream"
                    ).start()
                except Exception:  # noqa: BLE001 -- launch failure has no public diagnostics.
                    self._release()
                    return self._unwarranted()
            while not self._finished:
                if self._closed:
                    raise StopIteration
                try:
                    self._control.check()
                except CancelledError:
                    return self._unwarranted()
                now = time.monotonic()
                if self._next_beat <= now:
                    self._next_beat = now + self._heartbeat
                    return _COMMENT
                self._changed.wait(
                    max(0.0, min(self._next_beat, self._control.deadline) - now)
                )
            if self._closed:
                raise StopIteration
            if self._frames is None or self._guard is None:
                return self._unwarranted()
            guard = self._guard
        # This includes the signed promise/window checks and may consult storage.
        # Keep close/cancel responsive while it runs. Recheck control at disclosure.
        try:
            self._control.check()
            guard()
            valid = True
        except Exception:  # noqa: BLE001 -- the wire signal is always just unwarranted.
            valid = False
        with self._changed:
            if self._closed:
                raise StopIteration
            try:
                self._control.check()
            except CancelledError:
                valid = False
            if not valid or self._frames is None:
                return self._unwarranted()
            frame = self._frames[self._next_frame]
            self._next_frame += 1
            if self._next_frame == 2:
                self._frames = self._guard = None
            return frame

    def close(self) -> None:
        """Stop disclosure now. An active engine worker keeps its slot until it returns."""
        with self._changed:
            if self._closed:
                return
            self._closed = True
            self._run = None
            self._frames = self._guard = None
            self._control.cancel()
            if not self._started:
                self._release()
            self._changed.notify_all()
