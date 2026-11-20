"""Buffered chat/raw SSE and cancellation at each custody boundary."""

from __future__ import annotations

import io
import json
import threading
import time
import unittest
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from unittest.mock import Mock, patch

from gateway.policy import Mode
from gateway.serving import AdmissionQueue, Completion, RequestControl
from gateway.stream_reader import IncompleteStream, terminal_evidence
from gateway.streaming import StreamDelivery

_TEXT = "💧\n\ndata: [DONE]\n\n雪"
_EVIDENCE = {
    "version": "vig/1",
    "receipt": {"private_fixture": "terminal-only"},
    "prompt_token_ids": [1],
    "reply_token_ids": [2, 3],
}


def _completion(guard: Callable[[], None], mode: Mode = "chat") -> Completion:
    choice: dict[str, object] = {"index": 0, "finish_reason": "length"}
    if mode == "chat":
        choice["message"] = {"role": "assistant", "content": _TEXT}
    else:
        choice.update(text=None, token_ids=[2, 3])
    return Completion(
        {
            "id": "cmpl-demo",
            "created": 1,
            "model": "fixture",
            "choices": [choice],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
            "verification": _EVIDENCE,
        },
        "never-a-stream-header",
        guard,
    )


class StreamTests(unittest.TestCase):
    def setUp(self) -> None:
        self.released = Mock()
        self.control = RequestControl(AdmissionQueue(), 10)

    def stream(
        self, fn: Callable[[], Completion], *, mode: Mode = "chat", usage: bool = False
    ) -> StreamDelivery:
        stream = StreamDelivery(
            fn,
            self.control,
            release=self.released,
            mode=mode,
            include_usage=usage,
            heartbeat_seconds=0.02,
        )
        self.addCleanup(stream.close)
        return stream

    def test_chat_and_raw_buffered_one_delta_then_one_terminal(self) -> None:
        for mode in ("chat", "raw"):
            for usage in (False, True):
                with self.subTest(mode=mode, usage=usage):
                    guard = Mock()
                    completion = _completion(guard, mode)
                    stream = self.stream(
                        Mock(return_value=completion), mode=mode, usage=usage
                    )
                    frames = list(stream)
                    self.assertTrue(frames[0].startswith(b":"))
                    events = [frame for frame in frames if not frame.startswith(b":")]
                    self.assertEqual(len(events), 3)
                    self.assertEqual(events[-1], b"data: [DONE]\n\n")
                    first, last = (
                        json.loads(event.removeprefix(b"data: "))
                        for event in events[:2]
                    )
                    self.assertNotIn("usage", first)
                    self.assertEqual("usage" in last, usage)
                    self.assertNotIn("verification", first)
                    self.assertEqual(last["verification"], _EVIDENCE)
                    self.assertIsNone(first["choices"][0]["finish_reason"])
                    self.assertEqual(last["choices"][0]["finish_reason"], "length")
                    if mode == "chat":
                        self.assertEqual(first["object"], "chat.completion.chunk")
                        self.assertEqual(first["choices"][0]["delta"]["content"], _TEXT)
                        self.assertEqual(last["choices"][0]["delta"], {})
                    else:
                        self.assertEqual(first["object"], "text_completion")
                        self.assertEqual(first["choices"][0]["token_ids"], [2, 3])
                        self.assertEqual(last["choices"][0]["token_ids"], [])
                    self.assertEqual(
                        terminal_evidence(io.BytesIO(b"".join(frames))), _EVIDENCE
                    )
                    self.assertEqual(guard.call_count, 2)
                    self.released.assert_called_once_with()
                    self.released.reset_mock()

    def test_never_started_close_and_failed_launch_release_once(self) -> None:
        run = Mock()
        stream = self.stream(run)
        iter(stream)
        stream.close()
        stream.close()
        self.assertEqual(list(stream), [])
        self.assertTrue(self.control.cancelled)
        self.released.assert_called_once_with()
        run.assert_not_called()
        self.control = RequestControl(AdmissionQueue(), 10)
        self.released.reset_mock()
        stream = self.stream(run)
        with patch(
            "gateway.streaming.threading.Thread.start",
            side_effect=OSError("private fixture"),
        ):
            self.assert_unwarranted(list(stream))
        stream.close()
        self.released.assert_called_once_with()
        run.assert_not_called()

    def assert_unwarranted(self, frames: list[bytes]) -> None:
        events = [item for item in frames if not item.startswith(b":")]
        self.assertEqual(events[-1], b"data: [DONE]\n\n")
        self.assertEqual(
            json.loads(events[-2].removeprefix(b"data: ")),
            {"verification": {"status": "unwarranted"}},
        )
        self.assertNotIn(b"private", b"".join(frames))
        with self.assertRaises(IncompleteStream):
            terminal_evidence(io.BytesIO(b"".join(frames)))

    def test_slow_worker_keepalives_and_no_early_slot_release(self) -> None:
        stop, running, exited = threading.Event(), threading.Event(), threading.Event()
        self.released.side_effect = exited.set

        def run() -> Completion:
            running.set()
            self.assertTrue(stop.wait(3))
            return _completion(Mock())

        stream = self.stream(run)
        self.addCleanup(stop.set)
        for _ in range(3):
            self.assertTrue(next(stream).startswith(b":"))
        self.assertTrue(running.wait(1))
        stream.close()
        self.assertEqual(list(stream), [])
        self.assertTrue(self.control.cancelled)
        self.released.assert_not_called()
        stop.set()
        self.assertTrue(exited.wait(1))
        self.released.assert_called_once_with()

    def test_expiry_waiting_sends_only_unwarranted_and_done(self) -> None:
        stop, exited = threading.Event(), threading.Event()
        self.released.side_effect = exited.set

        def run() -> Completion:
            if not stop.wait(3):
                raise RuntimeError("private stall")
            return _completion(Mock())

        stream = self.stream(run)
        self.addCleanup(stop.set)
        self.assertTrue(next(stream).startswith(b":"))
        self.control.deadline = time.monotonic()
        self.assert_unwarranted(list(stream))
        stop.set()
        self.assertTrue(exited.wait(1))
        self.released.assert_called_once_with()

    def test_after_provisional_cancellation_or_stale_signed_promise(self) -> None:
        for cancel in (True, False):
            self.control = RequestControl(AdmissionQueue(), 10)
            guard = Mock(side_effect=[None, ValueError("private stale promise")])
            stream = self.stream(partial(_completion, guard))
            while (first := next(stream)).startswith(b":"):
                continue
            self.assertNotIn(b"verification", first)
            if cancel:
                self.control.cancel()
            self.assert_unwarranted([first, *stream])

    def test_close_while_disclosure_check_is_blocked(self) -> None:
        entered, proceed = threading.Event(), threading.Event()

        def guard() -> None:
            entered.set()
            self.assertTrue(proceed.wait(3))

        stream = self.stream(partial(_completion, guard))
        self.assertTrue(next(stream).startswith(b":"))
        with ThreadPoolExecutor(max_workers=1) as executor:
            outcome = executor.submit(list, stream)
            try:
                self.assertTrue(entered.wait(1))
                stream.close()
            finally:
                proceed.set()
            self.assertTrue(all(frame.startswith(b":") for frame in outcome.result(1)))
        self.released.assert_called_once_with()

    def test_worker_failure_missing_verification_or_invalid_raw_output(self) -> None:
        def failed() -> Completion:
            raise RuntimeError("private engine failure details")

        def no_receipt() -> Completion:
            return Completion({"verification": {}}, "private header", Mock())

        def wrong_raw() -> Completion:
            result = _completion(Mock(), "raw")
            result.body["choices"] = [{"finish_reason": "length", "token_ids": [4]}]
            return result

        for callback in (failed, no_receipt, wrong_raw):
            self.assert_unwarranted(list(self.stream(callback, mode="raw")))
            self.released.assert_called_once_with()
            self.released.reset_mock()


if __name__ == "__main__":
    unittest.main()
