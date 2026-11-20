"""Admission contracts from specs/gateway-api.md and docs/spec/02-public-api.md."""

import json
import unittest
from collections.abc import Iterator
from typing import Literal
from unittest.mock import Mock

from gateway.policy import PolicyError, admit, validate

MODEL = "descriptor-model"
RAW: dict[str, object] = {"model": MODEL, "prompt": [0, 200000, 202047]}
CHAT: dict[str, object] = {
    "model": MODEL,
    "messages": [{"role": "user", "content": "private-chat-canary"}],
}


class RequestPolicyTests(unittest.TestCase):
    def test_neutral_controls_and_engine_allowlist(self) -> None:
        request = validate(
            RAW
            | {
                "temperature": 0.0,
                "top_p": 1.0,
                "top_k": -1,
                "frequency_penalty": 0,
                "presence_penalty": 0.0,
                "repetition_penalty": 1.0,
                "n": 1,
                "seed": -7,
                "stream": True,
                "stream_options": {"include_usage": True},
                "user": "private-user-canary",
                "max_tokens": 8,
                "max_completion_tokens": 8,
            },
            "raw",
            model=MODEL,
        )
        self.assertEqual(request.prompt, (0, 200000, 202047))
        self.assertTrue(request.include_usage)
        self.assertEqual(
            request.engine_request(),
            {
                "model": MODEL,
                "prompt": [0, 200000, 202047],
                "temperature": 0,
                "return_token_ids": True,
                "max_tokens": 8,
                "stream": True,
            },
        )
        self.assertNotIn("private-user-canary", repr(request))
        for top_k in (-1, 0):
            self.assertEqual(
                validate(RAW | {"top_k": top_k}, "raw", model=MODEL).max_tokens, 256
            )

    def test_non_neutral_controls_report_the_field(self) -> None:
        for field, values in {
            "temperature": (1, True, "0"),
            "top_p": (0.9, True, "1"),
            "top_k": (1, False, 0.0),
            "frequency_penalty": (-1, False),
            "presence_penalty": (1, True),
            "repetition_penalty": (0, True),
            "n": (2, True, 1.0),
            "seed": (True, "1", 1.0),
            "stream": (1, None),
            "user": (7, False),
            "stop": ("private-stop-canary",),
            "allowed_token_ids": ([123],),
            "bad_words": (["private-string"],),
            "min_tokens": (1,),
            "logit_bias": ({"2": 5},),
            "tools": ([],),
            "response_format": ({"type": "json_object"},),
        }.items():
            for value in values:
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(PolicyError) as raised,
                ):
                    validate(RAW | {field: value}, "raw", model=MODEL)
                self.assertEqual(
                    (
                        raised.exception.status,
                        raised.exception.code,
                        raised.exception.param,
                    ),
                    (400, "unsupported_parameter", field),
                )
                payload = raised.exception.as_dict()
                self.assertEqual(set(payload), {"error"})
                self.assertEqual(set(payload["error"]), {"code", "message", "param"})
                self.assertEqual(payload["error"]["code"], "unsupported_parameter")
                self.assertEqual(payload["error"]["param"], field)
                self.assertIsInstance(payload["error"]["message"], str)
                self.assertNotIn("private-", json.dumps(payload))

    def test_budget_and_window_edges(self) -> None:
        self.assertEqual(
            validate(RAW | {"max_completion_tokens": 1}, "raw", model=MODEL).max_tokens,
            1,
        )
        self.assertEqual(
            validate(RAW, "raw", model=MODEL, max_tokens_cap=4).max_tokens, 4
        )
        self.assertEqual(
            len(validate(RAW | {"prompt": [0] * 768}, "raw", model=MODEL).prompt), 768
        )
        for changes, code in (
            ({"max_tokens": 2, "max_completion_tokens": 1}, "unsupported_parameter"),
            ({"max_tokens": True, "max_completion_tokens": 1}, "unsupported_parameter"),
            ({"max_tokens": 1, "max_completion_tokens": 1.0}, "unsupported_parameter"),
            ({"max_tokens": 257}, "unsupported_parameter"),
            ({"max_tokens": 0}, "unsupported_parameter"),
            ({"prompt": [0] * 769}, "context_too_long"),
        ):
            with self.subTest(code=code), self.assertRaises(PolicyError) as raised:
                validate(RAW | changes, "raw", model=MODEL)
            self.assertEqual(
                (raised.exception.status, raised.exception.code), (400, code)
            )
        with self.assertRaises(PolicyError):
            validate(RAW | {"max_tokens": 5}, "raw", model=MODEL, max_tokens_cap=4)

    def test_raw_contract_and_route_shapes(self) -> None:
        for prompt in ([], [True], [202048], [-1], [2.0], ["2"], "private-text"):
            with self.subTest(prompt=prompt), self.assertRaises(PolicyError) as raised:
                validate(RAW | {"prompt": prompt}, "raw", model=MODEL)
            self.assertEqual(
                (raised.exception.status, raised.exception.code),
                (400, "unsupported_content"),
            )
        routes: tuple[tuple[dict[str, object], Literal["chat", "raw"], str], ...] = (
            (RAW, "chat", "prompt"),
            (CHAT, "raw", "messages"),
        )
        for body, mode, field in routes:
            with self.subTest(mode=mode), self.assertRaises(PolicyError) as raised:
                validate(body, mode, model=MODEL, render=Mock())
            self.assertEqual(
                (raised.exception.code, raised.exception.param),
                ("unsupported_parameter", field),
            )
        for wrong_model in (
            {"prompt": [1]},
            RAW | {"model": "private-model-canary"},
            RAW | {"model": None},
        ):
            with (
                self.subTest(body=wrong_model),
                self.assertRaises(PolicyError) as raised,
            ):
                validate(wrong_model, "raw", model=MODEL)
            self.assertEqual(
                (raised.exception.code, raised.exception.param),
                ("unsupported_parameter", "model"),
            )
            self.assertNotIn("private-model-canary", str(raised.exception))

    def test_chat_uses_rendered_token_length(self) -> None:
        render = Mock(return_value=(200000, 1))
        req = validate(CHAT, "chat", model=MODEL, render=render)
        self.assertEqual(req.prompt, (200000, 1))
        self.assertFalse(req.stream)
        self.assertFalse(req.include_usage)
        render.assert_called_once_with(CHAT["messages"])
        messages = [
            {"role": "system", "content": "preserve whitespace"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": " left "},
                    {"type": "text", "text": "right "},
                ],
            },
        ]
        self.assertEqual(
            validate(
                CHAT | {"messages": messages}, "chat", model=MODEL, render=render
            ).prompt,
            (200000, 1),
        )
        render.assert_called_with(messages)
        with self.assertRaises(PolicyError) as raised:
            validate(CHAT, "chat", model=MODEL, render=Mock(return_value=(0,) * 769))
        self.assertEqual(
            (raised.exception.status, raised.exception.code), (400, "context_too_long")
        )
        with self.assertRaises(PolicyError) as raised:
            validate(
                CHAT,
                "chat",
                model=MODEL,
                render=Mock(side_effect=ValueError("private-chat-canary")),
            )
        self.assertEqual(
            (raised.exception.status, raised.exception.code),
            (400, "unsupported_content"),
        )
        self.assertNotIn("private-chat-canary", str(raised.exception))

    def test_authentication_precedes_read_and_render(self) -> None:
        def unread() -> Iterator[bytes]:
            raise AssertionError("unauthorized body read")
            yield b""

        for header in (None, "", "Basic private-key", "Bearer rejected-private-key"):
            render = Mock()
            with self.subTest(header=header), self.assertRaises(PolicyError) as raised:
                admit(
                    unread(),
                    "chat",
                    authorization=header,
                    authenticate=lambda token: False,
                    model=MODEL,
                    render=render,
                )
            self.assertEqual(raised.exception.status, 401)
            self.assertNotIn("private-key", json.dumps(raised.exception.as_dict()))
            self.assertNotIn("private-key", str(raised.exception))
            render.assert_not_called()

    def test_streaming_body_limit_precedes_parse(self) -> None:
        auth = Mock(return_value=True)

        def chunks() -> Iterator[bytes]:
            yield b"not-json"
            yield b"!"
            raise AssertionError("continued after configured limit")

        with self.assertRaises(PolicyError) as raised:
            admit(
                chunks(),
                "chat",
                authorization="Bearer private-token",
                authenticate=auth,
                model=MODEL,
                render=Mock(),
                body_limit=8,
            )
        self.assertEqual(raised.exception.status, 413)
        self.assertNotIn("private-token", json.dumps(raised.exception.as_dict()))
        auth.assert_called_once_with("private-token")
        data = json.dumps(RAW).encode()
        request = admit(
            [data[:5], data[5:]],
            "raw",
            authorization="Bearer private-token",
            authenticate=auth,
            model=MODEL,
            body_limit=len(data),
        )
        self.assertEqual(request.prompt, (0, 200000, 202047))

    def test_decode_errors_and_invalid_stream_options(self) -> None:
        for data in (b"[1]", b"null", b"{", b"\xff"):
            with self.subTest(data=data), self.assertRaises(PolicyError) as raised:
                admit(
                    data,
                    "raw",
                    authorization="Bearer ok",
                    authenticate=lambda _: True,
                    model=MODEL,
                )
            self.assertEqual(
                (raised.exception.status, raised.exception.code),
                (400, "unsupported_content"),
            )
        invalid_options: tuple[object, ...] = (
            None,
            [],
            {"include_usage": 1},
            {"unexpected": True},
        )
        for value in invalid_options:
            with self.subTest(value=value), self.assertRaises(PolicyError) as raised:
                validate(RAW | {"stream_options": value}, "raw", model=MODEL)
            self.assertEqual(
                (raised.exception.status, raised.exception.code),
                (400, "unsupported_parameter"),
            )
