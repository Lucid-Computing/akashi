"""The challenge endpoint authenticates before consuming private holder material."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from http.client import HTTPConnection
from typing import Any
from unittest.mock import Mock

from auditor.challenge_http import ChallengeApp
from auditor.intake import IntakeError
from tests.m1_flow import _loopback

_ROUTE = "/audit/v1/challenges"
_TOKEN = "private-bearer-fixture"
_CHAT = "private-holder-transcript"
_DOC = {"bundle": {"input": [{"role": "user", "content": _CHAT}]}, "leaf_index": 3}
_BODY = json.dumps(_DOC).encode()
_HANDLE = {
    "challenge_id": "73b13015-bc9d-400d-9b48-620f13802359",
    "status": "pending",
    "capability": "private-new-challenge-capability",
}


class ChallengeHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.submit = Mock(return_value={**_HANDLE, "private": _CHAT})
        self.auth = Mock(
            side_effect=lambda token: "stable-holder" if token == _TOKEN else None
        )
        self.app = ChallengeApp(
            self.submit, authenticate=self.auth, body_limit=len(_BODY)
        )

    def request(
        self, data: bytes = _BODY, /, **env: object
    ) -> tuple[int, dict[str, str], dict[str, Any]]:
        start = Mock()
        body = b"".join(
            self.app(
                {
                    "PATH_INFO": _ROUTE,
                    "REQUEST_METHOD": "POST",
                    "CONTENT_LENGTH": str(len(data)),
                    "HTTP_AUTHORIZATION": "Bearer " + _TOKEN,
                    "wsgi.input": io.BytesIO(data),
                    **env,
                },
                start,
            )
        )
        status, raw_headers = start.call_args.args
        headers = dict(raw_headers)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(int(headers["Content-Length"]), len(body))
        self.assertNotIn(_TOKEN.encode(), body)
        self.assertNotIn(_CHAT.encode(), body)
        return int(status[:3]), headers, json.loads(body)

    def test_live_submission_uses_authenticated_holder_and_safe_handle(self) -> None:
        with (
            _loopback(self.app) as port,
            contextlib.closing(HTTPConnection("127.0.0.1", port, timeout=3)) as conn,
        ):
            conn.request("POST", _ROUTE, _BODY, {"Authorization": "Bearer " + _TOKEN})
            with conn.getresponse() as response:
                self.assertEqual(
                    (response.status, response.getheader("Cache-Control")),
                    (202, "no-store"),
                )
                self.assertEqual(json.loads(response.read()), _HANDLE)
        self.auth.assert_called_once_with(_TOKEN)
        self.submit.assert_called_once_with("stable-holder", _DOC["bundle"], 3)

    def test_unauthorized_does_not_touch_length_body_or_submit(self) -> None:
        stream = Mock()
        stream.read.side_effect = AssertionError
        for auth in (
            None,
            "Bearer",
            "Basic " + _TOKEN,
            "Bearer wrong",
            "Bearer " + _TOKEN + "\r\n",
        ):
            code, headers, body = self.request(
                HTTP_AUTHORIZATION=auth,
                CONTENT_LENGTH="invalid",
                **{"wsgi.input": stream},
            )
            self.assertEqual(
                (code, headers.get("WWW-Authenticate"), body),
                (401, "Bearer", {"error": {"code": "unauthorized"}}),
            )
        stream.read.assert_not_called()
        self.submit.assert_not_called()

    def test_declared_and_terminated_bodies_are_bounded_before_parsing(self) -> None:
        stream = Mock()
        for value in ("9" * 10000, str(len(_BODY) + 1)):
            code, _, _ = self.request(CONTENT_LENGTH=value, **{"wsgi.input": stream})
            self.assertEqual(code, 413)
        stream.read.assert_not_called()
        for invalid_length in ("-1", "3, 3", "1.0", " 1", "１", 0, True):
            self.assertEqual(self.request(CONTENT_LENGTH=invalid_length)[0], 400)
        self.assertEqual(
            self.request(_BODY[:-1], CONTENT_LENGTH=str(len(_BODY)))[0], 400
        )
        self.assertEqual(self.request(CONTENT_LENGTH="")[0], 400)
        self.assertEqual(
            self.request(
                _BODY + b"x", CONTENT_LENGTH="", **{"wsgi.input_terminated": True}
            )[0],
            413,
        )
        self.assertEqual(
            self.request(
                _BODY + b"x",
                CONTENT_LENGTH=str(len(_BODY)),
                **{"wsgi.input_terminated": True},
            )[0],
            400,
        )
        self.submit.assert_not_called()
        self.assertEqual(
            self.request(CONTENT_LENGTH="", **{"wsgi.input_terminated": True})[0], 202
        )
        self.assertEqual(self.request(CONTENT_LENGTH="000" + str(len(_BODY)))[0], 202)

    def test_duplicate_nested_field_or_invalid_bundle_shape(self) -> None:
        for malformed in (
            b'{"bundle":{},"leaf_index":2,"leaf_index":3}',
            b'{"bundle":{"x":0,"x":1},"leaf_index":3}',
            b'{"bundle":{},"leaf_index":true}',
            b'{"bundle":{},"leaf_index":-1}',
            b'{"bundle":{},"leaf_index":18446744073709551616}',
            b'{"bundle":[],"leaf_index":3}',
            b'{"bundle":{},"leaf_index":3,"extra":0}',
            b'{"bundle":{"x":NaN},"leaf_index":3}',
            b'{"bundle":{"x":1e999},"leaf_index":3}',
            b'{"bundle":"\xff"}',
            b"null",
            b"{}",
            b"",
        ):
            code, _, body = self.request(malformed)
            self.assertEqual((code, body), (400, {"error": {"code": "invalid_bundle"}}))
        self.submit.assert_not_called()

    def test_authentication_and_intake_failures_never_expose_diagnostics(self) -> None:
        for exc, code, expected in (
            (IntakeError(400, "expired"), 400, "expired"),
            (IntakeError(429, "rate_limited", 42), 429, "rate_limited"),
            (IntakeError(400, "invalid_bundle"), 400, "invalid_bundle"),
            (IntakeError(400, _CHAT), 503, "verifier_unavailable"),
            (RuntimeError(_TOKEN + _CHAT), 503, "verifier_unavailable"),
        ):
            self.submit.side_effect = exc
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status, headers, body = self.request()
            self.assertEqual((status, body), (code, {"error": {"code": expected}}))
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(headers.get("Retry-After"), "42" if code == 429 else None)
        self.auth.side_effect = RuntimeError(_TOKEN)
        self.assertEqual(self.request()[0], 503)

    def test_only_the_post_submission_route_is_exposed(self) -> None:
        for route in (
            "/audit/v1/challenges/",
            "/audit/v1/challenges/holder",
            "/audit/v1/verdicts",
        ):
            self.assertEqual(self.request(PATH_INFO=route)[0], 404)
        self.assertEqual(self.request(QUERY_STRING="capability=" + _TOKEN)[0], 404)
        status, headers, _ = self.request(REQUEST_METHOD="GET")
        self.assertEqual((status, headers["Allow"]), (405, "POST"))
        self.auth.assert_not_called()
        self.submit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
