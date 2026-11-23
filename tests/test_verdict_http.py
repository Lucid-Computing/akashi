"""Capability isolation and signed, redacted audit API responses over WSGI and HTTP."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from http.client import HTTPConnection
from pathlib import Path
from typing import Any
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auditor.challenge_http import ChallengeApp
from auditor.selections import Selections, SelectionsApp
from auditor.verdict_http import VerdictApp
from auditor.verdict_signing import sign_verdict, verify_signed
from prover.request import build_statement
from tests.m1_flow import _loopback

_ID = "aefd9895-70ca-48b9-9106-cd6bd820df00"
_OTHER = "f0013d93-8887-4e1c-a7c8-1e46eaf2e23f"
_T = "6a" * 32
_BASE = "/audit/v1"
_PRIVATE = "private-audit-capability"
_STATUS = _BASE + "/challenges/" + _ID
_WHEN = "2026-11-20T09:00:00.000Z"


class VerdictHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.verdict = sign_verdict(
            {
                "version": "vig-verdict/1",
                "challenge_id": _ID,
                "transcript_commitment": _T,
                "outcome": "CONFORMS",
                "reason": "exact_match",
                "verified_at": _WHEN,
                "auditor_key_id": "auditor-test",
                "proof_sha256": "ab" * 32,
                "statement_sha256": "ce" * 32,
            },
            self.key,
        )
        self.artifact = {
            "kind": "deviation",
            "statement": build_statement((1,), (2,)).hex(),
            "proof": "eA==",
            "index": 0,
            "expected": 2,
        }
        self.store = Mock()
        self.store.by_commitment.return_value = [self.verdict]
        self.store.recent.return_value = [self.verdict]
        self.store.stats.return_value = {
            "total_challenges": 1,
            "conform": 1,
            "deviate": 0,
            "pending": 0,
            "unavailable": 0,
            "incomplete": 0,
            "excused_range": 0,
            "last_updated": _WHEN,
            "private": _PRIVATE,
        }
        self.store.private_status.side_effect = lambda cid, capability: (
            {
                "challenge_id": cid,
                "status": "completed",
                "verdict": self.verdict,
                "capability": _PRIVATE,
            }
            if cid == _ID and capability == _PRIVATE
            else None
        )
        self.store.private_proof.side_effect = lambda cid, capability: (
            {**self.artifact, "private": _PRIVATE}
            if cid == _ID and capability == _PRIVATE
            else None
        )
        self.app = VerdictApp(self.store)

    def request(
        self, path: str, query: str = "", auth: str | None = None, method: str = "GET"
    ) -> tuple[int, dict[str, str], bytes]:
        start = Mock()
        data = b"".join(
            self.app(
                {
                    "PATH_INFO": path,
                    "REQUEST_METHOD": method,
                    "QUERY_STRING": query,
                    "HTTP_AUTHORIZATION": auth,
                },
                start,
            )
        )
        status, raw_headers = start.call_args.args
        headers = dict(raw_headers)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(int(headers["Content-Length"]), len(data))
        self.assertNotIn(_PRIVATE.encode(), data)
        return int(status[:3]), headers, data

    def test_private_endpoints_are_opaque_for_unknown_expired_and_bad_credentials(
        self,
    ) -> None:
        for suffix in ("", "/proof"):
            misses = [
                self.request(_STATUS + suffix, auth=auth)
                for auth in (None, "Bearer", "Bearer wrong", "Basic " + _PRIVATE)
            ]
            misses.extend(
                [
                    self.request(
                        _BASE + "/challenges/" + _OTHER + suffix,
                        auth="Bearer " + _PRIVATE,
                    ),
                    self.request(_STATUS + suffix, "capability=" + _PRIVATE),
                    self.request(_BASE + "/challenges/not-a-uuid" + suffix),
                ]
            )
            self.assertTrue(all(r == misses[0] for r in misses))
            self.assertEqual((misses[0][0], misses[0][2]), (404, b""))
        self.store.private_status.side_effect = None
        self.store.private_status.return_value = None
        self.assertEqual(self.request(_STATUS, auth="Bearer " + _PRIVATE)[0], 404)

    def test_authorized_private_projection_and_public_signature(self) -> None:
        code, _, data = self.request(_STATUS, auth="Bearer " + _PRIVATE)
        self.assertEqual(code, 200)
        status = json.loads(data)
        self.assertEqual(
            status,
            {"challenge_id": _ID, "status": "completed", "verdict": self.verdict},
        )
        for path, query in (
            (_BASE + "/verdicts", "commitment=" + _T),
            (_BASE + "/verdicts/recent", "hours=168"),
        ):
            code, _, data = self.request(path, query)
            self.assertEqual(code, 200)
            signed = json.loads(data)["verdicts"]
            self.assertEqual(signed, [self.verdict])
            self.assertNotIn(b"prompt_token", data)
            self.assertNotIn(b'"proof":', data)
            self.assertEqual(
                verify_signed(
                    signed[0], lambda *_: self.key.public_key().public_bytes_raw()
                ),
                self.verdict,
            )
        code, _, data = self.request(_STATUS + "/proof", auth="Bearer " + _PRIVATE)
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(data), self.artifact)
        self.store.recent.assert_called_once_with(168)
        self.store.by_commitment.assert_called_once_with(_T)

    def test_statistics_and_query_validation(self) -> None:
        code, _, data = self.request(_BASE + "/stats")
        self.assertEqual(code, 200)
        self.assertNotIn("private", json.loads(data))
        for route, query in (
            ("stats", "hours=1"),
            ("verdicts", ""),
            ("verdicts", "commitment=" + _T.upper()),
            ("verdicts", "commitment=" + _T + "&commitment=" + _T),
            ("verdicts/recent", "hours=0"),
            ("verdicts/recent", "hours=169"),
            ("verdicts/recent", "hours=1&hours=2"),
            ("verdicts/recent", "hours=1e1"),
        ):
            self.assertEqual(self.request(_BASE + "/" + route, query)[0], 400)
        self.assertEqual(self.request(_BASE + "/unlisted")[0], 404)
        self.assertEqual(self.request(_BASE + "/stats", method="POST")[0], 405)
        self.store.by_commitment.assert_not_called()
        self.store.recent.assert_not_called()

    def test_broken_backend_or_private_fields_in_signed_payload_cannot_escape(
        self,
    ) -> None:
        self.store.recent.return_value = [{**self.verdict, "secret": _PRIVATE}]
        self.store.private_status.side_effect = None
        self.store.private_status.return_value = {
            "challenge_id": _OTHER,
            "status": "completed",
            "verdict": self.verdict,
        }
        self.store.stats.side_effect = RuntimeError(_PRIVATE)
        self.store.private_proof.side_effect = None
        self.store.private_proof.return_value = {**self.artifact, "proof": "eB=="}
        with contextlib.redirect_stderr(io.StringIO()) as capture:
            for route, query in (
                (_BASE + "/verdicts/recent", "hours=1"),
                (_BASE + "/stats", ""),
                (_STATUS, ""),
                (_STATUS + "/proof", ""),
            ):
                self.assertEqual(
                    self.request(route, query, "Bearer " + _PRIVATE)[::2], (503, b"")
                )
            self.assertEqual(capture.getvalue(), "")

    def test_aggregate_serves_actual_selections_and_stats_over_http(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            selections = SelectionsApp(
                Selections(Path(tmp) / "public", log_id=_T), page_size=1
            )
            app = VerdictApp(self.store, selections=selections)
            with (
                _loopback(app) as port,
                contextlib.closing(
                    HTTPConnection("127.0.0.1", port, timeout=3)
                ) as client,
            ):
                for path, expected in (
                    ("/audit/v1/selections", "selections"),
                    ("/audit/v1/stats", "total_challenges"),
                ):
                    client.request("GET", path)
                    with client.getresponse() as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(
                            response.getheader("Cache-Control"), "no-store"
                        )
                        self.assertIn(expected, json.loads(response.read()))

    def test_aggregate_dispatches_real_post_intake(self) -> None:
        submit = Mock(
            return_value={
                "challenge_id": _ID,
                "capability": _PRIVATE,
                "status": "pending",
            }
        )
        app = VerdictApp(
            self.store,
            intake=ChallengeApp(
                submit, authenticate=lambda _: "holder", body_limit=512
            ),
        )
        with (
            _loopback(app) as port,
            contextlib.closing(HTTPConnection("127.0.0.1", port, timeout=3)) as client,
        ):
            client.request(
                "POST",
                _BASE + "/challenges",
                json.dumps({"bundle": {}, "leaf_index": 0}),
                {"Authorization": "Bearer fixture"},
            )
            with client.getresponse() as response:
                self.assertEqual(response.status, 202)
                result: dict[str, Any] = json.loads(response.read())
                self.assertEqual(result["capability"], _PRIVATE)
        submit.assert_called_once_with("holder", {}, 0)


if __name__ == "__main__":
    unittest.main()
