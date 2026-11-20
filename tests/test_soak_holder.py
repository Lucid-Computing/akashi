"""Restart-safe local Mode R receipt recovery and independent holder proof policy."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import ExitStack, closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from auditor.challenge_http import ChallengeApp
from auditor.intake import ChallengeIntake
from auditor.verdict_signing import sign_verdict
from engine.mock import MockEngine
from escrow.store import EscrowStore
from gateway.commit_delivery import DeliveryCommitter
from gateway.discovery import ServiceConfig
from gateway.http import ServingApp
from gateway.renderer import ChatRenderer
from gateway.serving import Serving
from log.http import LogApp
from log.receipt import leaf_hash
from log.store import MerkleLog
from pickup.http import PerIPLimit, PickupApp, make_pickup_server
from pickup.store import PickupStore
from prover.request import build_statement
from router.soak_holder import SoakHolder, _private_config, _Reload
from tests.m1_flow import _loopback
from tests.router_demo import _router
from tests.test_discovery import CONFIG
from tests.test_mock_router import serve

_DATA = {
    "case_id": "first",
    "messages": [{"role": "user", "content": "Name a color."}],
    "max_tokens": 2,
    "challenge": True,
}
_PROOF = b"CPU holder policy fixture"


class SoakHolderTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.signer = Ed25519PrivateKey.generate()
        self.auditor = Ed25519PrivateKey.generate()
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.config = ServiceConfig(
            **{
                **CONFIG,
                "log_public_key": self.signer.public_key().public_bytes_raw().hex(),
                "auditor_public_key": self.auditor.public_key()
                .public_bytes_raw()
                .hex(),
            }
        )
        self.ledger = MerkleLog(
            self.base / "log",
            log_id=self.config.log_id,
            log_key_id=self.config.log_key_id,
            signing_key=self.signer,
            leaf_hash=leaf_hash,
            clock=lambda: self.now,
        )
        descriptor = self.base / "descriptor"
        descriptor.write_text(json.dumps(self.config.descriptor()))
        self.runtime = self.base / "runtime"
        self.runtime.write_text(
            json.dumps(
                {
                    "binary": "/unprovisioned/cp_verify",
                    "manifest": "/unprovisioned/manifest",
                    "config_dir": "/unprovisioned/config",
                    "public_key_dir": "/unprovisioned/ivk",
                    "timeout_seconds": 2,
                    "memory_bytes": 2**30,
                    "max_proof_bytes": 1024,
                }
            )
        )
        self.options: dict[str, Any] = {
            "state": str(self.base / "holder.db"),
            "descriptor": str(descriptor),
            "assets": os.environ.get("VIG_RENDER_ASSETS", str(self.base)),
            "runtime": str(self.runtime),
            "router_origin": "http://127.0.0.1:1",
            "inference_bearer": "chat-only",
            "challenge_bearer": "intake-only",
            "timeout_seconds": 5,
            "max_response_bytes": 2**18,
        }

    def holder(self) -> SoakHolder:
        return SoakHolder(self.options, clock=lambda: self.now)

    def test_lost_chat_response_no_second_submission_or_private_output(self) -> None:
        holder = self.holder()
        with (
            patch.object(holder, "_head", return_value=self.ledger.head()),
            patch.object(
                holder, "_request", side_effect=ConnectionResetError("private-marker")
            ) as post,
        ):
            result = holder.advance(_DATA)
            self.assertEqual(
                result, {"schema_version": 1, "stage": "chat", "status": "uncertain"}
            )
            self.assertEqual(post.call_count, 1)
        again = self.holder()
        with patch.object(
            again, "_request", side_effect=AssertionError("unexpected resubmission")
        ):
            self.assertEqual(again.advance(_DATA), result)
        with self.assertRaises(ValueError):
            again.advance({**_DATA, "max_tokens": 3})
        self.assertEqual((self.base / "holder.db").stat().st_mode & 0o777, 0o600)
        self.options["challenge_bearer"] = "different-holder"
        with self.assertRaises(ValueError):
            self.holder()

    def test_endpoint_and_private_config_trust(self) -> None:
        for name, value in (
            ("router_origin", "http://127.0.0.1:80/elsewhere"),
            ("router_origin", "https://not-a-loopback.example"),
            ("loopback_origins", {"audit": "http://private-token@127.0.0.1:1"}),
            ("loopback_origins", {"audit": "https://not-a-loopback.example"}),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                SoakHolder({**self.options, name: value})
        private = self.base / "settings"
        private.write_text(json.dumps(self.options))
        private.chmod(0o644)
        with self.assertRaises(ValueError):
            _private_config(private)
        private.chmod(0o600)
        self.assertEqual(_private_config(private), self.options)
        with self.assertRaises(ValueError):
            SoakHolder({**self.options, "timeout_seconds": False})

    def test_only_explicit_engine_integrity_502_is_unwarranted(self) -> None:
        holder = self.holder()
        for number, (code, error, outcome) in enumerate(
            (
                (502, "unwarranted_reply", "unwarranted"),
                (502, "proxy_error", "uncertain"),
                (503, "unwarranted_reply", "uncertain"),
                (400, "private-diagnostic", "failed"),
            )
        ):
            case = {**_DATA, "case_id": f"http-{number}"}
            with (
                self.subTest(code=code, outcome=outcome),
                patch.object(holder, "_head", return_value=self.ledger.head()),
                patch.object(
                    holder,
                    "_request",
                    return_value=(code, {}, {"error": {"code": error}}),
                ) as call,
            ):
                report = holder.advance(case)
                self.assertEqual(
                    (report["status"], report["http_status"]), (outcome, code)
                )
                self.assertEqual(self.holder().advance(case), report)
                self.assertNotIn("private-diagnostic", json.dumps(report))
                self.assertEqual(call.call_count, 1)

    def test_quota_refusal_durable_until_eligible_and_uncertain_challenge_not_reissued(
        self,
    ) -> None:
        holder = self.holder()
        with patch.object(holder, "_head", side_effect=OSError):
            self.assertEqual(holder.advance(_DATA)["status"], "pending")
        holder._save("first", "new", "submit", {"bundle": {}, "leaf_index": 0})
        response = (
            429,
            {"cache-control": "no-store", "retry-after": "2"},
            {"error": {"code": "rate_limited"}},
        )
        with patch.object(holder, "_request", return_value=response) as submit:
            self.assertEqual(holder.advance(_DATA)["status"], "pending")
            self.assertEqual(submit.call_count, 1)
        with patch.object(
            holder, "_request", side_effect=AssertionError("premature intake retry")
        ):
            self.assertEqual(holder.advance(_DATA)["status"], "pending")
        self.now += timedelta(seconds=2)
        again = self.holder()
        with patch.object(
            again, "_request", side_effect=ConnectionResetError()
        ) as once:
            self.assertEqual(again.advance(_DATA)["status"], "uncertain")
            self.assertEqual(again.advance(_DATA)["status"], "uncertain")
            self.assertEqual(once.call_count, 1)
        stale = {"bundle": {}, "leaf_index": 0}
        with self.assertRaises(_Reload):
            holder._save("first", "challenge_post", "submit", stale)

    def test_terminal_requires_signed_subject_transcript_and_matching_artifact(
        self,
    ) -> None:
        holder = self.holder()
        subject, transcript = str(uuid4()), "ab" * 32
        statement = build_statement((1, 3), (4, 5))
        fields: dict[str, object] = {
            "version": "vig-verdict/1",
            "challenge_id": subject,
            "transcript_commitment": transcript,
            "auditor_key_id": self.config.auditor_key_id,
            "outcome": "CONFORMS",
            "reason": "exact_match",
            "verified_at": self.now.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "proof_sha256": hashlib.sha256(_PROOF).hexdigest(),
            "statement_sha256": hashlib.sha256(statement).hexdigest(),
        }
        artifact = {
            "kind": "conformance",
            "statement": statement.hex(),
            "proof": base64.b64encode(_PROOF).decode(),
        }
        state = {
            "handle": subject,
            "capability": "reader-only",
            "transcript_commitment": transcript,
        }
        for signed, proof in (
            (sign_verdict(fields, self.signer), artifact),
            (
                sign_verdict({**fields, "challenge_id": str(uuid4())}, self.auditor),
                artifact,
            ),
            (
                sign_verdict(
                    {**fields, "transcript_commitment": "cd" * 32}, self.auditor
                ),
                artifact,
            ),
            (
                sign_verdict(fields, self.auditor),
                {**artifact, "proof": base64.b64encode(b"different fixture").decode()},
            ),
            (sign_verdict(fields, self.auditor), {**artifact, "kind": "deviation"}),
        ):
            public = {"status": "completed", "challenge_id": subject, "verdict": signed}
            with (
                patch.object(holder, "_get", side_effect=[public, proof]),
                patch("verifier.proof.NativeVerifier.check") as native,
                self.assertRaises(ValueError),
            ):
                try:
                    holder._proof(state.copy())
                finally:
                    native.assert_not_called()

        range_fields = {
            k: v
            for k, v in fields.items()
            if k not in ("proof_sha256", "statement_sha256")
        }
        range_fields.update(outcome="EXCUSED_RANGE", reason="padding_range")
        signed_range = sign_verdict(range_fields, self.auditor)
        with patch.object(
            holder,
            "_get",
            return_value={
                "status": "completed",
                "challenge_id": subject,
                "verdict": signed_range,
            },
        ) as read:
            self.assertEqual(holder._proof(state), "excused_range")
            read.assert_called_once_with(
                holder.challenge + "/" + subject, bearer="reader-only", private=True
            )
            self.assertEqual(state["verdict_reason"], "padding_range")
            self.assertNotIn("proof_sha256", state)

    @unittest.skipUnless(os.getenv("VIG_RENDER_ASSETS"), "requires pinned F37 assets")
    def test_opaque_router_receipt_challenge_and_native_checker_boundary(self) -> None:
        assets = Path(self.options["assets"])
        clock = lambda: self.now
        key = PrivateKey.generate()
        intake = ChallengeIntake(
            self.base / "audit",
            descriptor=self.config.descriptor(),
            assets=assets,
            auditor_public_key=bytes(key.public_key),
            holder_hmac_key=os.urandom(32),
            clock=clock,
        )
        accepted: dict[str, Any] = {}

        def submit(
            holder: str, bundle: dict[str, Any], index: int
        ) -> dict[str, object]:
            handle = intake.submit(holder, bundle, index)
            accepted.update(handle=handle, bundle=bundle)
            return handle

        intake_app = ChallengeApp(
            submit,
            authenticate=lambda token: (
                "fixture-holder" if token == "intake-only" else None
            ),
            body_limit=2**18,
        )
        verdict_mode = "pending"
        status_gets = []

        def audit(env: dict[str, Any], start: Any) -> list[bytes]:
            if env["REQUEST_METHOD"] == "POST":
                return intake_app(env, start)
            handle = accepted["handle"]
            self.assertEqual(
                env["HTTP_AUTHORIZATION"], "Bearer " + handle["capability"]
            )
            path = "/audit/v1/challenges/" + handle["challenge_id"]
            status_gets.append(env["PATH_INFO"])
            verification = accepted["bundle"]["verification"]
            statement = build_statement(
                tuple(verification["prompt_token_ids"]),
                tuple(verification["reply_token_ids"]),
            )
            if env["PATH_INFO"] == path + "/proof":
                obj: dict[str, Any] = {
                    "kind": "conformance",
                    "statement": statement.hex(),
                    "proof": base64.b64encode(_PROOF).decode(),
                }
            else:
                self.assertEqual(env["PATH_INFO"], path)
                obj = {"challenge_id": handle["challenge_id"], "status": verdict_mode}
                if verdict_mode == "completed":
                    obj["verdict"] = sign_verdict(
                        {
                            "version": "vig-verdict/1",
                            "challenge_id": handle["challenge_id"],
                            "transcript_commitment": verification["receipt"][
                                "transcript_commitment"
                            ],
                            "outcome": "CONFORMS",
                            "reason": "exact_match",
                            "verified_at": self.now.isoformat(
                                timespec="milliseconds"
                            ).replace("+00:00", "Z"),
                            "auditor_key_id": self.config.auditor_key_id,
                            "proof_sha256": hashlib.sha256(_PROOF).hexdigest(),
                            "statement_sha256": hashlib.sha256(statement).hexdigest(),
                        },
                        self.auditor,
                    )
            raw = json.dumps(obj).encode()
            start(
                "200 OK",
                [
                    ("Cache-Control", "no-store"),
                    ("Content-Length", str(len(raw))),
                    ("Content-Type", "application/json"),
                ],
            )
            return [raw]

        pickup = PickupStore(self.base / "pickup", clock=clock)
        escrow = EscrowStore(
            self.base / "escrow",
            wrapping_key=os.urandom(32),
            auditor_public_key=bytes(key.public_key),
            clock=clock,
        )
        delivery = DeliveryCommitter(
            self.config,
            endpoint_id="holder-case",
            sampling_mode="soak",
            stage=escrow.stage,
            append=self.ledger.append,
            pickup=pickup,
            clock=clock,
        )
        serving = ServingApp(
            Serving(
                self.config,
                ChatRenderer(assets),
                MockEngine(),
                delivery,
                lambda token: token == "chat-only",
            ),
            request_timeout=5,
            retry_after_seconds=1,
        )

        def local(port: int) -> str:
            return f"http://127.0.0.1:{port}"

        with ExitStack() as stack:
            upstream = stack.enter_context(_loopback(serving))
            router = stack.enter_context(_router(upstream, "opaque"))
            log = stack.enter_context(
                _loopback(LogApp(self.ledger, gateway_identity="holder-case"))
            )
            pickups = stack.enter_context(
                serve(
                    make_pickup_server(
                        PickupApp(
                            pickup,
                            limiter=PerIPLimit(
                                requests=16, period_seconds=60, max_peers=1
                            ),
                        ),
                        port=0,
                    )
                )
            )
            audits = stack.enter_context(_loopback(audit))
            self.options.update(
                router_origin=local(router),
                loopback_origins={
                    "log": local(log),
                    "pickup": local(pickups),
                    "audit": local(audits),
                },
            )
            holder = self.holder()
            first = holder.advance(_DATA)
            self.assertEqual(
                (first["status"], first["stage"], first["leaf_index"]),
                ("pending", "verdict", 0),
            )
            self.assertEqual(self.ledger.head()["tree_size"], 1)
            verdict_mode = "completed"
            # Absent native public files cannot turn a signed auditor opinion into verified conformance.
            self.assertEqual(self.holder().advance(_DATA)["status"], "pending")
            with patch(
                "verifier.proof.NativeVerifier.check", return_value="verified"
            ) as native:
                result = self.holder().advance(_DATA)
                self.assertEqual(
                    (result["status"], result["stage"]), ("conforms", "proof")
                )
                self.assertEqual(
                    result["proof_sha256"], hashlib.sha256(_PROOF).hexdigest()
                )
                native.assert_called_once()
                self.assertEqual(native.call_args.args[-1], _PROOF)
                self.assertEqual(self.holder().advance(_DATA), result)
                native.assert_called_once()
            self.assertEqual(
                result.keys(),
                {
                    "schema_version",
                    "status",
                    "stage",
                    "leaf_index",
                    "leaf_hash",
                    "transcript_commitment",
                    "proof_sha256",
                    "statement_sha256",
                    "prompt_tokens",
                    "reply_tokens",
                    "verdict_sha256",
                    "verdict_outcome",
                    "verdict_reason",
                },
            )
            self.assertNotIn(accepted["handle"]["capability"], json.dumps(result))
            control = {**_DATA, "case_id": "recovery-only", "challenge": False}
            self.assertEqual(self.holder().advance(control)["status"], "recovered")
            self.assertEqual(self.ledger.head()["tree_size"], 2)
            with closing(sqlite3.connect(self.base / "audit")) as db:
                self.assertEqual(
                    db.execute("SELECT count(*) FROM challenge_handles").fetchone()[0],
                    1,
                )
            self.assertIn("/proof", status_gets[-1])


if __name__ == "__main__":
    unittest.main()
