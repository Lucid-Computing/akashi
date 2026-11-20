"""Offline holder outcomes with signed promises, real inclusion paths and trusted checkpoints."""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import ANY, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auditor.beacon import round_for
from gateway.discovery import ServiceConfig
from gateway.renderer import CHAT_PROFILE_DIGEST, RAW_PROFILE_DIGEST, ChatRenderer
from log.receipt import leaf_hash, params_digest, transcript_commitment
from log.store import MerkleLog
from tests.test_discovery import CONFIG
from verifier.holder import COMMITMENT, verify


class HolderTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.now = datetime(2026, 11, 20, 9, tzinfo=timezone.utc)
        self.signer = Ed25519PrivateKey.generate()
        self.cfg = ServiceConfig(
            **{
                **CONFIG,
                "log_public_key": self.signer.public_key().public_bytes_raw().hex(),
            }
        )
        self.trusted = self.cfg.descriptor()
        self.log = MerkleLog(
            self.root / "log.db",
            log_id=self.cfg.log_id,
            log_key_id=self.cfg.log_key_id,
            signing_key=self.signer,
            leaf_hash=leaf_hash,
            clock=lambda: self.now,
        )
        self.old = self.log.head()

    def bundle(
        self,
        reply: tuple[int, ...] = (2, 3),
        *,
        wrong_round: bool = False,
        chat: ChatRenderer | None = None,
    ) -> dict[str, Any]:
        messages = [{"role": "user", "content": "Test the holder's original input."}]
        prompt = chat.render(messages) if chat else (17, 4)
        profile = CHAT_PROFILE_DIGEST if chat else RAW_PROFILE_DIGEST
        salt = "01" * 32
        fields = {
            "log_id": self.cfg.log_id,
            "log_key_id": self.cfg.log_key_id,
            "endpoint_id": "test-holder",
            "request_id": str(uuid.uuid4()),
            "commitment_id": COMMITMENT,
            "served_at": "2026-11-20T09:00:00.000Z",
            "render_profile": profile,
            "beacon_round": round_for(self.now) + int(wrong_round),
            "params_digest": params_digest(2),
            "transcript_commitment": transcript_commitment(
                COMMITMENT, profile, 2, salt, prompt, reply
            ),
            "sampling_mode": "live",
        }
        receipt = self.log.append(fields)
        index = receipt.pop("leaf_index")
        assert isinstance(index, int)
        receipt["salt"] = salt
        head = self.log.head()
        size = head["tree_size"]
        assert isinstance(size, int)
        history = {
            "sth": head,
            "inclusion": {
                "tree_size": size,
                "leaf_index": index,
                "audit_path": [s.hex() for s in self.log.path(index, size)],
            },
            "consistency": {"from": 0, "to": size, "consistency_path": []},
        }
        return {
            "verification": {
                "version": "vig/1",
                "receipt": receipt,
                "prompt_token_ids": list(prompt),
                "reply_token_ids": list(reply),
            },
            "max_tokens": 2,
            "input": messages if chat else list(prompt),
            "text": chat.decode(reply) if chat else None,
            "history": history,
        }

    def test_receipt_only_missing_proof_and_all_verifier_outcomes(self) -> None:
        bundle = self.bundle()
        with patch("verifier.holder.check_proof", side_effect=AssertionError):
            result = verify(
                bundle, self.trusted, self.old, receipt_only=True, now=self.now
            )
            self.assertEqual(
                (result.exit_code, result.outcome), (30, "RECEIPT_VERIFIED")
            )
        self.assertEqual(
            verify(bundle, self.trusted, now=self.now).outcome, "NO_VERDICT"
        )
        for code, kind in (
            (0, "CONFORMS"),
            (20, "PROOF_REJECTED"),
            (21, "DEVIATES"),
            (30, "NO_VERDICT"),
        ):
            with (
                self.subTest(code=code),
                patch(
                    "verifier.holder.check_proof", return_value=(code, kind)
                ) as backend,
            ):
                result = verify(bundle, self.trusted, self.old, now=self.now)
                self.assertEqual((result.exit_code, result.outcome), (code, kind))
                backend.assert_called_once_with(
                    (17, 4), (2, 3), 2, None, runtime=None, record_disagreement=ANY
                )

    def test_independent_verifier_disagreement_is_preserved(self) -> None:
        def disagree(
            *args: object,
            runtime: object,
            record_disagreement: Callable[[str, str], None],
        ) -> tuple[int, str]:
            record_disagreement("verified", "rejected")
            return 30, "VERIFIER_DISAGREEMENT"

        with patch("verifier.holder.check_proof", side_effect=disagree):
            result = verify(self.bundle(), self.trusted, now=self.now).as_json()
        self.assertEqual(result["exit_code"], 30)
        self.assertEqual(
            result["verifier_outcomes"], {"native": "verified", "lean": "rejected"}
        )

    def test_wrong_original_budget_display_or_identity(self) -> None:
        bundle = self.bundle()
        for key, value, expected in (
            ("max_tokens", 1, 10),
            ("input", [4, 17], 11),
            ("input", [True], 11),
            ("text", "secret", 12),
        ):
            with self.subTest(key=key):
                self.assertEqual(
                    verify(
                        {**bundle, key: value}, self.trusted, now=self.now
                    ).exit_code,
                    expected,
                )
        self.assertEqual(
            verify(bundle, {**self.trusted, "commitment_id": "00" * 32}).exit_code, 10
        )
        bundle["verification"]["receipt"]["salt"] = "ff" * 32
        self.assertEqual(verify(bundle, self.trusted).exit_code, 10)
        self.assertEqual(
            verify(self.bundle(wrong_round=True), self.trusted).exit_code, 10
        )
        self.assertEqual(verify(self.bundle((2,)), self.trusted).exit_code, 13)
        self.assertEqual(verify(self.bundle((200001, 3)), self.trusted).exit_code, 13)

    def test_checkpoint_and_inclusion_are_independent(self) -> None:
        first = self.bundle()
        old = first["history"]["sth"]
        second = self.bundle()
        history = second["history"]
        history["consistency"] = {
            "from": 1,
            "to": 2,
            "consistency_path": [x.hex() for x in self.log.consistency(1, 2)],
        }
        self.assertEqual(
            verify(second, self.trusted, old, receipt_only=True).outcome,
            "RECEIPT_VERIFIED",
        )
        for field in ("inclusion", "consistency"):
            bad = copy.deepcopy(second)
            key = "audit_path" if field == "inclusion" else "consistency_path"
            bad["history"][field][key] = ["ff" * 32]
            self.assertEqual(verify(bad, self.trusted, old).exit_code, 10)
        del history["consistency"]
        self.assertEqual(
            verify(second, self.trusted, old).outcome, "CONSISTENCY_UNAVAILABLE"
        )
        history["inclusion"] = None
        early = verify(second, self.trusted, now=self.now)
        late = verify(second, self.trusted, now=self.now + timedelta(seconds=11))
        self.assertEqual((early.outcome, early.warnings), ("INCLUSION_UNAVAILABLE", ()))
        self.assertEqual(late.warnings, ("MERGE_DEADLINE_ELAPSED",))

    def test_backdating_uses_only_a_contemporaneous_holder_witness(self) -> None:
        bundle = self.bundle()
        archived = self.now + timedelta(days=31)
        bundle["observed_at"] = archived.isoformat()
        self.assertEqual(
            verify(bundle, self.trusted, receipt_only=True, now=archived).warnings,
            ("CHALLENGE_WINDOW_EXPIRED",),
        )
        for offset, expected in (
            (timedelta(seconds=-31), ()),
            (timedelta(seconds=30), ()),
            (timedelta(seconds=30, microseconds=1), ("PROMISE_BACKDATED",)),
        ):
            with self.subTest(offset=offset):
                result = verify(
                    bundle,
                    self.trusted,
                    receipt_only=True,
                    now=self.now,
                    observed_at=self.now + offset,
                )
                self.assertEqual(
                    (result.exit_code, result.outcome, result.warnings),
                    (30, "RECEIPT_VERIFIED", expected),
                )
        late = self.now + timedelta(seconds=31)
        self.assertEqual(
            verify(bundle, self.trusted, now=archived, observed_at=late).warnings,
            ("PROMISE_BACKDATED", "CHALLENGE_WINDOW_EXPIRED"),
        )
        bundle.pop("history")
        self.assertEqual(
            verify(bundle, self.trusted, now=late, observed_at=late).warnings,
            ("PROMISE_BACKDATED", "MERGE_DEADLINE_ELAPSED"),
        )
        self.assertEqual(
            verify(
                bundle, self.trusted, observed_at=self.now.replace(tzinfo=None)
            ).exit_code,
            64,
        )

    def test_cli_keeps_delivery_observation_separate_from_untrusted_bundle(
        self,
    ) -> None:
        bundle = self.root / "observed-bundle.json"
        trusted = self.root / "observed-descriptor.json"
        bundle.write_text(json.dumps(self.bundle()))
        trusted.write_text(json.dumps(self.trusted))
        command = [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "vig"),
            "verify",
            str(bundle),
            "--descriptor",
            str(trusted),
            "--receipt-only",
            "--observed-at",
        ]
        for stamp in ("2026-11-20T09:00:30.000001Z", "2026-11-20T09:00:31+00:00"):
            run = subprocess.run([*command, stamp], capture_output=True, check=False)
            self.assertEqual(run.returncode, 30)
            result = json.loads(run.stdout)
            self.assertEqual(result["outcome"], "RECEIPT_VERIFIED")
            self.assertIn("PROMISE_BACKDATED", result["warnings"])
            self.assertNotIn(stamp.encode(), run.stdout + run.stderr)
        for stamp in (
            "2026-11-20T09:00:31",
            "2026-11-20T09:00:31+01:00",
            "private-invalid-date",
        ):
            run = subprocess.run([*command, stamp], capture_output=True, check=False)
            self.assertEqual(run.returncode, 64)
            self.assertEqual(json.loads(run.stderr)["outcome"], "USAGE")
            self.assertNotIn(stamp.encode(), run.stdout + run.stderr)

    def test_historical_keys_are_role_scoped(self) -> None:
        bundle = self.bundle()
        log = dict(self.trusted["log"])  # type: ignore[call-overload]
        historical = {
            "key_id": log["log_key_id"],
            "public_key": log["log_public_key"],
            "active": False,
        }
        log.update(log_key_id="new", log_public_key="ff" * 32)
        for role, outcome in (
            ("log", "RECEIPT_VERIFIED"),
            ("auditor", "RECEIPT_INVALID"),
        ):
            trusted = {
                **self.trusted,
                "log": log,
                "verification_keys": [{**historical, "role": role}],
            }
            self.assertEqual(
                verify(bundle, trusted, receipt_only=True).outcome, outcome
            )

    @unittest.skipUnless(
        os.getenv("VIG_RENDER_ASSETS"), "requires pinned chat renderer"
    )
    def test_chat_uses_holder_messages_and_display(self) -> None:
        assets = Path(os.environ["VIG_RENDER_ASSETS"])
        bundle = self.bundle(chat=ChatRenderer(assets))
        self.assertEqual(
            verify(bundle, self.trusted, assets=assets, receipt_only=True).outcome,
            "RECEIPT_VERIFIED",
        )
        self.assertEqual(
            verify(bundle, self.trusted, assets=None).outcome, "ASSETS_UNAVAILABLE"
        )
        bundle["text"] = "different"
        self.assertEqual(verify(bundle, self.trusted, assets=assets).exit_code, 12)
        bundle["input"][0]["content"] = "rewritten"
        self.assertEqual(verify(bundle, self.trusted, assets=assets).exit_code, 11)

    def test_command_exits_and_redaction(self) -> None:
        bundle = self.bundle()
        path = self.root / "bundle.json"
        descriptor = self.root / "descriptor.json"
        path.write_text(json.dumps(bundle))
        descriptor.write_text(json.dumps(self.trusted))
        cli = [sys.executable, str(Path(__file__).resolve().parents[1] / "vig")]
        for args, code, kind in (
            ([], 64, "USAGE"),
            (
                [
                    "verify",
                    str(path),
                    "--descriptor",
                    str(descriptor),
                    "--receipt-only",
                ],
                30,
                "RECEIPT_VERIFIED",
            ),
            (
                [
                    "verify",
                    str(self.root / "private-do-not-echo"),
                    "--descriptor",
                    str(descriptor),
                ],
                30,
                "INPUT_UNAVAILABLE",
            ),
        ):
            run = subprocess.run([*cli, *args], capture_output=True, check=False)
            self.assertEqual(run.returncode, code)
            out = run.stdout + run.stderr
            self.assertEqual(json.loads(out)["outcome"], kind)
            self.assertNotIn(b"private-do-not-echo", out)
        path.write_text('{"text":1,"text":2}')
        run = subprocess.run(
            [*cli, "verify", str(path), "--descriptor", str(descriptor)],
            capture_output=True,
            check=False,
        )
        self.assertEqual(run.returncode, 64)
        self.assertEqual(json.loads(run.stdout)["outcome"], "INVALID_JSON")
