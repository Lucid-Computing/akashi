"""Exercise soak audit transport, authenticated custody, and singleton proof decisions."""

import base64
import io
import json
import os
import socket
import sqlite3
import tempfile
import threading
import unittest
import uuid
from contextlib import closing, nullcontext
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from auditor.verdict_signing import sign_verdict, verify_signed
from escrow.crypto import seal_record, transfer_record
from escrow.mailbox import AuditorInbox
from escrow.store import Binding
from prover.reference import ReferenceTrace
from prover.request import WINDOW, build_statement
from prover.worker import CandidateProof, Unavailable
from soak.audit_service import (
    LazyScorer,
    PublicReader,
    QuietUnixServer,
    SpoolReceipts,
    accept_carrier,
    private_file,
    private_handler,
    read_body,
    sampled_verdict,
    settle_one,
)
from soak.settings import response


class SoakAuditTests(unittest.TestCase):
    def test_exact_carrier_retry_and_authenticated_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recipient = PrivateKey.generate()
            now = datetime(2026, 11, 20, tzinfo=timezone.utc)
            binding = Binding(
                "61" * 32, "91" * 32, "2026-11-20T00:00:00.000Z", 1, "soak"
            )
            wrap = os.urandom(32)
            ciphertext, slot = seal_record(wrap, binding.metadata(), b"private-test")
            ciphertext, slot = transfer_record(
                wrap, bytes(recipient.public_key), binding.metadata(), ciphertext, slot
            )
            doc = {
                "binding": asdict(binding),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "key_slot": base64.b64encode(slot).decode(),
            }
            inbox = AuditorInbox(
                root / "inbox.sqlite",
                auditor_private_key=bytes(recipient),
                clock=lambda: now,
            )
            self.assertEqual(accept_carrier(inbox, doc), binding.leaf_hash)
            self.assertEqual(accept_carrier(inbox, doc), binding.leaf_hash)
            altered = {**doc, "binding": {**asdict(binding), "leaf_hash": "62" * 32}}
            with self.assertRaises(ValueError):
                accept_carrier(inbox, altered)
            self.assertNotIn(b"private-test", (root / "inbox.sqlite").read_bytes())

    @unittest.skipUnless(
        hasattr(socket, "SO_PEERCRED"), "requires the Linux peer-credential interface"
    )
    def test_real_unix_socket_ack_follows_authenticated_inbox_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = PrivateKey.generate()
            now = datetime(2026, 11, 20, tzinfo=timezone.utc)
            binding = Binding(
                "ab" * 32, "ac" * 32, "2026-11-20T00:00:00.000Z", 1, "soak"
            )
            wrap = os.urandom(32)
            encrypted = seal_record(wrap, binding.metadata(), b"one protected sample")
            ciphertext, slot = transfer_record(
                wrap, bytes(key.public_key), binding.metadata(), *encrypted
            )
            doc = {
                "binding": asdict(binding),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "key_slot": base64.b64encode(slot).decode(),
            }
            inbox = AuditorInbox(
                root / "box.sqlite", auditor_private_key=bytes(key), clock=lambda: now
            )
            jobs = Mock()
            jobs.sample_status.return_value = None
            conf = {
                "io_timeout_seconds": 5,
                "custody_peer_uid": os.geteuid(),
                "carrier_limit_bytes": 4096,
            }
            with QuietUnixServer(
                str(root / "audit.sock"), private_handler(inbox, jobs, Mock(), conf)
            ) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:

                    def request(route: str, body: object = None) -> tuple[int, Any]:
                        return response(
                            "unix://" + str(root / "audit.sock"),
                            route,
                            timeout=5,
                            cap=4096,
                            data=body,
                        )

                    for _ in range(2):
                        self.assertEqual(
                            request("/internal/escrow/accept", doc),
                            (200, {"leaf_hash": binding.leaf_hash}),
                        )
                    self.assertEqual(
                        request("/internal/escrow/accept", {**doc, "key_slot": "!"})[0],
                        400,
                    )
                    self.assertEqual(
                        request("/internal/sampled/" + binding.leaf_hash), (404, {})
                    )
                finally:
                    server.shutdown()
                    thread.join()

    def test_sample_specific_signed_verdict_refuses_holder_substitution(self) -> None:
        signer = Ed25519PrivateKey.generate()
        leaf, t, sample, holder = (
            "61" * 32,
            "16" * 32,
            str(uuid.uuid4()),
            str(uuid.uuid4()),
        )

        def signature(subject: str) -> str:
            return json.dumps(
                sign_verdict(
                    {
                        "version": "vig-verdict/1",
                        "outcome": "UNAVAILABLE",
                        "reason": "selection_gap",
                        "verified_at": "2026-11-20T00:00:00.000Z",
                        "auditor_key_id": "a1",
                        "challenge_id": subject,
                        "transcript_commitment": t,
                    },
                    signer,
                )
            )

        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript(
                "CREATE TABLE sampled_verdict_ids(leaf,subject); CREATE TABLE sampled_obligations(leaf,job_id); CREATE TABLE audit_jobs(job_id,t); CREATE TABLE signed_verdicts(challenge_id,document);"
            )
            db.execute("INSERT INTO sampled_verdict_ids VALUES(?,?)", (leaf, sample))
            db.execute("INSERT INTO sampled_obligations VALUES(?,?)", (leaf, "job"))
            db.execute("INSERT INTO audit_jobs VALUES(?,?)", ("job", t))
            db.execute(
                "INSERT INTO signed_verdicts VALUES(?,?)", (holder, signature(holder))
            )
            jobs, store = Mock(), Mock()
            jobs._tx.return_value = nullcontext(db)
            store._public.side_effect = lambda _db, raw: verify_signed(
                json.loads(raw),
                lambda role, kid: signer.public_key().public_bytes_raw(),
            )
            self.assertEqual(sampled_verdict(jobs, store, leaf), (202, {}))
            db.execute(
                "INSERT INTO signed_verdicts VALUES(?,?)", (sample, signature(sample))
            )
            status, signed = sampled_verdict(jobs, store, leaf)
            self.assertEqual((status, signed["challenge_id"]), (200, sample))
            db.execute(
                "UPDATE signed_verdicts SET document=? WHERE challenge_id=?",
                (signature(holder), sample),
            )
            with self.assertRaises(ValueError):
                sampled_verdict(jobs, store, leaf)

    def test_restart_retires_spool_only_after_durable_verdict(self) -> None:
        with closing(sqlite3.connect(":memory:")) as db:
            jobs, spool = Mock(), Mock()
            jobs._tx.return_value = nullcontext(db)
            db.execute("CREATE TABLE audit_jobs(job_id,state)")
            db.execute("INSERT INTO audit_jobs VALUES('a','verifying')")
            receipts = SpoolReceipts(jobs, spool)
            receipts.remember("a", "a")
            receipts.remember("a", "a/corrected")
            receipts.recover(2)
            spool.handoff.assert_not_called()
            db.execute("UPDATE audit_jobs SET state='completed' WHERE job_id='a'")
            spool.handoff.side_effect = OSError("interrupted")
            with self.assertRaises(OSError):
                receipts.recover(1)
            spool.handoff.reset_mock(side_effect=True)
            restart = SpoolReceipts(jobs, spool)
            restart.recover(1)
            restart.recover(2)
            restart.recover(2)
            self.assertEqual(
                [args[0][0] for args in spool.handoff.call_args_list],
                ["a", "a/corrected"],
            )

    def test_private_bounds_and_loopback(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "private"
            private.write_bytes(b"content")
            private.chmod(0o600)
            self.assertEqual(private_file(private), b"content")
            alias = root / "link"
            alias.symlink_to(private)
            with self.assertRaises(OSError):
                private_file(alias)
            private.chmod(0o644)
            with self.assertRaises(ValueError):
                private_file(private)
        for url in (
            "http://example.com/log/v1/",
            "http://user:key@127.0.0.1:9/log/v1/",
            "file:///path",
            "http://127.0.0.1:9/log/v1/#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                PublicReader(url, 2, 1024)
        PublicReader("http://127.0.0.1:9/log/v1/", 2, 1024)
        payload = json.dumps({"test": 1}).encode()
        self.assertEqual(
            read_body(io.BytesIO(payload), len(payload), len(payload)), {"test": 1}
        )
        for n in (0, len(payload) + 1, 3 * len(payload)):
            with self.assertRaises(ValueError):
                read_body(io.BytesIO(payload), n, len(payload))

    def test_authenticated_spool_failure_uses_real_diagnosis_to_request_correction(
        self,
    ) -> None:
        jobs = Mock()
        claim = jobs.claim.return_value
        claim.prompt = (10,)
        claim.reply = (12,)
        claim.budget = 1
        claim.incomplete = False
        active = jobs.dispatch.return_value
        active.job_id = "one"
        active.deadline_ns = 2**63 - 1
        scorer = LazyScorer({})
        scorer.model = Mock()
        choices = (13,) + (0,) * (WINDOW - 1)
        scorer.model.score.return_value = ReferenceTrace(choices)
        worker, spool, verdicts = Mock(), Mock(), Mock()
        proof = CandidateProof(
            build_statement((10,), (13,)), bytes(4), b"checked-by-verdict-store"
        )
        worker.wait.side_effect = [Unavailable("spool_failure"), proof]
        spool.submit.return_value.job_id = "one/corrected"
        self.assertTrue(
            settle_one(
                jobs,
                verdicts,
                spool,
                worker,
                scorer,
                Mock(),
                lease=5,
                deadline=2,
                poll=0.1,
            )
        )
        spool.submit.assert_called_once_with(
            "one/corrected", proof.statement, deadline_ns=active.deadline_ns
        )
        verdicts.settle.assert_called_once_with(claim, proof)
        self.assertIsNone(scorer.last)

    def test_matching_proof_and_unauthenticated_failure_do_not_invoke_reference(
        self,
    ) -> None:
        for result in (
            CandidateProof(build_statement((1,), (3,)), bytes(4), b"fixture"),
            Unavailable("invalid_response"),
            Unavailable("deadline"),
        ):
            jobs, worker, spool, verdicts = Mock(), Mock(), Mock(), Mock()
            claim = jobs.claim.return_value
            claim.prompt = (1,)
            claim.reply = (3,)
            claim.budget = 1
            claim.incomplete = False
            worker.wait.return_value = result
            scorer = cast(Any, Mock())
            with self.subTest(result=type(result)):
                self.assertTrue(
                    settle_one(
                        jobs,
                        verdicts,
                        spool,
                        worker,
                        scorer,
                        Mock(),
                        lease=5,
                        deadline=2,
                        poll=0.1,
                    )
                )
                scorer.score.assert_not_called()
                spool.submit.assert_not_called()
                verdicts.settle.assert_called_once_with(claim, result)
