"""CPU verification binds the original served prefix, even with two proof checkers."""

import hashlib
import json
import os
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from prover.request import build_statement
from prover.runtime import REVISION
from prover.scoring import Divergence
from prover.submission import COMMITMENT
from prover.worker import CandidateProof
from verifier.native_output import native_outcome
from verifier.proof import NativeVerifier, Verification, verify_reply

_POLICY = {
    "version": "H821",
    "C": "256",
    "theta": "256",
    "cap": "0",
    "s": "15",
    "sh": "8",
    "sT": "4",
    "F": "24",
    "record": "1",
}
_POLICY_BYTES = "".join(f"{k} {v}\n" for k, v in _POLICY.items()).encode()
_PROOF = b"CPPFH821" + bytes(4) + b"cpu fixture"
_REQUEST = build_statement((3, 4), (5, 6))
# Terminal accounting format from the pinned verifier, with the local fixture's range.
_OUTPUT = (
    "commitment: 86 closeness rounds of the one-time files rest on another source than the bound within a third of the distance; "
    "the table has a record: the binding of the weights rests on the theorem on codes (ePrint 2025/2055, Theorem 4.6), taken as given\n"
    "proof of work: up to 32 bits counted in 71 rounds; with it the least round has 128.00 bits, without it 96.23 bits\n"
    f"result-v1 status=0 claim=exact-match id={COMMITMENT} bits=128 work=32 work-rounds=71 least-round=128.00 "
    "least-round-without-work=96.23 commitment-assumed-rounds=86 record=1 r=1 e=3 T=1024 tokens=2..3 y=no policy=exact-match "
    f"C=256 theta=256 cap=0 s=15 sh=8 sT=4 F=24 above-clip=0 leaf=0 stages=key,leaf,request dw=8 build={'ab' * 32}\nYES\n"
).encode()


class ProofVerificationTests(unittest.TestCase):
    def test_coverage_and_accounting_must_match_even_with_exit_zero(self) -> None:
        self.assertEqual(
            native_outcome(0, _OUTPUT, _REQUEST, _PROOF, _POLICY), "verified"
        )
        for good, bad in (
            (b"claim=exact-match", b"claim=next-token"),
            (b"tokens=2..3", b"tokens=2..2"),
            (b"r=1", b"r=2"),
            (b"y=no", b"y=yes"),
            (b"record=1", b"record=0"),
            (b"leaf=0", b"leaf=1"),
            (COMMITMENT.encode(), b"0" * 64),
            (b"work-rounds=71", b"work-rounds=72"),
            (b"least-round=128", b"least-round=129"),
            (b"commitment-assumed-rounds=86", b"commitment-assumed-rounds=85"),
            (b"stages=key,leaf,request", b"stages=leaf,request"),
            (b"theta=256", b"theta=128"),
            (b"YES\n", b"YES\nNOT-A-VERIFICATION\n"),
            (b"the table has a record", b"missing record"),
        ):
            with self.subTest(good=good):
                self.assertEqual(
                    native_outcome(
                        0, _OUTPUT.replace(good, bad), _REQUEST, _PROOF, _POLICY
                    ),
                    "unavailable",
                )
        for prefix in (b"TEST BUILD:\n", b"result-v1 status=0\n"):
            self.assertEqual(
                native_outcome(0, prefix + _OUTPUT, _REQUEST, _PROOF, _POLICY),
                "unavailable",
            )

    def test_native_exits_do_not_promote_input_or_runtime_errors(self) -> None:
        self.assertEqual(
            native_outcome(1, b"NO: proof-refused\n", _REQUEST, _PROOF, _POLICY),
            "rejected",
        )
        for code in (-9, 1, 2, 3, 4, 5, 14, 15, 20, 124):
            self.assertEqual(
                native_outcome(code, _OUTPUT, _REQUEST, _PROOF, _POLICY), "unavailable"
            )
        self.assertEqual(
            native_outcome(0, b"YES\n", _REQUEST, _PROOF, _POLICY), "unavailable"
        )

    def test_disagreement_preserves_both_outcomes_and_identical_inputs(self) -> None:
        for first, other in (
            ("verified", "rejected"),
            ("unavailable", "verified"),
            ("rejected", "verified"),
            ("verified", "unavailable"),
        ):
            primary, secondary = Mock(), Mock()
            primary.check.return_value, secondary.check.return_value = first, other
            evidence = CandidateProof(_REQUEST, bytes(4), _PROOF)
            result = verify_reply(
                (3, 4), (5, 6), 2, evidence, primary, secondary=secondary
            )
            self.assertEqual(
                (result.outcome, result.primary, result.secondary),
                ("disagreement", first, other),
            )
            for checker in (primary, secondary):
                checker.check.assert_called_once_with(_REQUEST, bytes(4), _PROOF)

    def test_reconstruction_rejection_and_missing_evidence_are_distinct(self) -> None:
        checker = Mock()
        checker.check.return_value = "rejected"
        c = CandidateProof(_REQUEST, bytes(4), _PROOF)
        for candidate in (None, replace(c, proof=b"")):
            self.assertEqual(
                verify_reply((3, 4), (5, 6), 2, candidate, checker).outcome,
                "unavailable",
            )
        for candidate in (
            replace(c, y=b"x" * 4),
            replace(c, statement=c.statement + bytes(32)),
        ):
            self.assertEqual(
                verify_reply((3, 4), (5, 6), 2, candidate, checker).outcome,
                "statement_mismatch",
            )
        self.assertEqual(
            verify_reply((3, 4), (5, 6), 3, c, checker).outcome, "incomplete"
        )
        self.assertEqual(
            verify_reply(
                (3, 4), (5, 6), 2, c, checker, divergence=Divergence(0, 5)
            ).outcome,
            "statement_mismatch",
        )
        checker.check.assert_not_called()
        self.assertEqual(
            verify_reply((3, 4), (5, 6), 2, c, checker),
            Verification("rejected", "rejected"),
        )
        changed = build_statement((3, 4), (5, 9))
        checker.check.return_value = "verified"
        self.assertEqual(
            verify_reply(
                (3, 4),
                (5, 6),
                2,
                replace(c, statement=changed),
                checker,
                divergence=Divergence(1, 9),
            ).outcome,
            "verified",
        )
        checker.check.assert_called_with(changed, bytes(4), _PROOF)

    def test_private_snapshots_require_pinned_provisioned_files(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            cp = base / "cp_verify"
            cp.write_bytes(b"binary-fixture")
            cfg, key = base / "public-config", base / "public-key"
            cfg.mkdir()
            (key / "leaf").mkdir(parents=True)
            inputs = {
                "config/policy.txt": (cfg / "policy.txt", _POLICY_BYTES),
                "config/layout.txt": (cfg / "layout.txt", b"layout"),
                "config/KL.bin": (cfg / "KL.bin", b"kl"),
                "ivk/key.bin": (key / "key.bin", b"key"),
                "ivk/leaf/0.bin": (key / "leaf/0.bin", b"leaf"),
            }
            digest = {}
            for name, (path, data) in inputs.items():
                path.write_bytes(data)
                digest[name] = hashlib.sha256(data).hexdigest()
            manifest = base / "trusted.json"
            cp_hash = hashlib.sha256(cp.read_bytes()).hexdigest()
            doc = {
                "schema_version": 1,
                "flashprove_revision": REVISION,
                "commitment_id": COMMITMENT,
                "sha256": {
                    "cp_verify": cp_hash,
                    "config/layout.txt": digest["config/layout.txt"],
                    "config/policy.txt": digest["config/policy.txt"],
                },
            }
            manifest.write_text(json.dumps(doc))
            verifier = NativeVerifier(cp, manifest, cfg, key, 60, 1024**3, 1024)
            public = {
                k: digest[k] for k in ("config/KL.bin", "ivk/key.bin", "ivk/leaf/0.bin")
            }
            with patch.dict("verifier.proof._PUBLIC", public, clear=True):
                with verifier.workspace() as work:
                    policy, observed = verifier.stage(work, _REQUEST, bytes(4), _PROOF)
                    self.assertEqual((policy, observed), (_POLICY, cp_hash))
                    self.assertEqual((work / "request.bin").read_bytes(), _REQUEST)
                    self.assertEqual(
                        (work / "commitment.id").read_text().strip(), COMMITMENT
                    )
                    self.assertEqual(os.stat(work).st_mode & 0o077, 0)
                self.assertFalse(work.exists())
                for target in (cfg / "layout.txt", key / "key.bin", key / "leaf/0.bin"):
                    original = target.read_bytes()
                    target.write_bytes(original + b"changed")
                    with verifier.workspace() as work, self.assertRaises(ValueError):
                        verifier.stage(work, _REQUEST, bytes(4), _PROOF)
                    target.write_bytes(original)
                manifest.write_text(json.dumps(doc | {"commitment_id": "00" * 32}))
                with verifier.workspace() as work, self.assertRaises(ValueError):
                    verifier.stage(work, _REQUEST, bytes(4), _PROOF)

    def test_next_token_proof_cannot_stand_in_for_whole_reply(self) -> None:
        next_token = bytes(4096) + struct.pack("<II", 1023, 1024)
        native = (
            _OUTPUT.replace(b"claim=exact-match", b"claim=next-token")
            .replace(b"r=1 e=3", b"r=1023 e=1024")
            .replace(b"tokens=2..3 y=no", b"tokens=none y=yes")
        )
        self.assertEqual(
            native_outcome(0, native, next_token, _PROOF, _POLICY), "verified"
        )
        proof = CandidateProof(next_token, bytes(4), _PROOF)
        self.assertEqual(
            verify_reply((0,) * 1023, (0,), 1, proof, Mock()).outcome,
            "statement_mismatch",
        )
