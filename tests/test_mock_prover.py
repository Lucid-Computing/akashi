"""CPU worker fixtures from FlashProve spool.whole_reply at the F1 revision.

MINIMUM and FULL were measured from the #18 vectors for a 1+1 and a 1023+1
token transcript. Both exclude the 32-byte nonce reserved for a spool submission.
"""

import unittest
from dataclasses import fields

from prover.mock import MockProver, ProofRejected, ProofTimeout

MINIMUM = bytes.fromhex("400d0300 410d0300") + bytes(4092) + bytes.fromhex("01000000")
FULL = bytes.fromhex("400d0300") * 1023 + bytes.fromhex("3f150300 fe030000 ff030000")


class MockProverTests(unittest.TestCase):
    def test_repeated_worker_calls_return_statement_bound_mock_evidence(self) -> None:
        prover = MockProver()
        minimum = prover.prove(MINIMUM)
        self.assertEqual(minimum.kind, "mock")
        self.assertEqual(
            minimum.statement_sha256,
            "fe8bbd0b3f7aea514dd77ccebf2390c04489b048d3a1e32c7025d465d6611e75",
        )
        full = prover.prove(FULL)
        self.assertEqual(full.kind, "mock")
        self.assertEqual(
            full.statement_sha256,
            "f1a2187cc5b2a4a3746912753756ac9ac360706b316ca81f52ed6c51776a30ed",
        )
        self.assertEqual(prover.prove(MINIMUM), minimum)
        self.assertEqual(MockProver().prove(MINIMUM), minimum)
        self.assertNotIn("proof", {field.name for field in fields(minimum)})
        self.assertNotIn("statement", {field.name for field in fields(minimum)})

    def test_distinct_rejection_and_timeout(self) -> None:
        for worker, error in (
            (MockProver("rejection"), ProofRejected),
            (MockProver("timeout"), ProofTimeout),
        ):
            for statement in (MINIMUM, FULL, MINIMUM):
                with self.subTest(worker=error), self.assertRaises(error) as caught:
                    worker.prove(statement)
                self.assertNotIn(statement.hex(), str(caught.exception))
                self.assertFalse(hasattr(caught.exception, "proof"))

    def test_rejects_spool_nonce_and_malformed_whole_reply_statements(self) -> None:
        for reason, statement in {
            "missing range": MINIMUM[:-8],
            "spool nonce": MINIMUM + bytes(32),
            "empty range": MINIMUM[:-4] + bytes(4),
            "range past last known token": MINIMUM[:-4] + (1024).to_bytes(4, "little"),
            "descending range": MINIMUM[:-8] + bytes.fromhex("02000000 01000000"),
            "out-of-vocabulary token": (202048).to_bytes(4, "little") + MINIMUM[4:],
            "nonzero padding": MINIMUM[:8] + bytes.fromhex("01000000") + MINIMUM[12:],
        }.items():
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                MockProver().prove(statement)

    def test_malformed_input_does_not_become_a_tool_outcome(self) -> None:
        for worker in (MockProver("rejection"), MockProver("timeout")):
            with self.assertRaises(ValueError):
                worker.prove(b"")
