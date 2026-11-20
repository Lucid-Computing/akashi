"""Offline fixtures from the api.drand.sh quicknet /info, /public/1 and /public/1000000.

drand-client 1.4.2 fetchBeacon verified both rounds using the pinned chain hash
and public key. The selection words below were computed independently with Node
crypto SHA-256 over commitment || round (8-byte big-endian) || raw signature,
then Buffer.readUInt32BE(0), per specs/sampling.md and RFC-0005.
"""

import unittest
from datetime import datetime, timedelta, timezone

from auditor.beacon import round_for, round_is_open, select_round, verify_round

INFO: dict[str, object] = {
    "public_key": (
        "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d106451"
        "0d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
    ),
    "period": 3,
    "genesis_time": 1692803367,
    "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
    "schemeID": "bls-unchained-g1-rfc9380",
    "metadata": {"beaconID": "quicknet"},
}
FIRST_SIG = "b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b"
LATER_SIG = "83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72"
FIRST: dict[str, object] = {
    "round": 1,
    "signature": FIRST_SIG,
    "randomness": "1466a6cd24e327188770752f6134001c64d6efcc590ccc26b721611ad96f165a",
}
LATER: dict[str, object] = {
    "round": 1000000,
    "signature": LATER_SIG,
    "randomness": "b22aad4794f7451896f7a371aa46106fd84d919f3f569acd5b2fddf1d1440af3",
}
GENESIS = datetime.fromtimestamp(1692803367, timezone.utc)


class QuicknetTests(unittest.TestCase):
    def test_round_strictly_after_mmd_and_margin(self) -> None:
        # r=6 opens at genesis + 15s. Subtract 10s MMD and 3s margin.
        cutoff = GENESIS + timedelta(seconds=2)
        tick = timedelta(microseconds=1)
        self.assertEqual(round_for(cutoff - tick), 6)
        self.assertEqual(round_for(cutoff), 7)
        self.assertEqual(round_for(cutoff + tick), 7)
        self.assertEqual(round_for(cutoff.astimezone(timezone(timedelta(hours=2)))), 7)
        self.assertEqual(round_for(GENESIS - timedelta(days=1)), 1)

    def test_round_is_open_at_terminal_boundary(self) -> None:
        opens = GENESIS + timedelta(seconds=15)
        self.assertFalse(round_is_open(6, opens - timedelta(microseconds=1)))
        self.assertTrue(round_is_open(6, opens))
        self.assertTrue(round_is_open(6, opens + timedelta(microseconds=1)))

    def test_historical_bls_signatures(self) -> None:
        self.assertEqual(verify_round(1, INFO, FIRST), bytes.fromhex(FIRST_SIG))
        self.assertEqual(verify_round(1000000, INFO, LATER), bytes.fromhex(LATER_SIG))

    def test_nested_modulo_selections(self) -> None:
        for commitment, first_word in (
            (0, 1067648162),
            (8, 1988721580),
            (1176, 2175411000),
        ):
            with self.subTest(commitment=commitment):
                self.assertEqual(
                    select_round(commitment.to_bytes(32, "big"), 1000000, INFO, LATER),
                    {n: first_word % n == 0 for n in (1, 20, 1000)},
                )

    def test_assignment_and_signer_authentication(self) -> None:
        # A valid signature plus matching randomness for a different signed round.
        with self.assertRaises(ValueError):
            verify_round(1, INFO, LATER | {"round": 1})
        with self.assertRaises(ValueError):
            verify_round(1, INFO, LATER)
        for changes in (
            {"hash": "00" * 32},
            {"public_key": "00" * 96},
            {"schemeID": "pedersen-bls-chained"},
            {"period": 30},
            {"genesis_time": 0},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify_round(1, INFO | changes, FIRST)

    def test_malformed_inputs_do_not_select_even_at_soak_rate(self) -> None:
        for changes in (
            {"signature": "xx" * 48},
            {"signature": "00" * 47},
            {"randomness": "ff" * 32},
            {"round": True},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                select_round(bytes(32), 1, INFO, FIRST | changes)
        for value in (0, True, 2**64):
            with self.subTest(assigned=value), self.assertRaises(ValueError):
                verify_round(value, INFO, FIRST)
        with self.assertRaises(ValueError):
            select_round(bytes(31), 1, INFO, FIRST)
