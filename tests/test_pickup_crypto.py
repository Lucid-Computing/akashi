"""Protocol known answers from the independent generator documented with pickup-v1.json."""

import hashlib
import hmac
import json
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import call, patch

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

from pickup.crypto import PickupError, lookup_id, parse_holder_secret, seal
from pickup.crypto import open as open_pickup

VECTOR = Path(__file__).parent / "fixtures" / "pickup-v1.json"


def frame(data: bytes) -> bytes:
    return len(data).to_bytes(4, "little") + data


class PickupCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.v: dict[str, Any] = json.loads(VECTOR.read_bytes())
        self.secret = bytes.fromhex(self.v["holder_secret_hex"])
        self.chat = self.v["original_chat"]
        self.budget = self.v["budget"]
        self.reply = self.v["reply_text"]
        self.verification = self.v["verification"]
        self.envelope: dict[str, str] = self.v["envelope"]
        self.nonce = bytes.fromhex(self.envelope["nonce"])

    def test_independent_byte_vectors(self) -> None:
        reply = self.reply.encode("utf-8")
        self.assertEqual(reply.hex(), self.v["reply_utf8_hex"])
        budget_bytes = self.budget.to_bytes(4, "little")
        self.assertEqual(budget_bytes.hex(), self.v["budget_u32le_hex"])
        preimage = (
            b"vig/pickup/v1"
            + self.secret
            + frame(bytes.fromhex(self.v["messages_jcs_hex"]))
            + budget_bytes
            + frame(reply)
        )
        self.assertEqual(preimage.hex(), self.v["k_preimage_hex"])
        k = hashlib.sha256(preimage).digest()
        self.assertEqual(k.hex(), self.v["k_hex"])
        digest = hashlib.sha256(b"id" + k).digest()
        self.assertEqual(digest.hex(), self.v["pickup_id"])
        self.assertEqual(
            lookup_id(self.chat, self.budget, self.reply, self.secret), digest.hex()
        )
        prk = hmac.digest(bytes(32), k, "sha256")
        key = hmac.digest(prk, b"enc\x01", "sha256")
        self.assertEqual(key.hex(), self.v["encryption_key_hex"])
        aad = b"vig-pickup/1" + digest
        self.assertEqual(aad.hex(), self.v["aad_hex"])
        ciphertext = bytes.fromhex(self.envelope["ciphertext"])
        self.assertEqual(ciphertext[-16:].hex(), self.v["tag_hex"])
        plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad, self.nonce, key
        )
        self.assertEqual(plaintext.hex(), self.v["verification_jcs_hex"])
        self.assertEqual(json.loads(plaintext), self.verification)

    def test_seal_and_open_reference_envelope(self) -> None:
        with patch(
            "pickup.crypto.secrets.token_bytes", return_value=self.nonce
        ) as source:
            result = seal(
                self.verification, self.chat, self.budget, self.reply, self.secret
            )
        source.assert_called_once_with(24)
        self.assertEqual(result, (self.v["pickup_id"], self.envelope))
        self.assertEqual(
            open_pickup(self.envelope, self.secret, self.chat, self.budget, self.reply),
            self.verification,
        )

    def test_canonical_object_order_and_exact_text(self) -> None:
        def reverse_members(value: Any) -> Any:
            if isinstance(value, dict):
                return {k: reverse_members(v) for k, v in reversed(value.items())}
            if isinstance(value, list):
                return [reverse_members(item) for item in value]
            return value

        chat = reverse_members(self.chat)
        with patch("pickup.crypto.secrets.token_bytes", return_value=self.nonce):
            result = seal(
                reverse_members(self.verification),
                chat,
                self.budget,
                self.reply,
                self.secret,
            )
        self.assertEqual(result, (self.v["pickup_id"], self.envelope))
        ids = {
            lookup_id(self.chat, self.budget, text, self.secret)
            for text in ("é", "e\u0301", " é", "é\n")
        }
        self.assertEqual(len(ids), 4)

    def test_each_seal_requests_a_fresh_nonce_for_one_lookup_id(self) -> None:
        alternative = bytes(x ^ 255 for x in self.nonce)
        with patch(
            "pickup.crypto.secrets.token_bytes", side_effect=[self.nonce, alternative]
        ) as source:
            first_id, first = seal(
                self.verification, self.chat, self.budget, self.reply, self.secret
            )
            second_id, second = seal(
                self.verification, self.chat, self.budget, self.reply, self.secret
            )
        self.assertEqual(source.call_args_list, [call(24), call(24)])
        self.assertEqual(first_id, second_id)
        self.assertEqual(second["nonce"], alternative.hex())
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])
        self.assertEqual(
            open_pickup(second, self.secret, self.chat, self.budget, self.reply),
            self.verification,
        )

    def test_wrong_holder_material_and_changed_transcript(self) -> None:
        changed_secret = bytes([self.secret[0] ^ 1]) + self.secret[1:]
        changes = {
            "secret": (changed_secret, self.chat, self.budget, self.reply),
            "original_chat": (
                self.secret,
                [*self.chat, {"role": "user", "content": "?"}],
                self.budget,
                self.reply,
            ),
            "budget": (self.secret, self.chat, self.budget + 1, self.reply),
            "reply": (self.secret, self.chat, self.budget, self.reply + "\n"),
        }
        for field, (secret, chat, budget, reply) in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(
                    lookup_id(chat, budget, reply, secret), self.v["pickup_id"]
                )
                with self.assertRaises(PickupError):
                    open_pickup(self.envelope, secret, chat, budget, reply)

    def test_wrong_aad_has_a_valid_tag_for_only_that_aad(self) -> None:
        ciphertext = bytes.fromhex(self.v["wrong_aad_ciphertext_hex"])
        wrong_aad = bytes.fromhex(self.v["wrong_aad_hex"])
        self.assertNotEqual(wrong_aad.hex(), self.v["aad_hex"])
        plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext,
            wrong_aad,
            self.nonce,
            bytes.fromhex(self.v["encryption_key_hex"]),
        )
        self.assertEqual(plaintext.hex(), self.v["verification_jcs_hex"])
        with self.assertRaises(PickupError):
            open_pickup(
                {**self.envelope, "ciphertext": ciphertext.hex()},
                self.secret,
                self.chat,
                self.budget,
                self.reply,
            )

    def test_wire_shape_and_authenticated_bytes(self) -> None:
        ciphertext = self.envelope["ciphertext"]
        nonce = self.envelope["nonce"]

        def flip(value: str, index: int) -> str:
            data = bytearray.fromhex(value)
            data[index] ^= 1
            return data.hex()

        invalid: dict[str, Any] = {
            "unknown version": {**self.envelope, "version": "vig-pickup/2"},
            "non-object": list(self.envelope),
            **{
                f"missing {k}": {i: v for i, v in self.envelope.items() if i != k}
                for k in self.envelope
            },
        }
        for key, value in (("nonce", nonce), ("ciphertext", ciphertext)):
            for name, changed in (
                ("type", False),
                ("uppercase", value.upper()),
                ("odd hex", value[:-1]),
                ("nonhex", "x" + value[1:]),
                ("whitespace", value[:2] + " " + value[2:]),
                ("changed byte", flip(value, 0)),
            ):
                invalid[f"{key} {name}"] = {**self.envelope, key: changed}
        invalid["short nonce"] = {**self.envelope, "nonce": nonce[2:]}
        invalid["short tag"] = {**self.envelope, "ciphertext": "00" * 15}
        invalid["changed tag"] = {**self.envelope, "ciphertext": flip(ciphertext, -1)}
        for name, envelope in invalid.items():
            with self.subTest(case=name), self.assertRaises(PickupError):
                open_pickup(envelope, self.secret, self.chat, self.budget, self.reply)

    def test_additive_envelope_metadata_has_no_effect_on_plaintext(self) -> None:
        extended = {**self.envelope, "future_hint": "ignored"}
        self.assertEqual(
            open_pickup(extended, self.secret, self.chat, self.budget, self.reply),
            self.verification,
        )

    def test_verification_shape_and_canonical_plaintext(self) -> None:
        invalid = {
            "nonobject": [],
            "missing receipt": {
                k: v for k, v in self.verification.items() if k != "receipt"
            },
            "bad version": {**self.verification, "version": "vig/2"},
            "nonobject receipt": {**self.verification, "receipt": []},
            "nonarray prompt": {**self.verification, "prompt_token_ids": "0"},
            "boolean ID": {**self.verification, "reply_token_ids": [True]},
            "empty prompt": {**self.verification, "prompt_token_ids": []},
            "empty reply": {**self.verification, "reply_token_ids": []},
            "outside vocabulary": {**self.verification, "reply_token_ids": [202048]},
            "conflicting embedded ID": {**self.verification, "pickup_id": "00" * 32},
            "negative ID": {**self.verification, "reply_token_ids": [-1]},
            "non-uint32 ID": {**self.verification, "prompt_token_ids": [2**32]},
            "invalid pickup ID": {**self.verification, "pickup_id": "ff"},
        }
        for case, value in invalid.items():
            with self.subTest(case=case), self.assertRaises(PickupError):
                seal(value, self.chat, self.budget, self.reply, self.secret)

        original = bytes.fromhex(self.v["verification_jcs_hex"])
        inner_id = self.v["pickup_id"].encode("ascii")
        self.assertEqual(original.count(inner_id), 1)
        payloads = {
            "conflicting embedded ID": original.replace(inner_id, b"00" * 32),
            "noncanonical JSON": b" " + original,
            "duplicate member": b'{"version":"vig/1",' + original[1:],
            "invalid UTF-8": b"\xff",
            "invalid JSON": b"{",
            "wrong shape": b"[]",
        }
        for case, payload in payloads.items():
            encrypted = crypto_aead_xchacha20poly1305_ietf_encrypt(
                payload,
                bytes.fromhex(self.v["aad_hex"]),
                self.nonce,
                bytes.fromhex(self.v["encryption_key_hex"]),
            )
            with self.subTest(case=case), self.assertRaises(PickupError):
                open_pickup(
                    {**self.envelope, "ciphertext": encrypted.hex()},
                    self.secret,
                    self.chat,
                    self.budget,
                    self.reply,
                )

    def test_optional_pickup_id_and_model_token_bounds(self) -> None:
        value = {k: v for k, v in self.verification.items() if k != "pickup_id"}
        value.update(prompt_token_ids=[0], reply_token_ids=[202047])
        _, envelope = seal(value, self.chat, self.budget, self.reply, self.secret)
        self.assertEqual(
            open_pickup(envelope, self.secret, self.chat, self.budget, self.reply),
            value,
        )

    def test_jcs_sorts_nested_object_names_as_utf16(self) -> None:
        # U+10000 starts with the surrogate D800 in UTF-16, before U+E000.
        value = {**self.verification, "extension": {"\ue000": 1, "\U00010000": 2}}
        _, envelope = seal(value, self.chat, self.budget, self.reply, self.secret)
        plain = crypto_aead_xchacha20poly1305_ietf_decrypt(
            bytes.fromhex(envelope["ciphertext"]),
            bytes.fromhex(self.v["aad_hex"]),
            bytes.fromhex(envelope["nonce"]),
            bytes.fromhex(self.v["encryption_key_hex"]),
        )
        self.assertIn('"extension":{"\U00010000":2,"\ue000":1}'.encode(), plain)

    def test_holder_opt_in_and_reserved_namespace(self) -> None:
        self.assertEqual(parse_holder_secret(self.v["holder_user"]), self.secret)
        for ordinary in (None, "", "user@example.org"):
            self.assertIsNone(parse_holder_secret(ordinary))
        text = self.v["holder_secret_hex"]
        for reserved in (
            "vig-pickup/2:" + text,
            "vig-pickup/1",
            "vig-pickup/1:",
            "vig-pickup/1:" + text.upper(),
            "vig-pickup/1:" + text[2:],
            "vig-pickup/1:" + text + "00",
            "vig-pickup/1:" + text + "\n",
            "vig-pickup/1:" + "xx" + text[2:],
        ):
            with self.subTest(prefix=reserved[:13]), self.assertRaises(PickupError):
                parse_holder_secret(reserved)

    def test_invalid_derivation_inputs(self) -> None:
        bad: dict[str, tuple[Any, Any, Any, Any]] = {
            "chat not array": (
                {"messages": self.chat},
                self.budget,
                self.reply,
                self.secret,
            ),
            "reply not text": (self.chat, self.budget, b"bytes", self.secret),
            "secret text": (self.chat, self.budget, self.reply, self.secret.hex()),
            "short secret": (self.chat, self.budget, self.reply, self.secret[:-1]),
            "long secret": (self.chat, self.budget, self.reply, self.secret + b"\0"),
        }
        for budget in (False, True, 0, -1, 2**32, 1.5, "1"):
            bad[f"budget {budget!r}"] = (self.chat, budget, self.reply, self.secret)
        for case, args in bad.items():
            with self.subTest(case=case), self.assertRaises(PickupError):
                lookup_id(*args)
