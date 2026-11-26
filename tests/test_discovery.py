"""WSGI discovery contracts from specs/gateway-api.md and RFC-0003."""

import json
import unittest
from typing import Any
from unittest.mock import Mock
from wsgiref.util import setup_testing_defaults

from gateway.discovery import DiscoveryApp, ServiceConfig

MODEL = "fixture-int-model"
CONFIG: dict[str, Any] = {
    "model": MODEL,
    "owned_by": "discovery-fixture",
    "created": 42,
    "log_id": "ab" * 32,
    "log_key_id": "log-test-01",
    "log_public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "auditor_key_id": "audit-test-02",
    "auditor_public_key": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "log_url": "https://log.example.org/log/v1/",
    "challenge_url": "https://audit.example.org/audit/v1/challenges",
    "audit_url": "https://audit.example.org/audit/v1/",
    "pickup_url": "https://pickup.example.org/receipts/v1/pickup/",
    "max_tokens_cap": 64,
}
REVISION = "86c5ecb6f2fbddf604c60120125fb202e09f2556"
ASSETS = f"https://huggingface.co/unsloth/Llama-4-Maverick-17B-128E-Instruct/resolve/{REVISION}/"


class DiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = ServiceConfig(**CONFIG)
        self.app = DiscoveryApp(self.config)

    def request(
        self, path: str, method: str = "GET"
    ) -> tuple[int, dict[str, str], dict[str, Any]]:
        environ: dict[str, Any] = {}
        setup_testing_defaults(environ)
        environ.update(
            REQUEST_METHOD=method,
            PATH_INFO=path,
            HTTP_AUTHORIZATION="Bearer private-token-canary",
            HTTP_COOKIE="session=private-cookie-canary",
            HTTP_HOST="private-host-canary",
        )
        start = Mock()
        body = b"".join(self.app(environ, start))
        self.assertEqual(start.call_count, 1)
        status, headers = start.call_args.args[:2]
        header_map = {k.lower(): v for k, v in headers}
        status_code = int(status.split()[0])
        self.assertNotIn(b"private-", body)
        if status_code == 200:
            self.assertEqual(
                header_map["content-type"].split(";")[0], "application/json"
            )
            return status_code, header_map, json.loads(body)
        return status_code, header_map, {}

    def test_model_list_and_descriptor_agree(self) -> None:
        status, _, listing = self.request("/v1/models")
        self.assertEqual(status, 200)
        self.assertEqual(listing["object"], "list")
        self.assertEqual(len(listing["data"]), 1)
        model = listing["data"][0]
        self.assertEqual(
            (model["id"], model["object"], model["created"], model["owned_by"]),
            (MODEL, "model", 42, CONFIG["owned_by"]),
        )
        status, _, descriptor = self.request("/.well-known/akashi.json")
        self.assertEqual(status, 200)
        self.assertEqual(descriptor["version"], "akashi/1")
        self.assertEqual(descriptor["model"], model["id"])
        self.assertEqual(
            descriptor["commitment_id"],
            "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46",
        )
        self.assertEqual(descriptor["max_tokens_cap"], 64)
        self.assertEqual(descriptor["window"], 1024)
        self.assertEqual(model["max_tokens_cap"], descriptor["max_tokens_cap"])
        self.assertEqual(model["window"], descriptor["window"])
        self.assertEqual(descriptor["end_tokens"], [200001, 200007, 200008])
        self.assertEqual(descriptor["sampling_rate"], {"live": 20, "shadow": 1000})

    def test_profiles_have_immutable_asset_pins(self) -> None:
        _, _, d = self.request("/.well-known/akashi.json")
        chat = {
            "profile": "llama4-chat/1",
            "digest": "207b541a4b5c22c90d8f9630411344c45e2a9a559ff755a2d64ca880181c94e3",
            "tokenizer_json_url": ASSETS + "tokenizer.json",
            "tokenizer_config_url": ASSETS + "tokenizer_config.json",
            "tokenizer_json_sha256": "172c9eb4beafc72601690da3ccfcede5c2e6806a8d5ec1fca33e22acea8023a4",
            "tokenizer_config_sha256": "2c56f1b600f928762c235c1b7a9349dc50c3574031f396a35ab25d3ad3ca425d",
        }
        self.assertEqual(d["render_profile"], chat)
        self.assertCountEqual(
            d["render_profiles"],
            [
                chat,
                {
                    "profile": "raw-ids/1",
                    "digest": "71aba540e25cdccec27d83c08bbae1e5eeaa4c1dec4181e28913c8f60970f9fa",
                },
            ],
        )

    def test_public_verification_identities_and_endpoints(self) -> None:
        _, _, d = self.request("/.well-known/akashi.json")
        self.assertEqual(
            d["log"],
            {
                "log_id": CONFIG["log_id"],
                "log_key_id": CONFIG["log_key_id"],
                "log_public_key": CONFIG["log_public_key"],
                "url": CONFIG["log_url"],
            },
        )
        for name in (
            "auditor_key_id",
            "auditor_public_key",
            "pickup_url",
            "challenge_url",
            "audit_url",
        ):
            self.assertEqual(d[name], CONFIG[name])
        self.assertEqual(d["beacon"]["chain"], "quicknet")
        self.assertEqual(
            d["beacon"]["chain_hash"],
            "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        )
        self.assertEqual(d["beacon"]["url"], "https://api.drand.sh")

    def test_unknown_routes_and_methods(self) -> None:
        self.assertEqual(self.request("/v1/models-typo")[0], 404)
        self.assertEqual(self.request("/.well-known/other")[0], 404)
        status, headers, _ = self.request("/v1/models", "POST")
        self.assertEqual(status, 405)
        self.assertEqual(headers["allow"], "GET")

    def test_config_fails_closed(self) -> None:
        incomplete = CONFIG.copy()
        del incomplete["auditor_public_key"]
        with self.assertRaises((TypeError, ValueError)):
            ServiceConfig(**incomplete)
        for field, value in (
            ("max_tokens_cap", True),
            ("max_tokens_cap", 257),
            ("log_id", "00"),
            ("log_public_key", "GG" * 32),
            ("auditor_key_id", ""),
            ("model", ""),
            ("log_url", "http://example.org/"),
            ("audit_url", "https://account:private-token-canary@example.org"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValueError) as raised:
                    ServiceConfig(**(CONFIG | {field: value}))
                self.assertNotIn("private-token-canary", str(raised.exception))

    def test_admission_receives_advertised_settings(self) -> None:
        _, _, descriptor = self.request("/.well-known/akashi.json")
        policy = Mock()
        auth = Mock()
        body = b'{"prompt":[20]}'
        self.assertIs(
            self.config.admit(
                policy, body, "raw", authorization="Bearer t", authenticate=auth
            ),
            policy.return_value,
        )
        self.assertEqual(policy.call_args.kwargs["model"], descriptor["model"])
        self.assertEqual(
            policy.call_args.kwargs["max_tokens_cap"], descriptor["max_tokens_cap"]
        )
        self.assertIs(policy.call_args.kwargs["authenticate"], auth)
