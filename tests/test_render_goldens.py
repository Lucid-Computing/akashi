"""Check the shipped RFC-0002 reference corpus against the shared gateway renderer."""

import hashlib
import json
import os
import unicodedata
import unittest
from importlib import import_module
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "render-goldens"
ASSETS = {
    "tokenizer.json": "172c9eb4beafc72601690da3ccfcede5c2e6806a8d5ec1fca33e22acea8023a4",
    "tokenizer_config.json": "2c56f1b600f928762c235c1b7a9349dc50c3574031f396a35ab25d3ad3ca425d",
}


class RenderGoldens(unittest.TestCase):
    def test_corpus_integrity_and_coverage(self) -> None:
        manifest = json.loads((FIXTURES / "manifest.json").read_bytes())
        corpus = (FIXTURES / "chat.jsonl").read_bytes()
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["file"], "chat.jsonl")
        self.assertEqual(hashlib.sha256(corpus).hexdigest(), manifest["sha256"])
        self.assertEqual(manifest["cases"], 200)
        self.assertEqual(manifest["profile"], "llama4-chat/1")
        self.assertEqual(
            manifest["asset_repository"], "unsloth/Llama-4-Maverick-17B-128E-Instruct"
        )
        self.assertEqual(
            manifest["asset_revision"], "86c5ecb6f2fbddf604c60120125fb202e09f2556"
        )
        self.assertEqual(manifest["assets"], ASSETS)
        self.assertEqual(
            manifest["flashprove_revision"], "9e2bdd8ff5bf9c62f18263d7dac189b0400b260c"
        )
        for library, version in (
            ("transformers", "5.17.0"),
            ("tokenizers", "0.23.2"),
            ("Jinja2", "3.1.6"),
        ):
            self.assertEqual(manifest["reference"][library], version)

        cases = [json.loads(line) for line in corpus.splitlines()]
        self.assertEqual(len(cases), 200)
        self.assertEqual(len({case["id"] for case in cases}), 200)
        self.assertEqual(
            len({json.dumps(case["messages"], sort_keys=True) for case in cases}), 200
        )
        texts: list[str] = []
        multipart = False
        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertIsInstance(case["id"], str)
                self.assertIsInstance(case["reply_text"], str)
                self.assertTrue(case["prompt_ids"])
                self.assertTrue(case["reply_ids"])
                for token in (*case["prompt_ids"], *case["reply_ids"]):
                    self.assertIs(type(token), int)
                    self.assertTrue(0 <= token < 202048)
                for message in case["messages"]:
                    content = message["content"]
                    if isinstance(content, list):
                        multipart |= len(content) > 1
                        texts.append("".join(part["text"] for part in content))
                    else:
                        texts.append(content)
        self.assertIn("", texts)
        self.assertTrue(multipart, "expected a joined multipart message")
        self.assertTrue(any(text != text.strip() for text in texts))
        self.assertTrue(
            any(unicodedata.normalize("NFC", text) != text for text in texts)
        )
        self.assertTrue(
            any(unicodedata.normalize("NFD", text) != text for text in texts)
        )

    @unittest.skipUnless(
        os.environ.get("AKASHI_RENDER_ASSETS"),
        "set AKASHI_RENDER_ASSETS for the renderer gate",
    )
    def test_all_200_chat_and_reply_vectors(self) -> None:
        # CPU-only discovery can validate the corpus without the renderer's optional assets.
        renderer = import_module("gateway.renderer").ChatRenderer(
            Path(os.environ["AKASHI_RENDER_ASSETS"])
        )
        lines = (FIXTURES / "chat.jsonl").read_bytes().splitlines()
        self.assertEqual(len(lines), 200)
        for line in lines:
            case = json.loads(line)
            with self.subTest(case=case["id"]):
                actual = renderer.render(case["messages"])
                self.assertEqual(actual, tuple(case["prompt_ids"]))
                self.assertEqual(actual[0], 200000)
                self.assertEqual(actual.count(200000), 1)
                self.assertEqual(
                    renderer.decode(case["reply_ids"]).encode("utf-8"),
                    case["reply_text"].encode("utf-8"),
                )


if __name__ == "__main__":
    unittest.main()
