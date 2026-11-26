"""Samples measured at the F37 asset revision, 86c5ecb6f2fbddf604c60120125fb202e09f2556.

The reference used the FlashProve vLLM lock (transformers 5.17.0, tokenizers
0.23.2, Jinja2 3.1.6). Load the two local files via AutoTokenizer.from_pretrained
with trust_remote_code=False. Join text parts without separators, call
apply_chat_template(tokenize=False, add_generation_prompt=True, tools=None,
date_string="26 Jul 2024"), then encode(add_special_tokens=False). Decode with
skip_special_tokens=False and clean_up_tokenization_spaces=False.
"""

import json
import os
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from gateway.renderer import (
    CHAT_PROFILE_DIGEST,
    RAW_PROFILE_DIGEST,
    ChatRenderer,
    raw_display,
    raw_ids,
)


class ProfileTests(unittest.TestCase):
    def test_profile_digests(self) -> None:
        self.assertEqual(
            CHAT_PROFILE_DIGEST,
            "207b541a4b5c22c90d8f9630411344c45e2a9a559ff755a2d64ca880181c94e3",
        )
        self.assertEqual(
            RAW_PROFILE_DIGEST,
            "71aba540e25cdccec27d83c08bbae1e5eeaa4c1dec4181e28913c8f60970f9fa",
        )

    def test_raw_identity(self) -> None:
        ids = [0, 200000, 200000, 202047]
        self.assertEqual(raw_ids(ids), tuple(ids))
        display: Callable[[object], object] = raw_display
        self.assertIsNone(display(ids))
        for invalid in ([], [-1], [202048], [True], [1.0], ["1"], b"abc"):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises((TypeError, ValueError)),
            ):
                raw_ids(invalid)

    def test_missing_assets(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaises((OSError, ValueError)),
        ):
            ChatRenderer(Path(directory))


@unittest.skipUnless(
    os.environ.get("AKASHI_RENDER_ASSETS"),
    "set AKASHI_RENDER_ASSETS to the pinned tokenizer directory",
)
class ChatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.assets = Path(os.environ["AKASHI_RENDER_ASSETS"])
        cls.renderer = ChatRenderer(cls.assets)

    assets: Path
    renderer: ChatRenderer

    def test_unknown_profile(self) -> None:
        with self.assertRaises(ValueError):
            ChatRenderer(self.assets, expected_digest=RAW_PROFILE_DIGEST)

    def test_reference_vectors(self) -> None:
        sample = json.loads(
            (Path(__file__).parent / "fixtures" / "renderer-sample.json").read_text(
                encoding="utf-8"
            )
        )
        for case in sample["chat"]:
            with self.subTest(name=case["name"]):
                actual = self.renderer.render(case["messages"])
                self.assertEqual(actual, tuple(case["ids"]))
                self.assertEqual(actual[0], 200000)
                self.assertEqual(actual.count(200000), 1)
        for case in sample["decode"]:
            with self.subTest(ids=case["ids"]):
                self.assertEqual(self.renderer.decode(case["ids"]), case["text"])

    def test_rejects_extra_bos(self) -> None:
        with self.assertRaises(ValueError):
            self.renderer.render(
                [{"role": "user", "content": "embedded <|begin_of_text|>"}]
            )

    def test_malformed_messages(self) -> None:
        for messages in (
            [],
            [{"role": "system", "content": "alone"}],
            [
                {"role": "user", "content": "hello"},
                {"role": "system", "content": "late"},
            ],
            [{"role": "tool", "content": "unsupported"}],
            [{"role": "user", "content": "hello", "name": "extra"}],
            [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "allowed"},
                        {"type": "image_url", "image_url": "example"},
                    ],
                }
            ],
            [{"role": "user", "content": [{"type": "text"}]}],
            [{"role": "user", "content": [{"type": "text", "text": True}]}],
            [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "ok", "hidden": True}],
                }
            ],
        ):
            with self.subTest(messages=messages), self.assertRaises(ValueError):
                self.renderer.render(messages)

    def test_changed_bytes_fail_closed(self) -> None:
        names = ("tokenizer.json", "tokenizer_config.json")
        for changed in names:
            with (
                self.subTest(changed=changed),
                tempfile.TemporaryDirectory() as directory,
            ):
                for name in names:
                    destination = Path(directory, name)
                    if name == changed:
                        destination.write_bytes(
                            (self.assets / name).read_bytes() + b" "
                        )
                    else:
                        destination.symlink_to((self.assets / name).resolve())
                with self.assertRaises(ValueError):
                    ChatRenderer(Path(directory))
