"""Shared llama4-chat/1 and raw-ids/1 rendering profiles from RFC-0002."""

import hashlib
import json
from pathlib import Path

from jinja2 import StrictUndefined
from jinja2.sandbox import ImmutableSandboxedEnvironment
from tokenizers import Tokenizer

# F37, unsloth/Llama-4-Maverick-17B-128E-Instruct@86c5ecb6f2fbddf604c60120125fb202e09f2556.
_TOKENIZER_SHA = "172c9eb4beafc72601690da3ccfcede5c2e6806a8d5ec1fca33e22acea8023a4"
_CONFIG_SHA = "2c56f1b600f928762c235c1b7a9349dc50c3574031f396a35ab25d3ad3ca425d"
CHAT_PROFILE_DIGEST = hashlib.sha256(
    b"llama4-chat/1" + bytes.fromhex(_TOKENIZER_SHA) + bytes.fromhex(_CONFIG_SHA)
).hexdigest()
RAW_PROFILE_DIGEST = hashlib.sha256(b"raw-ids/1").hexdigest()


def _asset(path: Path, expected_digest: str) -> bytes:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ValueError(f"{path.name} differs from the pinned rendering asset")
    return data


def _ids(value: object) -> tuple[int, ...]:
    if not isinstance(value, (tuple, list)):
        raise TypeError("token IDs must be an array")
    ids = tuple(value)
    if any(type(token) is not int or not 0 <= token < 202048 for token in ids):
        raise ValueError("invalid token ID for the pinned vocabulary")
    return ids


def raw_ids(token_ids: object) -> tuple[int, ...]:
    """Preserve the supplied raw prompt and its token boundaries."""
    ids = _ids(token_ids)
    if not ids:
        raise ValueError("raw prompt must contain at least one token")
    return ids


def raw_display(token_ids: object) -> None:
    """Raw IDs have null display text in the holder bundle."""
    raw_ids(token_ids)


def _content(value: object) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, list):
        parts = []
        for part in value:
            if (
                not isinstance(part, dict)
                or part.keys() != {"type", "text"}
                or part["type"] != "text"
                or not isinstance(part["text"], str)
            ):
                raise ValueError("expected a text content part")
            parts.append(part["text"])
        text = "".join(parts)
    else:
        raise TypeError("expected text or a list of text parts")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("message content contains invalid Unicode") from None
    return text


class ChatRenderer:
    """A tokenizer and template initialized once from the same bytes that passed hashing."""

    def __init__(
        self, asset_dir: Path, *, expected_digest: str = CHAT_PROFILE_DIGEST
    ) -> None:
        if expected_digest != CHAT_PROFILE_DIGEST:
            raise ValueError("unsupported chat profile digest")
        data = _asset(asset_dir / "tokenizer.json", _TOKENIZER_SHA)
        config = json.loads(_asset(asset_dir / "tokenizer_config.json", _CONFIG_SHA))
        self._tokenizer = Tokenizer.from_buffer(data)
        environment = ImmutableSandboxedEnvironment(
            trim_blocks=True, lstrip_blocks=True, undefined=StrictUndefined
        )
        environment.globals.clear()
        self._template = environment.from_string(config["chat_template"])
        self._bos: str = config["bos_token"]

    def render(self, messages: object) -> tuple[int, ...]:
        """Return chat IDs with one BOS. A literal BOS in message content fails closed."""
        if not isinstance(messages, (list, tuple)) or not messages:
            raise ValueError("expected at least one message")
        chat = []
        for i, message in enumerate(messages):
            if not isinstance(message, dict) or message.keys() != {"role", "content"}:
                raise ValueError("invalid message fields")
            role = message["role"]
            if role not in ("system", "user", "assistant") or (
                i != 0 and role == "system"
            ):
                raise ValueError("unsupported message role or misplaced system message")
            chat.append({"role": role, "content": _content(message["content"])})
        if chat[-1]["role"] == "system":
            raise ValueError(
                "expected a user or assistant message after the system message"
            )
        formatted = self._template.render(
            messages=chat,
            bos_token=self._bos,
            add_generation_prompt=True,
            date_string="26 Jul 2024",
            tools=None,
        )
        ids = tuple(self._tokenizer.encode(formatted, add_special_tokens=False).ids)
        if not ids or ids[0] != 200000 or ids.count(200000) != 1:
            raise ValueError("chat must contain exactly one leading BOS")
        return ids

    def decode(self, token_ids: object) -> str:
        """Decode with the pinned tokenizer's decoder and retain special tokens."""
        return self._tokenizer.decode(list(_ids(token_ids)), skip_special_tokens=False)
