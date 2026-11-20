"""Regenerate with Python 3.13.18, transformers 5.17.0, tokenizers 0.23.2, Jinja2 3.1.6.

Run python regenerate.py ASSET_DIR OUTPUT.jsonl. The host supplies the two
pinned assets. messages and reply_ids are the independent test inputs.
"""

import hashlib
import importlib
import json
import sys
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory


def main(assets: Path, output: Path) -> None:
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for package in ("transformers", "tokenizers", "Jinja2"):
        if version(package) != manifest["reference"][package]:
            raise ValueError(f"reference version mismatch for {package}")
    with TemporaryDirectory() as clean:
        for name, expected in manifest["assets"].items():
            data = (assets / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError(f"asset mismatch for {name}")
            Path(clean, name).write_bytes(data)
        tokenizer = importlib.import_module(
            "transformers"
        ).AutoTokenizer.from_pretrained(
            clean, local_files_only=True, trust_remote_code=False
        )

        lines = []
        for line in (root / "chat.jsonl").read_bytes().splitlines():
            case = json.loads(line)
            messages = []
            for message in case["messages"]:
                content = message["content"]
                if isinstance(content, list):
                    if any(
                        set(p) != {"type", "text"} or p["type"] != "text"
                        for p in content
                    ):
                        raise ValueError(f"invalid multipart fixture in {case['id']}")
                    content = "".join(p["text"] for p in content)
                messages.append({"role": message["role"], "content": content})
            rendered = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                tools=None,
                date_string="26 Jul 2024",
            )
            case["prompt_ids"] = tokenizer.encode(rendered, add_special_tokens=False)
            case["reply_text"] = tokenizer.decode(
                case["reply_ids"],
                skip_special_tokens=False,
                clean_up_tokenization_spaces=False,
            )
            lines.append(json.dumps(case, ensure_ascii=True, separators=(",", ":")))
    output.write_bytes(("\n".join(lines) + "\n").encode("ascii"))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(Path(sys.argv[1]), Path(sys.argv[2]))
