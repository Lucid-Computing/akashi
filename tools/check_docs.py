"""Check repository documentation links, heading anchors and the accepted RFC outline."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

from markdown_it import MarkdownIt

_RFC_SECTIONS = (
    "Summary",
    "Motivation",
    "Goals",
    "Non-Goals",
    "Proposed Design",
    "Alternatives Considered",
    "Drawbacks",
    "Migration / Rollout",
    "Testing Strategy",
    "Open Questions",
    "References",
)
_MARKDOWN = MarkdownIt("commonmark", {"inline_definitions": True}).enable(
    ["table", "strikethrough"]
)


@dataclass
class Page:
    anchors: set[str] = field(default_factory=set)
    links: list[tuple[int, str]] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)


class _Html(HTMLParser):
    def __init__(self, page: Page, line: int) -> None:
        super().__init__()
        self.page, self.line = page, line

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if value is None:
                continue
            if key == "id" or (tag == "a" and key == "name"):
                self.page.anchors.add(value)
            if (tag, key) in (("a", "href"), ("img", "src")):
                self.page.links.append((self.line + self.getpos()[0] - 1, value))


def _slug(title: str, used: set[str]) -> str:
    # GitHub preserves spaces as hyphens, including consecutive spaces,
    # connector punctuation, letters, marks and decimal/letter numbers.
    base = "".join(
        "-" if c == " " else c
        for c in title.lower()
        if c in " -"
        or unicodedata.category(c)[0] in "LM"
        or unicodedata.category(c) in ("Pc", "Nd", "Nl")
    )
    value, suffix = base, 0
    while value in used:
        suffix += 1
        value = f"{base}-{suffix}"
    used.add(value)
    return value


def _parse(path: Path) -> Page:
    page = Page()
    used: set[str] = set()
    heading_level: str | None = None
    for token in _MARKDOWN.parse(path.read_text(encoding="utf-8")):
        line = (token.map or [0])[0] + 1
        if token.type == "heading_open":
            heading_level = token.tag
        elif token.type == "heading_close":
            heading_level = None
        elif token.type == "definition":
            page.links.append((line, token.meta["url"]))
        elif token.type == "html_block":
            _Html(page, line).feed(token.content)
        elif token.type == "inline":
            children = token.children or []
            if heading_level:
                title = "".join(
                    child.content
                    for child in children
                    if child.type in ("text", "code_inline")
                )
                page.anchors.add(_slug(title, used))
                if heading_level == "h2":
                    page.sections.append(title)
            for child in children:
                if child.type in ("image", "link_open"):
                    value = child.attrGet("src" if child.type == "image" else "href")
                    if isinstance(value, str):
                        page.links.append((line, value))
                elif child.type == "html_inline":
                    _Html(page, line).feed(child.content)
    return page


def repository_markdown(root: Path) -> list[Path]:
    if (root / ".git").exists():
        paths = subprocess.check_output(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                "*.md",
            ],
            cwd=root,
        )
        return [root / os.fsdecode(name) for name in paths.split(b"\x00") if name]
    # Source archives do not carry a Git index or worktree metadata.
    documents: list[Path] = []
    for parent, dirs, names in os.walk(root):
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".")
            and d not in {"node_modules", "venv", "build", "dist", "target"}
        ]
        documents.extend(Path(parent) / name for name in names if name.endswith(".md"))
    return sorted(documents)


def check(root: Path, documents: Iterable[Path]) -> list[str]:
    """Return diagnostics with repository-relative paths and Markdown block line numbers."""
    original = root.absolute()
    root = original.resolve()
    issues = []
    page_for = cache(_parse)
    for entry in documents:
        relative = entry.relative_to(original) if entry.is_absolute() else entry
        source = root / relative
        if not source.is_file() or not source.resolve().is_relative_to(root):
            issues.append(f"{relative}: missing or external documentation source")
            continue
        try:
            page = page_for(source.resolve())
        except (UnicodeError, OSError):
            issues.append(f"{relative}: unreadable UTF-8 Markdown source")
            continue
        if (
            relative.parent == Path("docs/rfcs")
            and source.match("RFC-*.md")
            and tuple(page.sections) != _RFC_SECTIONS
        ):
            missing = ", ".join(
                title for title in _RFC_SECTIONS if title not in page.sections
            )
            issues.append(
                f"{relative}: invalid RFC section order or content"
                + (f" (missing {missing})" if missing else "")
            )
        for line, href in dict.fromkeys(page.links):
            try:
                url = urlsplit(href)
                if url.scheme or url.netloc:
                    continue
                path = unquote(url.path, errors="strict")
                fragment = unquote(url.fragment, errors="strict")
                target = (
                    root / path.lstrip("/")
                    if path.startswith("/")
                    else source.parent / path
                    if path
                    else source
                ).resolve()
                if not target.is_relative_to(root):
                    reason = "path leaves the repository"
                elif not target.exists():
                    reason = "missing target"
                elif not fragment:
                    continue
                else:
                    if target.is_dir():
                        target = (target / "README.md").resolve()
                        if not target.is_relative_to(root):
                            raise ValueError("External directory README")
                    if target.suffix.lower() == ".md" and target.is_file():
                        if fragment in page_for(target).anchors:
                            continue
                    elif target.is_file() and (
                        bounds := re.fullmatch(
                            r"L([1-9][0-9]*)(?:-L([1-9][0-9]*))?", fragment
                        )
                    ):
                        with target.open("rb") as f:
                            if (
                                1
                                <= int(bounds[1])
                                <= int(bounds[2] or bounds[1])
                                <= sum(1 for _ in f)
                            ):
                                continue
                    reason = "missing anchor"
            except (UnicodeError, ValueError, RuntimeError, OSError):
                reason = "invalid target"
            issues.append(f"{relative}:{line}: {reason}: {href}")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    root = parser.parse_args().root.resolve()
    documents = repository_markdown(root)
    issues = check(root, documents)
    for entry in ("SPEC.md", "docs/rfcs/README.md"):
        if not (root / entry).is_file():
            issues.append(f"{entry}: required corpus entry point is missing")
    for issue in issues:
        print(issue)
    print(f"Checked {len(documents)} Markdown files with {len(issues)} errors.")
    return int(bool(issues))


if __name__ == "__main__":
    raise SystemExit(main())
