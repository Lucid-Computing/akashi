"""Local documentation fixtures exercise the same parser and paths as the release gate."""

from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.check_docs import check, main, repository_markdown


class DocsCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve() / "repo"
        self.root.mkdir()

    def file(self, name: str, body: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def issues(self) -> list[str]:
        return check(self.root, repository_markdown(self.root))

    def test_local_relative_rooted_escaped_and_reference_links(self) -> None:
        self.file("docs/spec/Topic (v1).md", "# Topic\n\n## What’s *new* in `v1`?\n")
        self.file("docs/images/file.svg", "<svg/>")
        self.file(
            "README.md",
            r"""[inline](docs/spec/Topic%20(v1).md#whats-new-in-v1)
[balanced](<docs/spec/Topic (v1).md#whats-new-in-v1> "current")
[escaped](docs/spec/Topic%20\(v1\).md#whats-new-in-v1)
[reference][topic]

[topic]: </docs/spec/Topic (v1).md#whats-new-in-v1>
![picture](docs/images/file.svg)
[web](https://example.invalid/missing#remote), [email](mailto:test@example.com).
""",
        )
        self.assertEqual(self.issues(), [])

    def test_fence_inline_code_and_comments_have_no_fake_targets_or_headings(
        self,
    ) -> None:
        self.file(
            "README.md",
            """# Actual

````markdown
# Hidden
[invalid](missing.md)
```
````

~~~md
[also invalid](missing2)
~~~

    [indented code](missing3)

`[inline code](missing4)`
<!-- [comment](missing5) -->
[real bad section](#hidden)
""",
        )
        issues = self.issues()
        self.assertEqual(len(issues), 1)
        self.assertIn("missing anchor: #hidden", issues[0])

    def test_unicode_sections_collision_suffixes_html_and_setext(self) -> None:
        self.file(
            "README.md",
            """# Élan — 東京_123!

## One
## One
## One-1
## One

Second `section`
----------------

<a id="custom-title"></a>
[unicode](#%C3%A9lan--%E6%9D%B1%E4%BA%AC_123) [first](#one) [second](#one-1)
[collision](#one-1-1) [third](#one-2) [setext](#second-section) [authored](#custom-title)
[bad](#one-3)
""",
        )
        self.assertEqual(len(self.issues()), 1)
        self.assertIn("missing anchor: #one-3", self.issues()[0])

    def test_parent_directory_or_symlink_cannot_leave_repository(self) -> None:
        (self.root.parent / "outside.md").write_text("# Private\n")
        (self.root / "escape.md").symlink_to(self.root.parent / "outside.md")
        doc = self.file(
            "docs/a.md",
            "[missing](missing.md) [outside](%2e%2e/%2e%2e/outside.md) [symbolic](../escape.md) [root](/gone.md)",
        )
        issues = check(self.root, [doc])
        self.assertEqual(len(issues), 4)
        self.assertEqual(sum("leaves the repository" in issue for issue in issues), 2)
        self.assertEqual(sum("missing target" in issue for issue in issues), 2)

    def test_source_line_fragments_and_rfc_required_sections(self) -> None:
        self.file("sample.py", "a\nb\nc\n")
        self.file(
            "docs/rfcs/RFC-9999-test.md",
            "# RFC\n\n## Summary\n\n[valid](../../sample.py#L2-L3) [invalid](../../sample.py#L3-L2)",
        )
        issues = self.issues()
        self.assertEqual(len(issues), 2)
        self.assertTrue(
            any("Motivation" in issue and "References" in issue for issue in issues)
        )
        self.assertTrue(
            any("missing anchor" in issue and "#L3-L2" in issue for issue in issues)
        )

    def test_cli_requires_both_corpus_entry_points_in_source_archive(self) -> None:
        with (
            patch("sys.argv", ["check_docs", "--root", str(self.root)]),
            contextlib.redirect_stdout(io.StringIO()) as report,
        ):
            self.assertEqual(main(), 1)
            self.assertIn(
                "SPEC.md: required corpus entry point is missing", report.getvalue()
            )
            self.assertIn(
                "docs/rfcs/README.md: required corpus entry point is missing",
                report.getvalue(),
            )
            self.file("SPEC.md", "# Specification\n")
            self.assertEqual(main(), 1)
            self.file("docs/rfcs/README.md", "# RFC index\n")
            self.assertEqual(main(), 0)

    def test_command_exit_tracks_actual_changes_and_honors_gitignore(self) -> None:
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        self.file("SPEC.md", "[Guide](docs/guide.md)\n")
        self.file("docs/rfcs/README.md", "# RFC index\n")
        self.file(".gitignore", "generated/\n")
        self.file("generated/output.md", "[bad](notfound)")
        self.file("README.md", "[section](docs/guide.md#usage)\n")
        self.file("docs/guide.md", "# Usage\n")
        self.assertEqual(
            {
                p.relative_to(self.root).as_posix()
                for p in repository_markdown(self.root)
            },
            {"README.md", "docs/guide.md", "SPEC.md", "docs/rfcs/README.md"},
        )
        with (
            patch("sys.argv", ["check_docs", "--root", str(self.root)]),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(main(), 0)
            self.file("docs/guide.md", "# New heading\n")
            self.assertEqual(main(), 1)
        self.assertIn("README.md:1: missing anchor", output.getvalue())


if __name__ == "__main__":
    unittest.main()
