from __future__ import annotations

import datetime as dt
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "lint_docs.py"
SPEC = importlib.util.spec_from_file_location("lint_docs", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
lint_docs = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lint_docs
SPEC.loader.exec_module(lint_docs)


class RepositoryFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write(self, relative_path: str, content: str) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def lint(self, *, today: dt.date = dt.date(2026, 8, 27)):
        diagnostics, _ = lint_docs.lint_repository(self.root, today=today)
        return diagnostics

    def codes(self) -> list[str]:
        return [diagnostic.code for diagnostic in self.lint()]


class LinkTests(RepositoryFixture):
    def test_recursive_links_fragments_decoding_routes_and_duplicate_headings(self) -> None:
        self.write(
            "README.md",
            "\n".join(
                [
                    "# Home",
                    "[nested](docs/a/entry.md#repeat-1)",
                    "[decoded](docs/space%20name.md#cafe)",
                    "[root route](/guide/start#intro)",
                    "[route html](/guide/start.html#intro)",
                    "[route directory](/en/#english)",
                    "[pure](#home)",
                    "[title](docs/a/entry.md \"Entry title\")",
                    "[parentheses](https://example.test/api(value))",
                ]
            ),
        )
        self.write("docs/a/entry.md", "# Repeat\n\n## Repeat\n")
        self.write("docs/space name.md", "# Café\n")
        self.write("site/guide/start.md", "# Intro\n")
        self.write("site/en/index.md", "# English\n")

        self.assertEqual(self.lint(), [])

    def test_reports_missing_files_anchors_and_repo_escape(self) -> None:
        self.write(
            "README.md",
            "# Home\n[missing](missing.md)\n[anchor](#absent)\n[escape](../secret.md)\n",
        )

        diagnostics = self.lint()

        self.assertEqual(
            [(item.line, item.code) for item in diagnostics],
            [(2, "LINK001"), (3, "LINK002"), (4, "LINK001")],
        )
        self.assertIn("escapes repository root", diagnostics[-1].message)

    def test_ignores_external_mailto_images_fenced_and_inline_code(self) -> None:
        self.write(
            "README.md",
            """# Home
[web](https://example.test/nope) [mail](mailto:docs@example.test)
![missing image](missing.png)
`[inline](missing.md)`
```md
[fenced](missing.md)
```
""",
        )

        self.assertEqual(self.lint(), [])

    def test_heading_slug_matches_vitepress_punctuation_unicode_and_duplicates(self) -> None:
        self.write(
            "README.md",
            """# Start
[one](docs/headings.md#_1-cafe-api)
[two](docs/headings.md#_1-cafe-api-1)
[custom](docs/headings.md#chosen)
[entity](docs/headings.md#a-amp-b)
[underscore](docs/headings.md#snake-case)
""",
        )
        self.write(
            "docs/headings.md",
            """## 1. Café / API
## 1. Café / API
## Any title {#chosen}
## A &amp; B
## snake_case
""",
        )

        self.assertEqual(self.lint(), [])

    def test_symlinked_markdown_cannot_escape_repository(self) -> None:
        outside = self.root.parent / f"{self.root.name}-outside.md"
        outside.write_text("# Secret\n", encoding="utf-8")
        try:
            try:
                (self.root / "escape.md").symlink_to(outside)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            self.assertEqual(self.codes(), ["DOC002"])
        finally:
            outside.unlink(missing_ok=True)

    def test_frontmatter_is_not_treated_as_a_setext_heading(self) -> None:
        self.write(
            "README.md",
            "---\ntitle: Phantom\n---\n\n# Actual\n[bad](#title-phantom)\n",
        )

        self.assertEqual(self.codes(), ["LINK002"])

    def test_vitepress_directory_route_does_not_fall_back_to_sibling_markdown(self) -> None:
        self.write("README.md", "[route](/guide/)\n")
        self.write("site/guide.md", "# Wrong target\n")

        self.assertEqual(self.codes(), ["LINK001"])

    def test_reference_style_links_resolve_full_collapsed_and_shortcut_labels(self) -> None:
        self.write(
            "README.md",
            """[full reference][Target Page]
[collapsed][]
[shortcut]
![ignored image][missing image]

[target   page]:
  docs/existing.md#answer
[collapsed]: docs/missing-collapsed.md
[shortcut]: <docs/missing shortcut.md> "title"
[missing image]: images/missing.png
""",
        )
        self.write("docs/existing.md", "# Answer\n")

        diagnostics = self.lint()

        self.assertEqual(
            [(item.line, item.code) for item in diagnostics],
            [(2, "LINK001"), (3, "LINK001")],
        )
        self.assertIn("missing-collapsed.md", diagnostics[0].message)
        self.assertIn("missing shortcut.md", diagnostics[1].message)

    def test_multiline_inline_links_and_reference_labels_are_checked(self) -> None:
        self.write(
            "README.md",
            """[existing
page](
  docs/existing.md#answer
)
[missing](
  docs/missing-inline.md
)
[reference][multi
line]

[multi line]: docs/missing-reference.md
""",
        )
        self.write("docs/existing.md", "# Answer\n")

        diagnostics = self.lint()

        self.assertEqual(
            [(item.line, item.code) for item in diagnostics],
            [(5, "LINK001"), (8, "LINK001")],
        )


class ResearchDateTests(RepositoryFixture):
    def test_accepts_nonfuture_iso_date_with_english_or_chinese_snapshot_wording(self) -> None:
        self.write(
            "docs/research/en.md",
            "# Research\n\nSource snapshot date: 2026-08-26.\n\n[Source](https://example.test)\n",
        )
        self.write(
            "docs/research/zh.md",
            "# 研究\n\n> 调研快照：2026-08-27。\n\n[来源](https://example.test)\n",
        )

        self.assertEqual(self.lint(), [])

    def test_requires_date_only_when_research_page_has_external_url(self) -> None:
        self.write("docs/research/local.md", "# Local\n\n[Read](../guide.md)\n")
        self.write("docs/guide.md", "# Read\n")
        self.write("docs/research/external.md", "# External\n\n[Web](https://example.test)\n")

        diagnostics = self.lint()

        self.assertEqual([(item.path, item.code) for item in diagnostics], [("docs/research/external.md", "DATE001")])

    def test_rejects_late_invalid_and_future_dates(self) -> None:
        late_lines = ["# Late"] + [f"line {index}" for index in range(1, 10)]
        late_lines += ["Source date: 2026-08-26", "[Web](https://example.test)"]
        self.write("docs/research/late.md", "\n".join(late_lines))
        self.write(
            "docs/research/invalid.md",
            "# Invalid\nSource date: 2026-02-30\n[Web](https://example.test)\n",
        )
        self.write(
            "docs/research/future.md",
            "# Future\nResearch date: 2026-08-28\n[Web](https://example.test)\n",
        )

        diagnostics = self.lint()

        self.assertEqual(
            {(item.path, item.code) for item in diagnostics},
            {
                ("docs/research/late.md", "DATE001"),
                ("docs/research/invalid.md", "DATE002"),
                ("docs/research/future.md", "DATE002"),
            },
        )

    def test_date_inside_code_does_not_satisfy_the_research_rule(self) -> None:
        self.write(
            "docs/research/code.md",
            "# Code\n`Source date: 2026-08-26`\n[Web](https://example.test)\n",
        )

        self.assertEqual(self.codes(), ["DATE001"])

    def test_fenced_lines_still_count_toward_the_first_ten_nonblank_lines(self) -> None:
        content = ["# Research", "```text"]
        content.extend(f"code {index}" for index in range(7))
        content.extend(
            [
                "```",
                "Source date: 2026-08-26",
                "[Web](https://example.test)",
            ]
        )
        self.write("docs/research/late-after-code.md", "\n".join(content))

        self.assertEqual(self.codes(), ["DATE001"])


class SafetyClaimTests(RepositoryFixture):
    def test_flags_exact_english_and_chinese_phrases_in_public_docs(self) -> None:
        self.write(
            "README.md",
            "It reports exact disk usage and will free space.\n"
            "This cache is unused and safe to delete.\n",
        )
        self.write(
            "site/claims.md",
            "这就是精确磁盘占用，一定释放空间，且可安全删除。\n",
        )
        self.write(
            "skills/example/SKILL.md",
            "Trash is guaranteed recoverable; erase is guaranteed unrecoverable.\n"
            "回收站保证可恢复，永久删除保证不可恢复。\n",
        )

        diagnostics = self.lint()

        self.assertEqual(len([item for item in diagnostics if item.code == "CLAIM001"]), 11)

    def test_same_sentence_negation_allows_claim_but_other_sentence_still_fails(self) -> None:
        self.write(
            "README.md",
            "It does not report exact disk usage. It will free space.\n"
            "SweepX never labels data unused or safe to delete.\n"
            "这不是精确磁盘占用，也不保证可恢复。\n",
        )

        diagnostics = self.lint()

        claims = [item for item in diagnostics if item.code == "CLAIM001"]
        self.assertEqual(len(claims), 1)
        self.assertIn("will free", claims[0].message)

    def test_unrelated_negation_in_same_sentence_does_not_suppress_claim(self) -> None:
        self.write(
            "README.md",
            "This does not estimate capacity, but this cache is safe to delete.\n"
            "This does not estimate capacity and this cache is unused.\n"
            "这不估算容量，而且这个缓存可安全删除。\n",
        )

        diagnostics = self.lint()

        self.assertEqual(
            [(item.line, item.code) for item in diagnostics],
            [(1, "CLAIM001"), (2, "CLAIM001"), (3, "CLAIM001")],
        )
        self.assertIn("safe to delete", diagnostics[0].message)

    def test_negation_can_scope_a_coordinated_reporting_claim(self) -> None:
        self.write(
            "README.md",
            "Never convert a plan, infer authority, or describe deletion as guaranteed unrecoverable.\n"
            "不是把目录年龄或名字当作可安全删除的证明。\n",
        )

        self.assertEqual(self.lint(), [])

    def test_later_same_sentence_negation_applies_without_crossing_sentence_boundary(self) -> None:
        self.write(
            "README.md",
            "Exact disk usage is not promised. This will free space, with no guarantee.\n",
        )

        self.assertEqual(self.lint(), [])

    def test_reasoned_suppression_applies_to_one_following_prose_line(self) -> None:
        self.write(
            "README.md",
            """<!-- docs-lint: allow-next-line safety-claim -- Quoting a vendor promise for analysis. -->
The vendor says it will free space.

This feature will free space.
""",
        )

        diagnostics = self.lint()

        self.assertEqual([(item.line, item.code) for item in diagnostics], [(4, "CLAIM001")])

    def test_rejects_empty_or_malformed_suppression(self) -> None:
        self.write(
            "README.md",
            """<!-- docs-lint: allow-next-line safety-claim --  -->
This will free space.
<!-- docs-lint: allow-next-line safety-claim -->
This is safe to delete.
""",
        )

        diagnostics = self.lint()

        self.assertEqual(
            [(item.line, item.code) for item in diagnostics],
            [(1, "CLAIM002"), (2, "CLAIM001"), (3, "CLAIM002"), (4, "CLAIM001")],
        )

    def test_suppression_token_inside_inline_or_fenced_code_is_not_a_directive(self) -> None:
        self.write(
            "README.md",
            """`<!-- docs-lint: allow-next-line safety-claim -- example -->`
This will free space.
```md
<!-- docs-lint: allow-next-line safety-claim -- example -->
```
This is safe to delete.
""",
        )

        self.assertEqual(
            [(item.line, item.code) for item in self.lint()],
            [(2, "CLAIM001"), (6, "CLAIM001")],
        )

    def test_ignores_claims_outside_public_scope_and_inside_code_or_images(self) -> None:
        self.write(
            "docs/design.md",
            "It will free space and is safe to delete.\n",
        )
        self.write(
            "README.md",
            "`will free`\n\n![safe to delete](image.png)\n\n```text\nunused\n```\n",
        )

        self.assertEqual(self.lint(), [])


if __name__ == "__main__":
    unittest.main()
