from __future__ import annotations

from pathlib import Path
import re
import tempfile
import unittest

from verify_release_notes import (
    DEFAULT_FEATURE_HEADINGS,
    DEFAULT_FIX_HEADINGS,
    DEFAULT_FORBIDDEN_HEADINGS,
    check,
)

FEATURES = list(DEFAULT_FEATURE_HEADINGS)
FIXES = list(DEFAULT_FIX_HEADINGS)
IDENTITY = ("## 版本信息", "## 构建信息")
LINK_RE = re.compile(r"/blob/v[^/\s]+/")
MAX_LINES = 40


def check_text(text: str) -> list[str]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "v0.1.0.md"
        path.write_text(text, encoding="utf-8")
        return check(path, FEATURES, FIXES, list(DEFAULT_FORBIDDEN_HEADINGS), IDENTITY,
                     LINK_RE, MAX_LINES)


VALID = (
    "一句话说明这版解决了什么。\n"
    "\n"
    "## 新功能\n"
    "\n"
    "- **小标题**：说明\n"
    "\n"
    "详细记录见 [发布溯源]("
    "https://github.com/huaxianyan/SevenMirror-Extension/blob/v0.1.0/docs/release-provenance.md)。\n"
)

REPAIRS = (
    "一句话说明这版修了什么。\n"
    "\n"
    "## 问题修复\n"
    "\n"
    "- **小标题**：说明\n"
    "\n"
    "详细记录见 [发布溯源]("
    "https://github.com/huaxianyan/SevenMirror-Extension/blob/v0.1.0/docs/release-provenance.md)。\n"
)


class VerifyReleaseNotesTest(unittest.TestCase):
    def test_accepts_the_short_shape_with_a_tag_link(self) -> None:
        self.assertEqual(check_text(VALID), [])

    def test_accepts_a_release_that_only_fixes_things(self) -> None:
        self.assertEqual(check_text(REPAIRS), [])

    def test_rejects_a_first_line_title(self) -> None:
        errors = check_text("# SevenMirror Android\n\n" + VALID)
        self.assertTrue(any("must not start with an H1" in error for error in errors))

    def test_rejects_a_merged_summary_section(self) -> None:
        errors = check_text(VALID.replace("## 新功能", "## 主要更新"))
        self.assertTrue(any("readers must see what is new" in error for error in errors))

    def test_rejects_a_classification_section_without_entries(self) -> None:
        errors = check_text(VALID + "\n## 问题修复\n\n只有一句说明，没有条目。\n")
        self.assertTrue(any("has no entries" in error for error in errors))

    def test_ignores_entries_that_are_only_an_example(self) -> None:
        errors = check_text(
            VALID.replace("## 新功能\n\n- **小标题**：说明\n",
                          "## 新功能\n\n```text\n- **小标题**：示例\n```\n"))
        self.assertTrue(any("has no entries" in error for error in errors))

    def test_rejects_a_forbidden_section(self) -> None:
        errors = check_text(VALID + "\n## 真机验收\n\nSome evidence.\n")
        self.assertTrue(any("真机验收" in error for error in errors))

    def test_rejects_a_missing_detail_link(self) -> None:
        errors = check_text(VALID.replace(
            "https://github.com/huaxianyan/SevenMirror-Extension/blob/v0.1.0/docs/release-provenance.md",
            "https://example.invalid/"))
        self.assertTrue(any("missing a link to the detailed record" in error for error in errors))

    def test_rejects_two_identity_sections(self) -> None:
        errors = check_text(VALID + "\n## 版本信息\n\n| a | b |\n\n## 构建信息\n\n| a | b |\n")
        self.assertTrue(any("keep only one version/build identity section" in error for error in errors))

    def test_rejects_an_overlong_body(self) -> None:
        errors = check_text(VALID + "\nfiller\n" * MAX_LINES)
        self.assertTrue(any("exceeds the" in error for error in errors))

    def test_accepts_the_checked_in_notes_for_the_current_version(self) -> None:
        repository = Path(__file__).resolve().parent.parent
        notes = repository / "docs" / "release-notes" / "v0.1.23.md"
        self.assertTrue(notes.is_file(), f"{notes} must exist for the tagged release")
        self.assertEqual(
            check(notes, FEATURES, FIXES, list(DEFAULT_FORBIDDEN_HEADINGS), IDENTITY,
                  LINK_RE, MAX_LINES),
            [],
        )


if __name__ == "__main__":
    unittest.main()
