from __future__ import annotations

from pathlib import Path
import re
import tempfile
import unittest

from verify_release_notes import DEFAULT_FORBIDDEN_HEADINGS, check

SUMMARY = "## 主要更新"
IDENTITY = ("## 版本信息", "## 构建信息")
LINK_RE = re.compile(r"/blob/v[^/\s]+/")
MAX_LINES = 40

REPOSITORY = "https://github.com/huaxianyan/SevenMirror-Extension"

VALID = (
    "One sentence about what this release solves.\n"
    "\n"
    "## 主要更新\n"
    "\n"
    "- **Small title**: detail\n"
    "\n"
    f"Details live in [the record]({REPOSITORY}/blob/v0.1.21/docs/release-provenance.md).\n"
)


def check_text(text: str) -> list[str]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "v0.1.21.md"
        path.write_text(text, encoding="utf-8")
        return check(path, SUMMARY, list(DEFAULT_FORBIDDEN_HEADINGS), IDENTITY, LINK_RE, MAX_LINES)


class VerifyReleaseNotesTest(unittest.TestCase):
    def test_accepts_the_short_shape_with_a_tag_link(self) -> None:
        self.assertEqual(check_text(VALID), [])

    def test_rejects_a_first_line_title(self) -> None:
        errors = check_text("# SevenMirror Extension\n\n" + VALID)
        self.assertTrue(any("must not start with an H1" in error for error in errors))

    def test_rejects_a_forbidden_section(self) -> None:
        errors = check_text(VALID + "\n## 使用说明\n\nSome usage text.\n")
        self.assertTrue(any("使用说明" in error for error in errors))

    def test_rejects_a_missing_detail_link(self) -> None:
        errors = check_text(VALID.replace(f"{REPOSITORY}/blob/v0.1.21/docs/release-provenance.md", "https://example.invalid/"))
        self.assertTrue(any("missing a link to the detailed record" in error for error in errors))

    def test_rejects_two_identity_sections(self) -> None:
        errors = check_text(VALID + "\n## 版本信息\n\n| a | b |\n\n## 构建信息\n\n| a | b |\n")
        self.assertTrue(any("keep only one version/build identity section" in error for error in errors))

    def test_rejects_an_overlong_body(self) -> None:
        errors = check_text(VALID + "\nfiller\n" * MAX_LINES)
        self.assertTrue(any("exceeds the" in error for error in errors))

    def test_accepts_the_checked_in_notes_for_the_current_version(self) -> None:
        repository = Path(__file__).resolve().parent.parent
        notes = repository / "docs" / "release-notes" / "v0.1.21.md"
        self.assertTrue(notes.is_file(), f"{notes} must exist for the tagged release")
        self.assertEqual(
            check(notes, SUMMARY, list(DEFAULT_FORBIDDEN_HEADINGS), IDENTITY, LINK_RE, MAX_LINES),
            [],
        )


if __name__ == "__main__":
    unittest.main()
