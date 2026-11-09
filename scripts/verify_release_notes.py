#!/usr/bin/env python3
"""检查版本化的发布说明是否够短，并链接到详细记录。

GitHub Release 的正文由 ``docs/release-notes/v<版本>.md`` 加上工作流追加的
「## 构建信息」一节拼成。正文必须保持简短：一段概述、按新功能／问题修复分开的条目，
以及指向详细记录的链接。
使用方式、真机验收和构建范围的细节属于 ``docs/architecture.md`` 等长期文档，不写进发布说明。

用法：
    python verify_release_notes.py docs/release-notes/v0.2.0.md
    python verify_release_notes.py --tag v0.2.0
    python verify_release_notes.py --tag v0.2.0 --dir docs/releases --forbidden '## 迁移指南'

Python 3.7 以上，无第三方依赖。
"""

import argparse
import re
import sys
from pathlib import Path

DEFAULT_FEATURE_HEADINGS = ("## 新功能", "## 新特性", "## 新增功能")
DEFAULT_FIX_HEADINGS = ("## 问题修复", "## 修复", "## Bug 修复", "## 缺陷修复")
DEFAULT_FORBIDDEN_HEADINGS = (
    "## 使用说明",
    "## 真机验收",
    "## 构建与兼容范围",
    "## 兼容边界",
)
# 身份节至多出现一个，通常由工作流追加
IDENTITY_HEADINGS = ("## 版本信息", "## 构建信息")
# 指向仓库内某个标签下的文档，例如 /blob/v0.2.0/docs/architecture.md
DEFAULT_LINK_PATTERN = r"/blob/v[^/\s]+/"
DEFAULT_NOTES_DIR = "docs/release-notes"
DEFAULT_MAX_LINES = 40


def section_items(lines, headings):
    """Return the bullet count under each matching section, stopping at the next heading.

    Fenced blocks are skipped so an example snippet cannot stand in for real entries.
    """
    counts = []
    fenced = False
    current = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        if stripped.startswith("#"):
            current = stripped if stripped in headings else None
            if current is not None:
                counts.append([current, 0])
            continue
        if current is not None and (stripped.startswith("- ") or stripped.startswith("* ")):
            counts[-1][1] += 1
    return counts


def check(path, feature_headings, fix_headings, forbidden, identity, link_re, max_lines):
    errors = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return ["%s: cannot read (%s)" % (path, exc)]

    lines = text.splitlines()
    if not lines:
        return ["%s: file is empty" % path]

    if lines[0].startswith("# "):
        errors.append(
            "%s: must not start with an H1 heading; drop the product/version title line" % path)
    for heading in forbidden:
        if any(line.strip() == heading for line in lines):
            errors.append(
                "%s: must not contain the section %r; details belong in docs/"
                % (path, heading))
    identity_hits = [line.strip() for line in lines if line.strip() in identity]
    if len(identity_hits) > 1:
        errors.append(
            "%s: keep only one version/build identity section, found %r"
            % (path, identity_hits))
    sections = section_items(lines, tuple(feature_headings) + tuple(fix_headings))
    if not sections:
        errors.append(
            "%s: needs a %r or %r section; readers must see what is new and what got fixed"
            % (path, feature_headings[0], fix_headings[0]))
    for heading, count in sections:
        if count == 0:
            errors.append(
                "%s: section %r has no entries; drop it or list what changed"
                % (path, heading))
    if not link_re.search(text):
        errors.append(
            "%s: missing a link to the detailed record (expected a /blob/v<tag>/ URL)" % path)
    if len(lines) > max_lines:
        errors.append(
            "%s: %d lines exceeds the %d-line brevity limit" % (path, len(lines), max_lines))
    return errors


def main():
    parser = argparse.ArgumentParser(description="check versioned release notes",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("notes", nargs="*", help="release note files")
    parser.add_argument("--tag", help="release tag, for example v0.2.0")
    parser.add_argument("--dir", default=DEFAULT_NOTES_DIR,
                        help="release notes directory (default: %(default)s)")
    parser.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES,
                        help="line limit (default: %(default)s)")
    parser.add_argument("--feature-heading", action="append", default=[],
                        help="extra new-feature section heading, repeatable")
    parser.add_argument("--fix-heading", action="append", default=[],
                        help="extra fixed-issue section heading, repeatable")
    parser.add_argument("--link-pattern", default=DEFAULT_LINK_PATTERN,
                        help="regex the detail link must match (default: %(default)s)")
    parser.add_argument("--forbidden", action="append", default=[],
                        help="extra forbidden section heading, repeatable")
    args = parser.parse_args()

    paths = [Path(item) for item in args.notes]
    if not paths and args.tag:
        paths = [Path(args.dir) / ("%s.md" % args.tag)]
    if not paths:
        print("give at least one release note file, or a tag with --tag", file=sys.stderr)
        return 2

    try:
        link_re = re.compile(args.link_pattern)
    except re.error as exc:
        print("invalid --link-pattern: %s" % exc, file=sys.stderr)
        return 2

    feature_headings = list(DEFAULT_FEATURE_HEADINGS) +         [item for item in args.feature_heading if item not in DEFAULT_FEATURE_HEADINGS]
    fix_headings = list(DEFAULT_FIX_HEADINGS) +         [item for item in args.fix_heading if item not in DEFAULT_FIX_HEADINGS]

    forbidden = list(DEFAULT_FORBIDDEN_HEADINGS)
    for item in args.forbidden:
        if item not in forbidden:
            forbidden.append(item)

    errors = []
    for path in paths:
        if not path.is_file():
            errors.append("%s: file does not exist" % path)
            continue
        errors.extend(check(path, feature_headings, fix_headings, forbidden,
                            IDENTITY_HEADINGS, link_re, args.max_lines))

    if errors:
        print("release note format check failed:", file=sys.stderr)
        for error in errors:
            print("- %s" % error, file=sys.stderr)
        return 1
    print("verified across %d file(s)" % len(paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
