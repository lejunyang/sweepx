#!/usr/bin/env python3
"""Lint repository documentation without third-party dependencies or network I/O.

The checks intentionally cover only repository-local invariants:

* local Markdown links resolve inside the repository and referenced heading anchors exist;
* research pages that cite external URLs carry a dated source snapshot near the top; and
* public documentation does not make a small set of unsafe cleanup claims without
  negating or explicitly suppressing the claim.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


EXCLUDED_DIRECTORIES = {".git", ".vitepress", "node_modules", "target"}
EXTERNAL_URL_RE = re.compile(r"https?://", re.IGNORECASE)
ISO_DATE_RE = re.compile(r"(?<!\d)(\d{4}-\d{2}-\d{2})(?!\d)")
SOURCE_DATE_WORDING_RE = re.compile(
    r"(?:source(?:s)?(?:[- ](?:snapshot|access))?[- ]date|"
    r"research[- ](?:date|snapshot)|sources?[- ]snapshot|snapshot[- ]date|"
    r"sources?[- ]accessed|"
    r"as[- ]of|调研快照|研究日期|网络来源访问日期|研究截点|"
    r"资料快照|来源日期|访问日期|截点)",
    re.IGNORECASE,
)
SUPPRESSION_TOKEN = "docs-lint: allow-next-line safety-claim"
SUPPRESSION_RE = re.compile(
    r"^\s*<!-- docs-lint: allow-next-line safety-claim -- (?P<reason>.*?) -->\s*$"
)

ENGLISH_UNSAFE_CLAIMS = (
    "exact disk usage",
    "will free",
    "unused",
    "safe to delete",
    "guaranteed recoverable",
    "guaranteed unrecoverable",
)
CHINESE_UNSAFE_CLAIMS = (
    "精确磁盘占用",
    "一定释放",
    "必定释放",
    "可安全删除",
    "保证可恢复",
    "保证不可恢复",
)
ENGLISH_NEGATION_RE = re.compile(
    r"\b(?:never|cannot|can't|can’t|won't|won’t|no\s+guarantee|"
    r"(?:do|does|did|is|are|was|were|will|must|should|can)(?: not|n't))\b"
    r"|\bnot\b(?!\s+only\b)",
    re.IGNORECASE,
)
CHINESE_NEGATION_RE = re.compile(
    r"(?:绝不|并不|并非|不是|不能|不会|不得|禁止|切勿|勿|不应|"
    r"不保证|无保证|未曾|尚未|没有|不可|不要|未|(?!仅)不)"
)
SENTENCE_BOUNDARY_RE = re.compile(r"[.!?;|。！？；]")
FENCE_OPEN_RE = re.compile(r"^ {0,3}(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
ATX_HEADING_RE = re.compile(r"^ {0,3}(?P<marks>#{1,6})(?:[ \t]+|$)(?P<title>.*)$")
SETEXT_RE = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
CUSTOM_ID_RE = re.compile(r"^(?P<title>.*?)[ \t]*\{#(?P<id>[^}\s]+)\}[ \t]*$")
HTML_ID_RE = re.compile(r"<(?:a|h[1-6])\b[^>]*\b(?:id|name)\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)


@dataclass(frozen=True)
class Diagnostic:
    path: str
    line: int
    column: int
    code: str
    message: str

    def format(self) -> str:
        return f"{self.path}:{self.line}:{self.column}: {self.code}: {self.message}"


@dataclass
class Document:
    path: Path
    relative_path: str
    raw_lines: list[str]
    block_visible_lines: list[str]
    prose_lines: list[str]
    directive_lines: list[str]
    anchors: set[str]


@dataclass(frozen=True)
class MarkdownLink:
    destination: str
    column: int
    start: int
    end: int
    is_image: bool


def _is_escaped(text: str, index: int) -> bool:
    backslashes = 0
    index -= 1
    while index >= 0 and text[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1


def _find_label_end(text: str, opening: int) -> int | None:
    depth = 1
    index = opening + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            index += 2
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _parse_link_at(text: str, opening: int, is_image: bool) -> MarkdownLink | None:
    label_end = _find_label_end(text, opening)
    if label_end is None or label_end + 1 >= len(text) or text[label_end + 1] != "(":
        return None

    index = label_end + 2
    while index < len(text) and text[index] in " \t":
        index += 1
    if index >= len(text):
        return None

    destination_chars: list[str] = []
    if text[index] == "<":
        index += 1
        while index < len(text) and text[index] != ">":
            if text[index] == "\\" and index + 1 < len(text):
                index += 1
            destination_chars.append(text[index])
            index += 1
        if index >= len(text):
            return None
        index += 1
    else:
        nested_parentheses = 0
        while index < len(text):
            char = text[index]
            if char == "\\" and index + 1 < len(text):
                destination_chars.append(text[index + 1])
                index += 2
                continue
            if char == "(":
                nested_parentheses += 1
                destination_chars.append(char)
                index += 1
                continue
            if char == ")":
                if nested_parentheses == 0:
                    break
                nested_parentheses -= 1
                destination_chars.append(char)
                index += 1
                continue
            if char in " \t" and nested_parentheses == 0:
                break
            destination_chars.append(char)
            index += 1

    # A destination that ended directly on ')' has no title. Otherwise accept a
    # Markdown title delimited by quotes or parentheses, then require the link's
    # final ')'. This avoids swallowing prose after a malformed link.
    if index < len(text) and text[index] == ")":
        end = index + 1
    else:
        while index < len(text) and text[index] in " \t":
            index += 1
        if index >= len(text) or text[index] not in "'\"(":
            return None
        title_open = text[index]
        title_close = ")" if title_open == "(" else title_open
        index += 1
        while index < len(text):
            if text[index] == "\\" and index + 1 < len(text):
                index += 2
                continue
            if text[index] == title_close:
                break
            index += 1
        if index >= len(text):
            return None
        index += 1
        while index < len(text) and text[index] in " \t":
            index += 1
        if index >= len(text) or text[index] != ")":
            return None
        end = index + 1

    return MarkdownLink(
        destination="".join(destination_chars),
        column=(opening - 1 if is_image else opening) + 1,
        start=opening - 1 if is_image else opening,
        end=end,
        is_image=is_image,
    )


def iter_markdown_links(line: str) -> list[MarkdownLink]:
    links: list[MarkdownLink] = []
    index = 0
    while index < len(line):
        opening = line.find("[", index)
        if opening < 0:
            break
        if _is_escaped(line, opening):
            index = opening + 1
            continue
        is_image = opening > 0 and line[opening - 1] == "!" and not _is_escaped(line, opening - 1)
        parsed = _parse_link_at(line, opening, is_image)
        if parsed is None:
            index = opening + 1
            continue
        links.append(parsed)
        index = parsed.end
    return links


def _mask_html_comments(line: str, in_comment: bool) -> tuple[str, bool]:
    chars = list(line)
    index = 0
    while index < len(line):
        if in_comment:
            end = line.find("-->", index)
            if end < 0:
                for position in range(index, len(chars)):
                    chars[position] = " "
                return "".join(chars), True
            for position in range(index, end + 3):
                chars[position] = " "
            index = end + 3
            in_comment = False
            continue
        start = line.find("<!--", index)
        if start < 0:
            break
        end = line.find("-->", start + 4)
        if end < 0:
            for position in range(start, len(chars)):
                chars[position] = " "
            return "".join(chars), True
        for position in range(start, end + 3):
            chars[position] = " "
        index = end + 3
    return "".join(chars), in_comment


def _mask_fences_and_comments(lines: list[str]) -> list[str]:
    visible: list[str] = []
    fence_char: str | None = None
    fence_length = 0
    in_comment = False

    for line in lines:
        if fence_char is not None:
            close_re = re.compile(rf"^ {{0,3}}{re.escape(fence_char)}{{{fence_length},}}[ \t]*$")
            if close_re.match(line):
                fence_char = None
                fence_length = 0
            visible.append(" " * len(line))
            continue

        without_comments, in_comment = _mask_html_comments(line, in_comment)
        opening = FENCE_OPEN_RE.match(without_comments)
        if opening:
            fence = opening.group("fence")
            fence_char = fence[0]
            fence_length = len(fence)
            visible.append(" " * len(line))
            continue
        visible.append(without_comments)
    return visible


def _mask_fenced_code(lines: list[str]) -> list[str]:
    """Mask fenced code while retaining comments used as lint directives."""

    visible: list[str] = []
    fence_char: str | None = None
    fence_length = 0
    for line in lines:
        if fence_char is not None:
            close_re = re.compile(rf"^ {{0,3}}{re.escape(fence_char)}{{{fence_length},}}[ \t]*$")
            if close_re.match(line):
                fence_char = None
                fence_length = 0
            visible.append(" " * len(line))
            continue
        opening = FENCE_OPEN_RE.match(line)
        if opening:
            fence = opening.group("fence")
            fence_char = fence[0]
            fence_length = len(fence)
            visible.append(" " * len(line))
            continue
        visible.append(line)
    return visible


def _mask_inline_code(lines: list[str]) -> list[str]:
    text = "\n".join(lines)
    chars = list(text)
    index = 0
    while index < len(text):
        if text[index] != "`":
            index += 1
            continue
        run_end = index + 1
        while run_end < len(text) and text[run_end] == "`":
            run_end += 1
        delimiter = text[index:run_end]
        search = run_end
        closing = -1
        while True:
            candidate = text.find(delimiter, search)
            if candidate < 0:
                break
            before_is_tick = candidate > 0 and text[candidate - 1] == "`"
            after = candidate + len(delimiter)
            after_is_tick = after < len(text) and text[after] == "`"
            if not before_is_tick and not after_is_tick:
                closing = candidate
                break
            search = candidate + 1
        if closing < 0:
            index = run_end
            continue
        for position in range(index, closing + len(delimiter)):
            if chars[position] != "\n":
                chars[position] = " "
        index = closing + len(delimiter)
    return "".join(chars).split("\n")


def _mask_images(line: str) -> str:
    chars = list(line)
    for link in iter_markdown_links(line):
        if link.is_image:
            for index in range(link.start, link.end):
                chars[index] = " "
    return "".join(chars)


def vitepress_slug(text: str) -> str:
    """Return the default VitePress heading slug for *text*."""

    value = unicodedata.normalize("NFKD", text)
    value = re.sub(r"[\u0300-\u036f]", "", value)
    value = re.sub(r"[\u0000-\u001f]", "", value)
    value = re.sub(r"[\s~`!@#$%^&*()\-_+=\[\]{}|\\;:\"'“”‘’<>,.?/]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    if value[:1] in "0123456789":
        value = "_" + value
    return value.lower()


def _plain_heading_text(title: str) -> str:
    title = re.sub(r"(`+)(.*?)\1", lambda match: match.group(2).strip(), title)
    title = re.sub(r"!\[([^]]*)\]\([^)]*\)", "", title)
    previous = None
    while previous != title:
        previous = title
        title = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", title)
    title = re.sub(r"<[^>]+>", "", title)
    title = re.sub(r"\\([\\`*{}\[\]()#+.!_>~-])", r"\1", title)
    # markdown-it passes decoded text tokens for literal entities, but text from
    # an inline HTML token is discarded. Keep the same distinction here.
    return title.strip()


def _extract_anchors(lines: list[str]) -> set[str]:
    heading_lines = list(lines)
    if heading_lines and heading_lines[0].strip() == "---":
        for closing in range(1, len(heading_lines)):
            if heading_lines[closing].strip() in {"---", "..."}:
                for index in range(closing + 1):
                    heading_lines[index] = " " * len(heading_lines[index])
                break

    anchors: set[str] = set()
    heading_anchors: set[str] = set()
    for index, line in enumerate(heading_lines):
        for explicit in HTML_ID_RE.findall(line):
            anchors.add(html.unescape(explicit))

        match = ATX_HEADING_RE.match(line)
        title: str | None = None
        if match:
            title = re.sub(r"[ \t]+#+[ \t]*$", "", match.group("title"))
        elif SETEXT_RE.match(line) and index > 0 and heading_lines[index - 1].strip():
            title = heading_lines[index - 1].strip()
        if title is None:
            continue
        custom = CUSTOM_ID_RE.match(title)
        if custom:
            candidate = unquote(custom.group("id"))
            heading_anchors.add(candidate)
            anchors.add(candidate)
            continue
        base = vitepress_slug(_plain_heading_text(title))
        candidate = base
        suffix = 1
        while candidate in heading_anchors:
            candidate = f"{base}-{suffix}"
            suffix += 1
        heading_anchors.add(candidate)
        anchors.add(candidate)
    return anchors


def _read_document(path: Path, root: Path) -> tuple[Document | None, Diagnostic | None]:
    relative = path.relative_to(root).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return None, Diagnostic(relative, 1, 1, "DOC001", f"cannot read UTF-8 Markdown: {error}")
    raw_lines = text.splitlines()
    block_visible = _mask_fences_and_comments(raw_lines)
    prose_lines = [_mask_images(line) for line in _mask_inline_code(block_visible)]
    directive_lines = _mask_inline_code(_mask_fenced_code(raw_lines))
    return (
        Document(
            path=path,
            relative_path=relative,
            raw_lines=raw_lines,
            block_visible_lines=block_visible,
            prose_lines=prose_lines,
            directive_lines=directive_lines,
            anchors=_extract_anchors(block_visible),
        ),
        None,
    )


def discover_markdown(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".md", ".markdown"}:
            continue
        try:
            relative_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(part in EXCLUDED_DIRECTORIES for part in relative_parts):
            continue
        paths.append(path)
    return sorted(paths)


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _path_candidates(
    path: Path, *, vitepress_route: bool, directory_route: bool = False
) -> list[Path]:
    if vitepress_route:
        if directory_route:
            return [path / "index.md"]
        if path.suffix.lower() == ".html":
            return [path.with_suffix(".md")]
        if path.suffix:
            return [path]
        return [path.with_suffix(".md"), path / "index.md"]
    if path.is_dir():
        return [path / "README.md", path / "index.md"]
    return [path]


def _resolve_local_link(
    document: Document, destination: str, root: Path
) -> tuple[Path | None, str, str | None]:
    try:
        parsed = urlsplit(destination)
    except ValueError:
        return None, "", "invalid link destination"
    if parsed.scheme or parsed.netloc or destination.startswith("//"):
        return None, "", None

    try:
        decoded_path = unquote(parsed.path, errors="strict")
        fragment = unquote(parsed.fragment, errors="strict")
    except UnicodeDecodeError:
        return None, "", "invalid UTF-8 percent encoding in link"
    if "\x00" in decoded_path or "\x00" in fragment:
        return None, fragment, "NUL byte in link destination"

    root_resolved = root.resolve()
    if not decoded_path:
        return document.path.resolve(), fragment, None

    route = decoded_path.startswith("/")
    if route:
        site_root = (root / "site").resolve()
        route_path = PurePosixPath(decoded_path.lstrip("/"))
        unresolved = site_root.joinpath(*route_path.parts)
        resolved = unresolved.resolve()
        if not _within(resolved, site_root):
            return None, fragment, "VitePress route escapes site root"
    else:
        relative_path = PurePosixPath(decoded_path)
        unresolved = document.path.parent.joinpath(*relative_path.parts)
        resolved = unresolved.resolve()
        if not _within(resolved, root_resolved):
            return None, fragment, "local link escapes repository root"

    candidates = _path_candidates(
        resolved, vitepress_route=route, directory_route=route and decoded_path.endswith("/")
    )
    for candidate in candidates:
        candidate_resolved = candidate.resolve()
        allowed_root = (root / "site").resolve() if route else root_resolved
        if not _within(candidate_resolved, allowed_root):
            return None, fragment, "local link resolves outside its allowed root"
        if candidate_resolved.is_file():
            return candidate_resolved, fragment, None
    return candidates[0], fragment, "local link target does not exist"


def _lint_links(
    documents: dict[Path, Document], root: Path
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for document in list(documents.values()):
        for line_number, line in enumerate(document.prose_lines, start=1):
            for link in iter_markdown_links(line):
                if link.is_image:
                    continue
                target, fragment, error = _resolve_local_link(document, link.destination, root)
                if target is None and error is None:
                    continue
                if error is not None:
                    diagnostics.append(
                        Diagnostic(
                            document.relative_path,
                            line_number,
                            link.column,
                            "LINK001",
                            f"{error}: {link.destination!r}",
                        )
                    )
                    continue
                if not fragment or target is None or target.suffix.lower() not in {".md", ".markdown"}:
                    continue
                target_document = documents.get(target.resolve())
                if target_document is None:
                    target_document, read_error = _read_document(target, root)
                    if read_error is not None:
                        diagnostics.append(read_error)
                        continue
                    assert target_document is not None
                    documents[target.resolve()] = target_document
                if fragment not in target_document.anchors:
                    diagnostics.append(
                        Diagnostic(
                            document.relative_path,
                            line_number,
                            link.column,
                            "LINK002",
                            f"anchor #{fragment} does not exist in {target_document.relative_path}",
                        )
                    )
    return diagnostics


def _is_research_document(document: Document) -> bool:
    parts = PurePosixPath(document.relative_path).parts
    return len(parts) >= 3 and parts[0:2] == ("docs", "research")


def _lint_research_dates(documents: dict[Path, Document], today: dt.date) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for document in documents.values():
        if not _is_research_document(document):
            continue
        if not any(EXTERNAL_URL_RE.search(line) for line in document.prose_lines):
            continue

        first_nonblank: list[tuple[int, str]] = []
        for line_number, raw_line in enumerate(document.raw_lines, start=1):
            if raw_line.strip():
                first_nonblank.append((line_number, document.prose_lines[line_number - 1]))
                if len(first_nonblank) == 10:
                    break

        dated_lines = [item for item in first_nonblank if SOURCE_DATE_WORDING_RE.search(item[1])]
        if not dated_lines:
            diagnostics.append(
                Diagnostic(
                    document.relative_path,
                    1,
                    1,
                    "DATE001",
                    "research page with external URLs needs a source/snapshot date in its first 10 nonblank lines",
                )
            )
            continue

        valid_date = False
        date_errors: list[tuple[int, str]] = []
        for line_number, line in dated_lines:
            matches = ISO_DATE_RE.findall(line)
            if not matches:
                date_errors.append((line_number, "date wording is present without an ISO YYYY-MM-DD date"))
                continue
            for value in matches:
                try:
                    parsed_date = dt.date.fromisoformat(value)
                except ValueError:
                    date_errors.append((line_number, f"invalid ISO source date {value!r}"))
                    continue
                if parsed_date > today:
                    date_errors.append((line_number, f"source date {value} is in the future"))
                    continue
                valid_date = True
        if valid_date:
            continue
        line_number, message = date_errors[0]
        diagnostics.append(Diagnostic(document.relative_path, line_number, 1, "DATE002", message))
    return diagnostics


def _is_public_claim_document(document: Document) -> bool:
    parts = PurePosixPath(document.relative_path).parts
    return document.relative_path == "README.md" or (parts and parts[0] in {"site", "skills"})


def _unsafe_claims(line: str) -> list[tuple[int, int, str]]:
    matches: list[tuple[int, int, str]] = []
    for phrase in ENGLISH_UNSAFE_CLAIMS:
        pattern = re.compile(rf"(?<![\w]){re.escape(phrase)}(?![\w])", re.IGNORECASE)
        matches.extend((match.start(), match.end(), match.group(0)) for match in pattern.finditer(line))
    for phrase in CHINESE_UNSAFE_CLAIMS:
        start = 0
        while True:
            index = line.find(phrase, start)
            if index < 0:
                break
            matches.append((index, index + len(phrase), phrase))
            start = index + len(phrase)
    return sorted(matches)


def _sentence_span(line: str, start: int, end: int) -> tuple[int, int]:
    sentence_start = 0
    for boundary in SENTENCE_BOUNDARY_RE.finditer(line, 0, start):
        sentence_start = boundary.end()
    boundary = SENTENCE_BOUNDARY_RE.search(line, end)
    sentence_end = boundary.start() if boundary else len(line)
    return sentence_start, sentence_end


def _is_negated(line: str, start: int, end: int) -> bool:
    sentence_start, sentence_end = _sentence_span(line, start, end)
    sentence_chars = list(line[sentence_start:sentence_end])
    for claim_start, claim_end, _ in _unsafe_claims(line):
        if claim_start < sentence_start or claim_end > sentence_end:
            continue
        for index in range(claim_start - sentence_start, claim_end - sentence_start):
            sentence_chars[index] = " "
    sentence_without_claims = "".join(sentence_chars)
    return bool(
        ENGLISH_NEGATION_RE.search(sentence_without_claims)
        or CHINESE_NEGATION_RE.search(sentence_without_claims)
    )


def _lint_unsafe_claims(documents: dict[Path, Document]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for document in documents.values():
        if not _is_public_claim_document(document):
            continue
        suppress_next_prose_line = False
        for index, (directive_line, prose_line) in enumerate(
            zip(document.directive_lines, document.prose_lines), start=1
        ):
            marker = SUPPRESSION_RE.fullmatch(directive_line)
            if marker:
                if not marker.group("reason").strip():
                    diagnostics.append(
                        Diagnostic(
                            document.relative_path,
                            index,
                            1,
                            "CLAIM002",
                            "safety-claim suppression requires a nonempty reason",
                        )
                    )
                    suppress_next_prose_line = False
                else:
                    suppress_next_prose_line = True
                continue
            if SUPPRESSION_TOKEN in directive_line:
                diagnostics.append(
                    Diagnostic(
                        document.relative_path,
                        index,
                        1,
                        "CLAIM002",
                        "malformed safety-claim suppression; use '<!-- docs-lint: allow-next-line safety-claim -- REASON -->'",
                    )
                )
                suppress_next_prose_line = False
                continue
            if not prose_line.strip():
                continue

            suppressed = suppress_next_prose_line
            suppress_next_prose_line = False
            for start, end, phrase in _unsafe_claims(prose_line):
                if suppressed or _is_negated(prose_line, start, end):
                    continue
                diagnostics.append(
                    Diagnostic(
                        document.relative_path,
                        index,
                        start + 1,
                        "CLAIM001",
                        f"unsafe public cleanup claim {phrase!r}; negate it or add a reasoned one-line suppression",
                    )
                )
    return diagnostics


def lint_repository(root: Path, *, today: dt.date | None = None) -> tuple[list[Diagnostic], int]:
    root = root.resolve()
    documents: dict[Path, Document] = {}
    diagnostics: list[Diagnostic] = []
    paths = discover_markdown(root)
    for path in paths:
        resolved_path = path.resolve()
        if not _within(resolved_path, root):
            diagnostics.append(
                Diagnostic(
                    path.relative_to(root).as_posix(),
                    1,
                    1,
                    "DOC002",
                    "Markdown file resolves outside repository root",
                )
            )
            continue
        document, error = _read_document(resolved_path, root)
        if error is not None:
            diagnostics.append(error)
        elif document is not None:
            documents[resolved_path] = document

    # Work on a stable snapshot: link resolution may cache a target that was excluded
    # from discovery, but must not mutate the mapping during iteration.
    diagnostics.extend(_lint_links(documents, root))
    diagnostics.extend(_lint_research_dates(documents, today or dt.date.today()))
    diagnostics.extend(_lint_unsafe_claims(documents))
    diagnostics.sort(key=lambda item: (item.path, item.line, item.column, item.code, item.message))
    return diagnostics, len(paths)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the parent of scripts/)",
    )
    args = parser.parse_args(argv)
    if not args.root.is_dir():
        parser.error(f"repository root is not a directory: {args.root}")

    diagnostics, count = lint_repository(args.root)
    for diagnostic in diagnostics:
        print(diagnostic.format())
    if diagnostics:
        print(f"docs lint: {len(diagnostics)} error(s) across {count} Markdown file(s)", file=sys.stderr)
        return 1
    print(f"docs lint: checked {count} Markdown file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
