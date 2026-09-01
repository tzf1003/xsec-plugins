#!/usr/bin/env python3
"""Fail-closed validation for XSEC official marketplace source and releases.

``source`` validates a disposable output made by ``build_market.py`` and is
safe for pull requests and before the protected KMS publication step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from build_market import (
    MARKETPLACE_RELATIVE_PATH,
    RELEASE_ID_PATTERN,
    ROOT,
    SNAPSHOT_ROOT_RELATIVE_PATH,
    is_link,
    require_release_engines,
    release_id,
    sha256,
    write_zip,
)
from marketplace_contract import DEFAULT_OFFICIAL_PLUGIN_IDS


MAX_ZIP_ENTRIES = 10_000
MAX_ZIP_FILE_BYTES = 64 * 1024 * 1024
MAX_ZIP_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 100
WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>:"/\\|?*')
WINDOWS_RESERVED_DEVICE_NAMES = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
})
WINDOWS_DEVICE_SUPERSCRIPT_DIGITS = str.maketrans({
    "¹": "1",
    "²": "2",
    "³": "3",
})
ENTRYPOINT_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")
APPROVALS_PLUGIN_ID = "com.xsec.workspace.approvals"
APPROVALS_FRONTEND_METHODS = frozenset({
    "xsec.approvals.list",
    "xsec.approvals.statistics",
    "xsec.approvals.settings.get",
    "xsec.approvals.settings.set",
})
APPROVALS_FRONTEND_METHOD_CONTRACT = {
    "xsec.approvals.list": ("workspace.session.read", "session"),
    "xsec.approvals.statistics": ("workspace.session.read", "session"),
    "xsec.approvals.settings.get": ("pluginData.read", "plugin"),
    "xsec.approvals.settings.set": ("pluginData.write", "plugin"),
}
APPROVALS_FRONTEND_PLUGIN_API_RANGE = "^1.2.0"
APPROVALS_WORKSPACE_TOOL_ACTIVATION_EVENT = "onWorkspaceTool:approvals"
APPROVALS_WORKSPACE_TOOL_CONTRIBUTION = {
    "title": "审批记录",
    "icon": "clipboard-check",
    "scope": "session",
    "launchable": True,
    "policy": "singleton",
    "surface": "standard",
    "retain": "active",
    "preferredBottomHeight": 340,
    "surfaces": ["interactive-dock", "batch-observe"],
}
JAVASCRIPT_SYNTAX_CHECK_TIMEOUT_SECONDS = 10
JAVASCRIPT_LINE_TERMINATORS = frozenset({"\n", "\r", "\u2028", "\u2029"})
JAVASCRIPT_UNICODE_ESCAPE = re.compile(
    r"\\u(?:([0-9A-Fa-f]{4})|\{([0-9A-Fa-f]{1,6})\})"
)
APPROVALS_FRONTEND_LIFECYCLE_METHODS = frozenset({"mount", "update", "dispose"})
OFFICIAL_FRONTEND_PLUGIN_API_RANGE = "^1.2.0"
WORKSPACE_TOOL_NAVIGATION_PLUGIN_API_RANGE = "^1.3.0"
WORKSPACE_COMPOSER_PLUGIN_API_RANGE = "^1.4.0"
WORKSPACE_COMPOSER_METHODS = frozenset({
    "xsec.workspace.composer.line-comment.add",
    "xsec.workspace.composer.path.add",
})
OFFICIAL_FRONTEND_MIN_BYTES = 1_000
OFFICIAL_PLUGIN_SETTINGS_CONTRACT: dict[str, dict[str, object]] = {
    "com.xsec.asset-discovery": {
        "page": "asset-discovery",
        "title": "资产发现",
        "methods": {
            "xsec.asset-discovery.settings.get": ("pluginData.read", "plugin"),
            "xsec.asset-discovery.settings.set": ("pluginData.write", "plugin"),
            "xsec.asset-discovery.credentials.set": ("pluginData.write", "plugin"),
            "xsec.asset-discovery.credentials.clear": ("pluginData.write", "plugin"),
            "xsec.plugin.settings.open": ("pluginData.read", "plugin"),
        },
    },
    "com.xsec.project-workspace": {
        "page": "project-workspace",
        "title": "项目工作区",
        "methods": {
            "xsec.project-workspace.settings.get": ("pluginData.read", "plugin"),
            "xsec.project-workspace.settings.set": ("pluginData.write", "plugin"),
        },
    },
    "com.xsec.system-terminal": {
        "page": "system-terminal",
        "title": "系统终端",
        "methods": {
            "xsec.terminal.settings.get": ("pluginData.read", "plugin"),
            "xsec.terminal.settings.set": ("pluginData.write", "plugin"),
        },
        "optionalMethods": {
            "xsec.plugin.settings.open": ("pluginData.read", "plugin"),
        },
    },
    "com.xsec.workspace.approvals": {
        "page": "approvals",
        "title": "审批记录",
        "methods": {
            "xsec.approvals.settings.get": ("pluginData.read", "plugin"),
            "xsec.approvals.settings.set": ("pluginData.write", "plugin"),
        },
    },
    "com.xsec.workspace.browser": {
        "page": "browser",
        "title": "浏览器会话",
        "methods": {
            "xsec.browser.settings.get": ("pluginData.read", "plugin"),
            "xsec.browser.settings.set": ("pluginData.write", "plugin"),
        },
    },
    "com.xsec.workspace.traffic": {
        "page": "traffic",
        "title": "抓包流量",
        "methods": {
            "xsec.traffic.settings.get": ("pluginData.read", "plugin"),
            "xsec.traffic.settings.set": ("pluginData.write", "plugin"),
            "xsec.traffic.ca.status": ("pluginData.read", "plugin"),
            "xsec.traffic.ca.import": ("pluginData.write", "plugin"),
            "xsec.traffic.ca.rotate": ("pluginData.write", "plugin"),
            "xsec.traffic.passive-rules.list": ("pluginData.read", "plugin"),
            "xsec.traffic.passive-rules.upsert": ("pluginData.write", "plugin"),
            "xsec.traffic.passive-rules.toggle": ("pluginData.write", "plugin"),
            "xsec.traffic.passive-rules.delete": ("pluginData.write", "plugin"),
        },
    },
}
FORBIDDEN_OFFICIAL_FRONTEND_MARKERS = (
    "XSEC official plugin is active in Desktop.",
    "renderPlaceholder",
    "placeholder-module",
    "mock",
    "fallback-module",
)
FRONTEND_CALLBACK_APIS = frozenset({
    "IntersectionObserver",
    "MutationObserver",
    "ResizeObserver",
    "addEventListener",
    "catch",
    "finally",
    "forEach",
    "map",
    "requestAnimationFrame",
    "setInterval",
    "setTimeout",
    "then",
})
FRONTEND_REQUEST_FORWARDERS = frozenset({"call", "apply", "bind"})
# The browser-side approvals frontend is explicitly reviewed and pinned.  The
# hash includes its isolated settings surface, so any source change still
# requires an intentional validation update in the same review.
# Every released approvals frontend remains pinned to its exact reviewed
# source.  The Factory validates retained snapshots as well as a candidate
# source checkout, so a new candidate must not invalidate an earlier immutable
# release during the same validation pass.
APPROVALS_FRONTEND_SOURCE_SHA256_BY_VERSION = {
    "1.2.2": "5508a16c22e704d9a366abe60112edf20e7f0a9478d44e9d0048973501fcf00b",
    "1.3.0": "f2a7d1673b7117e7bb44398ed4ae62f08bb702f960463318260546819b0742df",
    "1.3.2": "209e8f2eb043a777a77235bdb4985d7d74f951a86162c913be80c27d9a4dcf18",
}


class MarketplaceValidationError(ValueError):
    """A marketplace invariant was not met."""


def fail(message: str) -> None:
    raise MarketplaceValidationError(message)


def read_json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object")
    return value


def safe_relative_path(value: object, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or value != value.strip():
        fail(f"{label} must be a non-empty relative path")
    if "\\" in value or "%" in value:
        fail(f"{label} must use unescaped forward-slash relative paths")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        fail(f"{label} must not be a URL")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        fail(f"{label} must not escape its release directory")
    return path


def resolve_below(base: Path, relative: PurePosixPath, label: str) -> Path:
    current = base
    for part in relative.parts:
        current = current / part
        if is_link(current):
            fail(f"{label} must not traverse symbolic links")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(base.resolve(strict=True))
    except (OSError, ValueError) as error:
        fail(f"{label} must resolve to a regular file below its release directory: {error}")
    if not resolved.is_file():
        fail(f"{label} must resolve to a regular file")
    return resolved


def desktop_entrypoints(manifest: dict[str, object], label: str) -> list[tuple[str, PurePosixPath]]:
    """Validate the XSEC entrypoint declaration shared by source and archives."""

    try:
        desktop = manifest["extensions"]["com.xsec.desktop"]
    except (KeyError, TypeError):
        fail(f"{label} lacks XSEC Desktop extension metadata")
    if not isinstance(desktop, dict):
        fail(f"{label} has invalid XSEC Desktop extension metadata")
    entrypoints = desktop.get("entrypoints")
    if not isinstance(entrypoints, dict) or not entrypoints:
        fail(f"{label} must declare at least one XSEC Desktop entrypoint")

    result: list[tuple[str, PurePosixPath]] = []
    for name, value in entrypoints.items():
        if not isinstance(name, str) or not ENTRYPOINT_NAME.fullmatch(name):
            fail(f"{label} has an invalid XSEC Desktop entrypoint name")
        relative = safe_relative_path(value, f"{label} entrypoint {name}")
        result.append((name, relative))
    return result


def consume_javascript_regex(source: str, index: int) -> int | None:
    """Return the first position following a regex literal, without executing it."""

    cursor = index + 1
    escaped = False
    in_character_class = False
    while cursor < len(source):
        character = source[cursor]
        if character in {"\n", "\r"}:
            return None
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "[":
            in_character_class = True
        elif character == "]":
            in_character_class = False
        elif character == "/" and not in_character_class:
            cursor += 1
            while cursor < len(source) and (source[cursor].isalpha() or source[cursor] in {"$", "_"}):
                cursor += 1
            return cursor
        cursor += 1
    return None


REGEX_PREFIX_KEYWORDS = {
    "await",
    "case",
    "delete",
    "do",
    "else",
    "in",
    "instanceof",
    "new",
    "of",
    "return",
    "throw",
    "typeof",
    "void",
    "yield",
}
CONTROL_HEADER_KEYWORDS = {"if", "for", "while", "with", "switch", "catch"}
CONST_INITIALIZER_TERMINATORS = {";", ",", "}"}
STATEMENT_BLOCK_KEYWORDS = {"else", "finally", "try", "do", "catch"}
STATEMENT_BOUNDARY_PUNCTUATION = {";", "{", "}"}


def javascript_control_header_closed(tokens: list[tuple[str, str]]) -> bool:
    """Return whether the last token closes if/for/while/with/switch/catch (...)."""

    opening = matching_opening_parenthesis(tokens, len(tokens) - 1)
    if opening is None or opening == 0:
        return False
    previous = tokens[opening - 1]
    if previous[0] == "identifier" and previous[1] in CONTROL_HEADER_KEYWORDS:
        # A member call such as ``value.catch(...)`` is an expression, not a
        # control-statement header.  Treating its closing parenthesis as a
        # statement boundary would let a following division slash consume
        # arbitrary source as a regex literal.
        return opening < 2 or tokens[opening - 2] != ("punctuation", ".")
    return (
        opening >= 2
        and previous == ("identifier", "await")
        and tokens[opening - 2] == ("identifier", "for")
    )


def matching_opening_brace(tokens: list[tuple[str, str]], closing_index: int) -> int | None:
    """Find the opening brace paired with a tokenized closing one."""

    depth = 0
    for index in range(closing_index, -1, -1):
        if tokens[index] == ("punctuation", "}"):
            depth += 1
        elif tokens[index] == ("punctuation", "{"):
            depth -= 1
            if depth == 0:
                return index
    return None


def javascript_declaration_boundary(tokens: list[tuple[str, str]], cursor: int) -> bool:
    if cursor < 0:
        return True
    if tokens[cursor] == ("identifier", "default"):
        cursor -= 1
    if cursor >= 0 and tokens[cursor] == ("identifier", "export"):
        cursor -= 1
    if cursor < 0:
        return True
    return tokens[cursor][1] in STATEMENT_BOUNDARY_PUNCTUATION


def javascript_function_declaration_before_brace(tokens: list[tuple[str, str]], opening: int) -> bool:
    paren = matching_opening_parenthesis(tokens, opening - 1)
    if paren is None or paren == 0:
        return False
    cursor = paren - 1
    if tokens[cursor][0] == "identifier" and tokens[cursor][1] != "function":
        cursor -= 1
        if cursor < 0:
            return False
    if tokens[cursor] == ("punctuation", "*"):
        cursor -= 1
        if cursor < 0:
            return False
    if tokens[cursor] != ("identifier", "function"):
        return False
    cursor -= 1
    if cursor >= 0 and tokens[cursor] == ("identifier", "async"):
        cursor -= 1
    return javascript_declaration_boundary(tokens, cursor)


def javascript_class_declaration_before_brace(tokens: list[tuple[str, str]], opening: int) -> bool:
    cursor = opening - 1
    if tokens[cursor] == ("punctuation", ")"):
        paren = matching_opening_parenthesis(tokens, cursor)
        if paren is None or paren == 0:
            return False
        cursor = paren - 1
        if cursor < 0 or tokens[cursor] != ("identifier", "extends"):
            return False
        cursor -= 1
    elif cursor >= 1 and tokens[cursor][0] == "identifier" and tokens[cursor - 1] == ("identifier", "extends"):
        cursor -= 2
    if cursor >= 0 and tokens[cursor][0] == "identifier" and tokens[cursor][1] != "class":
        cursor -= 1
    if cursor < 0 or tokens[cursor] != ("identifier", "class"):
        return False
    return javascript_declaration_boundary(tokens, cursor - 1)


def javascript_statement_brace_closed(
    tokens: list[tuple[str, str]], *, expression_context: bool = False
) -> bool:
    """Return whether the last `}` closes a statement, so a regex may follow."""

    opening = matching_opening_brace(tokens, len(tokens) - 1)
    if opening is None:
        return False
    if opening == 0:
        return not expression_context
    previous = tokens[opening - 1]
    if previous[1] in STATEMENT_BOUNDARY_PUNCTUATION:
        return True
    if previous[0] == "identifier" and previous[1] in STATEMENT_BLOCK_KEYWORDS:
        return True
    if (
        previous == ("punctuation", ">")
        and opening >= 2
        and tokens[opening - 2] == ("punctuation", "=")
    ):
        return True
    if previous != ("punctuation", ")"):
        return (
            not expression_context
            and javascript_class_declaration_before_brace(tokens, opening)
        )
    if javascript_control_header_closed(tokens[:opening]):
        return True
    if javascript_function_declaration_before_brace(tokens, opening):
        return not expression_context
    return not expression_context and javascript_class_declaration_before_brace(tokens, opening)


def javascript_for_of_keyword(tokens: list[tuple[str, str]]) -> bool:
    """Return whether the last identifier is the `of` keyword in `for (... of`."""

    depth = 0
    for index in range(len(tokens) - 2, -1, -1):
        value = tokens[index][1]
        if value == ")":
            depth += 1
        elif value == "(":
            if depth == 0:
                previous = tokens[index - 1] if index else None
                if previous == ("identifier", "for"):
                    return True
                return (
                    index >= 2
                    and tokens[index - 1] == ("identifier", "await")
                    and tokens[index - 2] == ("identifier", "for")
                )
            depth -= 1
    return False


def javascript_regex_allowed(
    tokens: list[tuple[str, str]], *, expression_context: bool = False
) -> bool:
    """Return whether the next slash can begin a JavaScript regex literal."""

    cursor = len(tokens) - 1
    had_line_terminator = False
    while cursor >= 0 and tokens[cursor][0] == "newline":
        had_line_terminator = True
        cursor -= 1
    if cursor < 0:
        return True
    kind, value = tokens[cursor]
    if kind == "identifier":
        if value in {"break", "continue"}:
            return had_line_terminator
        # ``break label`` / ``continue label`` plus a line terminator is a
        # complete statement.  ASI then lets the next slash start a regex.
        if had_line_terminator:
            previous = cursor - 1
            while previous >= 0 and tokens[previous][0] == "newline":
                previous -= 1
            if previous >= 0 and tokens[previous][0] == "identifier" and tokens[previous][1] in {"break", "continue"}:
                return True
        if value == "debugger" and had_line_terminator:
            return True
        if value not in REGEX_PREFIX_KEYWORDS:
            return False
        previous = cursor - 1
        while previous >= 0 and tokens[previous][0] == "newline":
            previous -= 1
        if previous >= 0 and tokens[previous] == ("punctuation", "."):
            return False
        if value == "of":
            return javascript_for_of_keyword(tokens[: cursor + 1])
        return True
    if kind in {"number", "regex", "string", "template"} or value == "]":
        return False
    if value == "}":
        return javascript_statement_brace_closed(
            tokens[: cursor + 1], expression_context=expression_context
        )
    if value == ")":
        return javascript_control_header_closed(tokens[: cursor + 1])
    previous = cursor - 1
    while previous >= 0 and tokens[previous][0] == "newline":
        previous -= 1
    if value in {"+", "-"} and previous >= 0 and tokens[previous] == tokens[cursor]:
        return False
    return True


def consume_javascript_template(source: str, index: int, label: str) -> tuple[int, list[tuple[str, str]], bool]:
    interpolated: list[tuple[str, str]] = []
    has_interpolation = False
    cursor = index + 1
    while cursor < len(source):
        character = source[cursor]
        if character == "\\":
            cursor += 2
            continue
        if character == "`":
            return cursor + 1, interpolated, has_interpolation
        if source.startswith("${", cursor):
            has_interpolation = True
            inner, cursor = tokenize_javascript(source, cursor + 2, label, stop_at_unmatched_brace=True)
            interpolated.extend(inner)
            continue
        cursor += 1
    fail(f"{label} contains an unterminated JavaScript string")


def javascript_line_terminator(source: str, start: int) -> tuple[int, int] | None:
    positions = [source.find(terminator, start) for terminator in JAVASCRIPT_LINE_TERMINATORS]
    present = [index for index in positions if index >= 0]
    if not present:
        return None
    index = min(present)
    width = 2 if source.startswith("\r\n", index) else 1
    return index, width


def decode_javascript_unicode_escapes(value: str, label: str) -> str:
    def decode(match: re.Match[str]) -> str:
        codepoint = int(match.group(1) or match.group(2), 16)
        if codepoint > 0x10FFFF:
            fail(f"{label} contains an invalid JavaScript Unicode escape")
        return chr(codepoint)

    return JAVASCRIPT_UNICODE_ESCAPE.sub(decode, value)


def javascript_spacing_or_comment(
    source: str, index: int, label: str
) -> tuple[int, tuple[str, str] | None] | None:
    character = source[index]
    if character in JAVASCRIPT_LINE_TERMINATORS:
        width = 2 if source.startswith("\r\n", index) else 1
        return index + width, ("newline", "\n")
    if character.isspace():
        return index + 1, None
    if source.startswith("//", index):
        terminator = javascript_line_terminator(source, index + 2)
        return (len(source), None) if terminator is None else (
            terminator[0] + terminator[1],
            ("newline", "\n"),
        )
    if not source.startswith("/*", index):
        return None
    end = source.find("*/", index + 2)
    if end == -1:
        fail(f"{label} contains an unterminated JavaScript block comment")
    has_newline = any(value in source[index + 2:end] for value in JAVASCRIPT_LINE_TERMINATORS)
    return end + 2, (("newline", "\n") if has_newline else None)


def consume_javascript_quoted_string(
    source: str, index: int, label: str
) -> tuple[int, str]:
    quote = source[index]
    start = index + 1
    cursor = start
    escaped = False
    while cursor < len(source):
        current = source[cursor]
        if escaped:
            escaped = False
        elif current == "\\":
            escaped = True
        elif current == quote:
            value = decode_javascript_unicode_escapes(source[start:cursor], label)
            return cursor + 1, value
        cursor += 1
    fail(f"{label} contains an unterminated JavaScript string")


def javascript_literal_tokens(
    source: str,
    index: int,
    label: str,
    tokens: list[tuple[str, str]],
    expression_context: bool,
) -> tuple[int, list[tuple[str, str]]] | None:
    character = source[index]
    if character == "/" and javascript_regex_allowed(tokens, expression_context=expression_context):
        end = consume_javascript_regex(source, index)
        if end is not None:
            return end, [("regex", source[index:end])]
    if character == "`":
        end, interpolated, dynamic = consume_javascript_template(source, index, label)
        literal = source[index + 1:end - 1]
        value = literal if dynamic else decode_javascript_unicode_escapes(literal, label)
        return end, [*interpolated, ("template" if dynamic else "string", value)]
    if character in {"'", '"'}:
        end, value = consume_javascript_quoted_string(source, index, label)
        return end, [("string", value)]
    return None


def javascript_word_token(
    source: str, index: int, label: str
) -> tuple[int, tuple[str, str]] | None:
    character = source[index]
    if character == "\\" and JAVASCRIPT_UNICODE_ESCAPE.match(source, index):
        fail(f"{label} contains a Unicode escape in executable JavaScript syntax")
    if character.isdigit():
        allowed = {"_", "."}
        kind = "number"
    elif character.isalpha() or character in {"_", "$"}:
        allowed = {"_", "$"}
        kind = "identifier"
    else:
        return None
    end = index + 1
    while end < len(source) and (source[end].isalnum() or source[end] in allowed):
        end += 1
    return end, (kind, source[index:end])


def tokenize_javascript(
    source: str,
    index: int,
    label: str,
    *,
    stop_at_unmatched_brace: bool = False,
) -> tuple[list[tuple[str, str]], int]:
    """Tokenize source from index, optionally stopping at an unmatched `}`."""

    tokens: list[tuple[str, str]] = []
    depth = 1 if stop_at_unmatched_brace else 0
    while index < len(source):
        character = source[index]
        spacing = javascript_spacing_or_comment(source, index, label)
        if spacing is not None:
            index, token = spacing
            if token is not None:
                tokens.append(token)
            continue
        literal = javascript_literal_tokens(
            source, index, label, tokens, stop_at_unmatched_brace
        )
        if literal is not None:
            index, emitted = literal
            tokens.extend(emitted)
            continue
        word = javascript_word_token(source, index, label)
        if word is not None:
            index, token = word
            tokens.append(token)
            continue
        if stop_at_unmatched_brace and character == "{":
            depth += 1
        if stop_at_unmatched_brace and character == "}":
            depth -= 1
            if depth == 0:
                return tokens, index + 1
        tokens.append(("punctuation", character))
        index += 1
    if stop_at_unmatched_brace:
        fail(f"{label} contains an unterminated JavaScript template interpolation")
    return tokens, index


def javascript_contract_tokens(source: str, label: str) -> list[tuple[str, str]]:
    """Tokenize the small JavaScript subset used by static frontend checks.

    Marketplace validation must never import or execute a plugin archive.  The
    tokenizer deliberately recognizes comments, string/template literals and
    slash-delimited literals so an `activate` or RPC snippet merely written as
    data cannot satisfy the release contract. Slash tokens use their lexical
    expression context to distinguish regex literals from division operators.
    """

    tokens, _ = tokenize_javascript(source, 0, label)
    return tokens


def matching_brace(tokens: list[tuple[str, str]], opening_index: int) -> int | None:
    """Find the closing brace for a tokenized JavaScript block."""

    depth = 0
    for index in range(opening_index, len(tokens)):
        if tokens[index] == ("punctuation", "{"):
            depth += 1
        elif tokens[index] == ("punctuation", "}"):
            depth -= 1
            if depth == 0:
                return index
    return None


def matching_parenthesis(tokens: list[tuple[str, str]], opening_index: int) -> int | None:
    """Find the closing parenthesis for a tokenized JavaScript group."""

    depth = 0
    for index in range(opening_index, len(tokens)):
        if tokens[index] == ("punctuation", "("):
            depth += 1
        elif tokens[index] == ("punctuation", ")"):
            depth -= 1
            if depth == 0:
                return index
    return None


def matching_opening_parenthesis(tokens: list[tuple[str, str]], closing_index: int) -> int | None:
    """Find the opening parenthesis paired with a tokenized closing one."""

    depth = 0
    for index in range(closing_index, -1, -1):
        if tokens[index] == ("punctuation", ")"):
            depth += 1
        elif tokens[index] == ("punctuation", "("):
            depth -= 1
            if depth == 0:
                return index
    return None


def activate_body_tokens(tokens: list[tuple[str, str]]) -> list[tuple[str, str]] | None:
    """Return the exact exported ``activate(host)`` function body tokens."""

    for index, token in enumerate(tokens):
        if token != ("identifier", "export"):
            continue
        cursor = index + 1
        if cursor < len(tokens) and tokens[cursor] == ("identifier", "async"):
            cursor += 1
        if tokens[cursor:cursor + 6] != [
            ("identifier", "function"),
            ("identifier", "activate"),
            ("punctuation", "("),
            ("identifier", "host"),
            ("punctuation", ")"),
            ("punctuation", "{"),
        ]:
            continue
        closing = matching_brace(tokens, cursor + 5)
        if closing is not None:
            return tokens[cursor + 6:closing]
    return None


def enclosing_named_function(index: int, blocks: list[tuple[str, int, int, int]]) -> int | None:
    """Return the innermost named function body containing a token index."""

    candidates = [
        block_index
        for block_index, (_, _, opening_brace, closing_brace) in enumerate(blocks)
        if opening_brace < index < closing_brace
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda block_index: blocks[block_index][3] - blocks[block_index][2])


def activation_lifecycle_method_blocks(
    tokens: list[tuple[str, str]],
    named_blocks: list[tuple[str, int, int, int]],
    unsupported_blocks: list[tuple[int, int]],
) -> set[tuple[int, int]]:
    """Return mount/update/dispose methods on an activation's returned object."""

    blocks: set[tuple[int, int]] = set()
    for index in range(len(tokens) - 1):
        if tokens[index:index + 2] != [
            ("identifier", "return"),
            ("punctuation", "{"),
        ] or (
            enclosing_named_function(index, named_blocks) is not None
            or is_in_block(index, unsupported_blocks)
        ):
            continue
        object_closing = matching_brace(tokens, index + 1)
        if object_closing is None:
            continue
        brace_depth = 1
        parenthesis_depth = 0
        bracket_depth = 0
        for method_index in range(index + 2, object_closing):
            kind, name = tokens[method_index]
            if (
                brace_depth == 1
                and parenthesis_depth == 0
                and bracket_depth == 0
                and kind == "identifier"
                and name in APPROVALS_FRONTEND_LIFECYCLE_METHODS
                and method_index + 1 < object_closing
                and tokens[method_index + 1] == ("punctuation", "(")
            ):
                parameter_closing = matching_parenthesis(tokens, method_index + 1)
                if (
                    parameter_closing is not None
                    and parameter_closing + 1 < object_closing
                    and tokens[parameter_closing + 1] == ("punctuation", "{")
                ):
                    method_closing = matching_brace(tokens, parameter_closing + 1)
                    if method_closing is not None and method_closing < object_closing:
                        blocks.add((parameter_closing + 1, method_closing))
            if tokens[method_index] == ("punctuation", "{"):
                brace_depth += 1
            elif tokens[method_index] == ("punctuation", "}"):
                brace_depth -= 1
            elif tokens[method_index] == ("punctuation", "("):
                parenthesis_depth += 1
            elif tokens[method_index] == ("punctuation", ")") and parenthesis_depth:
                parenthesis_depth -= 1
            elif tokens[method_index] == ("punctuation", "["):
                bracket_depth += 1
            elif tokens[method_index] == ("punctuation", "]") and bracket_depth:
                bracket_depth -= 1
    return blocks


def is_in_block(index: int, blocks: list[tuple[int, int]]) -> bool:
    return any(opening_brace < index < closing_brace for opening_brace, closing_brace in blocks)


def conditional_branch_end(tokens: list[tuple[str, str]], body_start: int) -> int:
    """Return the exclusive end of a compact ``if``/``else`` statement body."""

    while body_start < len(tokens) and tokens[body_start] == ("newline", "\n"):
        body_start += 1
    if body_start >= len(tokens):
        return len(tokens)
    if tokens[body_start] == ("punctuation", "{"):
        closing_brace = matching_brace(tokens, body_start)
        return len(tokens) if closing_brace is None else closing_brace + 1
    brace_depth = 0
    parenthesis_depth = 0
    bracket_depth = 0
    for cursor in range(body_start, len(tokens)):
        current = tokens[cursor]
        if current == ("punctuation", "{"):
            brace_depth += 1
        elif current == ("punctuation", "}") and brace_depth:
            brace_depth -= 1
        elif current == ("punctuation", "("):
            parenthesis_depth += 1
        elif current == ("punctuation", ")") and parenthesis_depth:
            parenthesis_depth -= 1
        elif current == ("punctuation", "["):
            bracket_depth += 1
        elif current == ("punctuation", "]") and bracket_depth:
            bracket_depth -= 1
        elif (
            current == ("punctuation", ";")
            and brace_depth == 0
            and parenthesis_depth == 0
            and bracket_depth == 0
        ):
            return cursor
    return len(tokens)


def is_in_statically_unreachable_if_branch(tokens: list[tuple[str, str]], index: int) -> bool:
    """Reject literal-Boolean ``if`` branches that cannot execute."""

    for cursor in range(len(tokens) - 4):
        if tokens[cursor:cursor + 2] != [
            ("identifier", "if"),
            ("punctuation", "("),
        ]:
            continue
        condition = tokens[cursor + 2]
        if condition not in {("identifier", "false"), ("identifier", "true")} or tokens[cursor + 3] != ("punctuation", ")"):
            continue
        body_start = cursor + 4
        while body_start < len(tokens) and tokens[body_start] == ("newline", "\n"):
            body_start += 1
        body_end = conditional_branch_end(tokens, body_start)
        if condition == ("identifier", "false") and body_start <= index < body_end:
            return True
        else_cursor = body_end
        if else_cursor < len(tokens) and tokens[else_cursor] == ("punctuation", ";"):
            else_cursor += 1
        while else_cursor < len(tokens) and tokens[else_cursor] == ("newline", "\n"):
            else_cursor += 1
        if (
            condition == ("identifier", "true")
            and else_cursor < len(tokens)
            and tokens[else_cursor] == ("identifier", "else")
        ):
            alternate_start = else_cursor + 1
            while alternate_start < len(tokens) and tokens[alternate_start] == ("newline", "\n"):
                alternate_start += 1
            alternate_end = conditional_branch_end(tokens, alternate_start)
            if alternate_start <= index < alternate_end:
                return True
    return False


def is_in_statically_unreachable_loop_body(tokens: list[tuple[str, str]], index: int) -> bool:
    """Reject evidence in loop bodies whose literal condition prevents entry."""

    for cursor in range(len(tokens) - 4):
        if tokens[cursor] == ("identifier", "while") and tokens[cursor + 1] == ("punctuation", "("):
            closing = matching_parenthesis(tokens, cursor + 1)
            if (
                closing is not None
                and tokens[cursor + 2:closing] == [("identifier", "false")]
            ):
                body_start = closing + 1
                while body_start < len(tokens) and tokens[body_start] == ("newline", "\n"):
                    body_start += 1
                body_end = conditional_branch_end(tokens, body_start)
                if body_start <= index < body_end:
                    return True
        if tokens[cursor] == ("identifier", "for") and tokens[cursor + 1] == ("punctuation", "("):
            closing = matching_parenthesis(tokens, cursor + 1)
            if (
                closing is not None
                and tokens[cursor + 2:cursor + 5] == [
                    ("punctuation", ";"),
                    ("identifier", "false"),
                    ("punctuation", ";"),
                ]
            ):
                body_start = closing + 1
                while body_start < len(tokens) and tokens[body_start] == ("newline", "\n"):
                    body_start += 1
                body_end = conditional_branch_end(tokens, body_start)
                update_start = cursor + 5
                if update_start <= index < closing or body_start <= index < body_end:
                    return True
    return False


def is_in_function_like_parameters(tokens: list[tuple[str, str]], index: int) -> bool:
    """Exclude unproved defaults from function, method, and arrow parameters."""

    for cursor, token in enumerate(tokens):
        if token == ("identifier", "function"):
            parameter_start = cursor + 1
            if parameter_start < len(tokens) and tokens[parameter_start] == ("punctuation", "*"):
                parameter_start += 1
            if parameter_start < len(tokens) and tokens[parameter_start][0] == "identifier":
                parameter_start += 1
            if parameter_start < len(tokens) and tokens[parameter_start] == ("punctuation", "("):
                parameter_end = matching_parenthesis(tokens, parameter_start)
                if parameter_end is not None and parameter_start < index < parameter_end:
                    return True
        # Parenthesized arrows: ``(value = expression) =>``.  We only need to
        # reject their parameter initializers, never execute or resolve them.
        if token == ("punctuation", "=") and cursor + 1 < len(tokens) and tokens[cursor + 1] == ("punctuation", ">"):
            parameter_end = cursor - 1
            if parameter_end >= 0 and tokens[parameter_end] == ("punctuation", ")"):
                parameter_start = matching_opening_parenthesis(tokens, parameter_end)
                if parameter_start is not None and parameter_start < index < parameter_end:
                    return True
        # Method-shaped declarations: ``method(value = expression) {}``.  Do
        # not mistake a control-flow condition for a method parameter list.
        if token == ("punctuation", "(") and cursor and tokens[cursor - 1][0] == "identifier":
            name = tokens[cursor - 1][1]
            if name in {"if", "for", "while", "switch", "catch", "with"}:
                continue
            parameter_end = matching_parenthesis(tokens, cursor)
            if (
                parameter_end is not None
                and parameter_end + 1 < len(tokens)
                and tokens[parameter_end + 1] == ("punctuation", "{")
                and cursor < index < parameter_end
            ):
                return True
    return False


def is_in_statically_unreachable_expression(tokens: list[tuple[str, str]], index: int) -> bool:
    """Reject evidence guarded by literal short-circuit or ternary branches.

    This deliberately recognizes only compact literal forms that can make a
    syntactically present broker request unconditionally unreachable.  The
    official frontend has no such expressions, so uncertainty remains
    fail-closed without implementing JavaScript's whole expression grammar.
    """

    # A semicolon ends the preceding expression.  Newlines do not: JavaScript
    # permits ``false &&\\n host.request(...)`` to continue the expression.
    statement_start = index
    while statement_start > 0:
        previous = tokens[statement_start - 1]
        if previous == ("punctuation", ";"):
            break
        statement_start -= 1
    for cursor in range(statement_start, index - 2):
        if tokens[cursor:cursor + 3] == [
            ("identifier", "false"),
            ("punctuation", "&"),
            ("punctuation", "&"),
        ]:
            return True
        if tokens[cursor:cursor + 3] == [
            ("identifier", "true"),
            ("punctuation", "|"),
            ("punctuation", "|"),
        ]:
            return True

    # For ``false ? consequent : alternate`` evidence in the consequent is
    # unreachable; for ``true ? consequent : alternate`` the alternate is.
    # Pick the nearest literal Boolean condition before the request and track
    # whether a matching top-level colon has started its alternate branch.
    # Nested ternaries are skipped conservatively.
    for question in range(index - 1, statement_start, -1):
        if tokens[question] != ("punctuation", "?") or question == 0:
            continue
        condition = tokens[question - 1]
        if condition not in {("identifier", "false"), ("identifier", "true")}:
            continue
        ternary_depth = 0
        delimiter_depth = 0
        alternate_started = False
        for cursor in range(question + 1, index):
            token = tokens[cursor]
            if token in {
                ("punctuation", "("),
                ("punctuation", "["),
                ("punctuation", "{"),
            }:
                delimiter_depth += 1
            elif token in {
                ("punctuation", ")"),
                ("punctuation", "]"),
                ("punctuation", "}"),
            } and delimiter_depth:
                delimiter_depth -= 1
            elif delimiter_depth == 0 and token == ("punctuation", "?"):
                ternary_depth += 1
            elif delimiter_depth == 0 and token == ("punctuation", ":"):
                if ternary_depth:
                    ternary_depth -= 1
                else:
                    alternate_started = True
                    break
        if condition == ("identifier", "false") and not alternate_started:
            return True
        if condition == ("identifier", "true") and alternate_started:
            return True
    return False


def lexical_declaration_shadows_helper(tokens: list[tuple[str, str]], name: str) -> bool:
    """Fail closed when a lexical binding could shadow a helper call.

    A full JavaScript scope resolver is intentionally outside this static,
    non-executing verifier.  A ``const``, ``let``, or ``var`` declaration sharing a
    helper name is enough ambiguity to reject every matching call edge.  This
    also handles a declaration later in the block, whose temporal-dead-zone
    semantics make an earlier call fail instead of reaching the function.
    This is stricter than JavaScript's exact block-scope rules but the official
    source has no such collisions.
    """

    for cursor in range(len(tokens) - 1):
        if tokens[cursor] not in {
            ("identifier", "const"),
            ("identifier", "let"),
            ("identifier", "var"),
        }:
            continue
        if tokens[cursor + 1:cursor + 2] == [("identifier", name)]:
            return True
    return False


def declarations_bind_host(tokens: list[tuple[str, str]], start: int, end: int) -> bool:
    """Conservatively reject local declarations that shadow the broker name."""

    for index in range(start, end):
        token = tokens[index]
        if token in {
            ("identifier", "function"),
            ("identifier", "class"),
        } and index + 1 < end and tokens[index + 1] == ("identifier", "host"):
            return True
        if token not in {
            ("identifier", "const"),
            ("identifier", "let"),
            ("identifier", "var"),
        }:
            continue
        cursor = index + 1
        delimiter_depth = 0
        while cursor < end:
            current = tokens[cursor]
            if current in {("punctuation", "{"), ("punctuation", "["), ("punctuation", "(")}:
                delimiter_depth += 1
            elif current in {("punctuation", "}"), ("punctuation", "]"), ("punctuation", ")")} and delimiter_depth:
                delimiter_depth -= 1
            elif delimiter_depth == 0 and current in {("punctuation", "="), ("punctuation", ";")}:
                break
            if current == ("identifier", "host"):
                return True
            cursor += 1
    return False


def block_binds_host(tokens: list[tuple[str, str]], block: tuple[str, int, int, int]) -> bool:
    """Return whether an eligible helper shadows activation's ``host``."""

    _, declaration_start, opening_brace, closing_brace = block
    cursor = declaration_start + (tokens[declaration_start] == ("identifier", "async"))
    parameter_opening = cursor + 2
    parameter_closing = matching_parenthesis(tokens, parameter_opening)
    if parameter_closing is not None and ("identifier", "host") in tokens[parameter_opening + 1:parameter_closing]:
        return True
    return declarations_bind_host(tokens, opening_brace + 1, closing_brace)


def lifecycle_block_binds_host(tokens: list[tuple[str, str]], block: tuple[int, int]) -> bool:
    """Return whether a returned lifecycle method shadows activation's host."""

    opening_brace, closing_brace = block
    parameter_closing = opening_brace - 1
    parameter_opening = matching_opening_parenthesis(tokens, parameter_closing)
    if parameter_opening is not None and ("identifier", "host") in tokens[parameter_opening + 1:parameter_closing]:
        return True
    return declarations_bind_host(tokens, opening_brace + 1, closing_brace)


def is_after_unconditional_return(
    tokens: list[tuple[str, str]],
    index: int,
    scope_start: int,
    scope_end: int,
) -> bool:
    """Return whether a completed direct-scope return precedes ``index``."""

    brace_depth = 0
    parenthesis_depth = 0
    bracket_depth = 0
    for cursor in range(scope_start, min(index, scope_end)):
        token = tokens[cursor]
        if token == ("punctuation", "{"):
            brace_depth += 1
        elif token == ("punctuation", "}") and brace_depth:
            brace_depth -= 1
        elif token == ("punctuation", "("):
            parenthesis_depth += 1
        elif token == ("punctuation", ")") and parenthesis_depth:
            parenthesis_depth -= 1
        elif token == ("punctuation", "["):
            bracket_depth += 1
        elif token == ("punctuation", "]") and bracket_depth:
            bracket_depth -= 1
        elif (
            token in {
                ("identifier", "return"),
                ("identifier", "throw"),
            }
            and brace_depth == 0
            and parenthesis_depth == 0
            and bracket_depth == 0
        ):
            expression_braces = 0
            expression_parentheses = 0
            expression_brackets = 0
            expression_started = False
            for end in range(cursor + 1, min(index, scope_end)):
                current = tokens[end]
                if current == ("newline", "\n"):
                    if not expression_started or (
                        expression_braces == 0
                        and expression_parentheses == 0
                        and expression_brackets == 0
                    ):
                        return True
                    continue
                expression_started = True
                if current == ("punctuation", "{"):
                    expression_braces += 1
                elif current == ("punctuation", "}") and expression_braces:
                    expression_braces -= 1
                elif current == ("punctuation", "("):
                    expression_parentheses += 1
                elif current == ("punctuation", ")") and expression_parentheses:
                    expression_parentheses -= 1
                elif current == ("punctuation", "["):
                    expression_brackets += 1
                elif current == ("punctuation", "]") and expression_brackets:
                    expression_brackets -= 1
                elif (
                    current == ("punctuation", ";")
                    and expression_braces == 0
                    and expression_parentheses == 0
                    and expression_brackets == 0
                ):
                    return True
    return False


def host_is_reassigned_before(
    tokens: list[tuple[str, str]],
    index: int,
    scope_start: int,
) -> bool:
    """Conservatively detect a prior write to the bare broker binding."""

    for cursor in range(scope_start, index):
        if tokens[cursor] != ("identifier", "host"):
            continue
        if cursor and tokens[cursor - 1] == ("punctuation", "."):
            continue
        following = tokens[cursor + 1:cursor + 3]
        if following[:1] == [("punctuation", "=")]:
            return True
        if tuple(following[:2]) in {
            (("punctuation", "+"), ("punctuation", "=")),
            (("punctuation", "-"), ("punctuation", "=")),
            (("punctuation", "*"), ("punctuation", "=")),
            (("punctuation", "/"), ("punctuation", "=")),
            (("punctuation", "%"), ("punctuation", "=")),
            (("punctuation", "&"), ("punctuation", "=")),
            (("punctuation", "|"), ("punctuation", "=")),
            (("punctuation", "^"), ("punctuation", "=")),
            (("punctuation", "+"), ("punctuation", "+")),
            (("punctuation", "-"), ("punctuation", "-")),
        }:
            return True
        if tuple(tokens[cursor + 1:cursor + 4]) in {
            (("punctuation", "&"), ("punctuation", "&"), ("punctuation", "=")),
            (("punctuation", "|"), ("punctuation", "|"), ("punctuation", "=")),
            (("punctuation", "?"), ("punctuation", "?"), ("punctuation", "=")),
            (("punctuation", "*"), ("punctuation", "*"), ("punctuation", "=")),
            (("punctuation", "<"), ("punctuation", "<"), ("punctuation", "=")),
            (("punctuation", ">"), ("punctuation", ">"), ("punctuation", "=")),
        }:
            return True
        if tuple(tokens[cursor + 1:cursor + 5]) == (
            ("punctuation", ">"),
            ("punctuation", ">"),
            ("punctuation", ">"),
            ("punctuation", "="),
        ):
            return True
        if tuple(tokens[cursor - 2:cursor]) in {
            (("punctuation", "+"), ("punctuation", "+")),
            (("punctuation", "-"), ("punctuation", "-")),
        }:
            return True
    return False


def reachable_named_functions(
    tokens: list[tuple[str, str]],
    blocks: list[tuple[str, int, int, int]],
    unsupported_blocks: list[tuple[int, int]],
    lifecycle_blocks: set[tuple[int, int]],
) -> set[int]:
    """Build a conservative call graph rooted at activation lifecycle code."""

    by_name: dict[str, list[int]] = {}
    for block_index, (name, _, _, _) in enumerate(blocks):
        by_name.setdefault(name, []).append(block_index)
    if any(len(block_indexes) != 1 for block_indexes in by_name.values()):
        return set()
    reachable: set[int] = set()
    pending: list[int] = []
    edges: dict[int, set[int]] = {block_index: set() for block_index in range(len(blocks))}

    for index in range(len(tokens) - 1):
        kind, value = tokens[index]
        if kind != "identifier" or value not in by_name or tokens[index + 1] != ("punctuation", "("):
            continue
        # Only a bare ``helper(...)`` call can establish an edge.  A member
        # call such as ``other.helper(...)`` might target a distinct method
        # with the same spelling and must not make a nested helper reachable.
        if index and tokens[index - 1] == ("punctuation", "."):
            continue
        closing_parenthesis = matching_parenthesis(tokens, index + 1)
        # ``{ helper() {} }`` is an object-method declaration, not an
        # invocation of the same-named ordinary helper.
        if (
            closing_parenthesis is not None
            and closing_parenthesis + 1 < len(tokens)
            and tokens[closing_parenthesis + 1] == ("punctuation", "{")
        ):
            continue
        # The declaration's own ``name(...)`` is not a call edge.
        if any(declaration_start <= index <= opening_brace for _, declaration_start, opening_brace, _ in blocks):
            continue
        # A call captured by an unsupported closure cannot establish a
        # reachability proof for a named helper.
        if is_in_block(index, unsupported_blocks):
            continue
        if is_in_statically_unreachable_if_branch(tokens, index) or is_in_statically_unreachable_expression(tokens, index):
            continue
        if lexical_declaration_shadows_helper(tokens, value):
            continue
        caller = enclosing_named_function(index, blocks)
        lifecycle_owner = next(
            (block for block in lifecycle_blocks if block[0] < index < block[1]),
            None,
        )
        if caller is None and lifecycle_owner is None and (
            is_after_unconditional_return(tokens, index, 0, len(tokens))
            or host_is_reassigned_before(tokens, index, 0)
        ):
            continue
        if lifecycle_owner is not None and (
            is_after_unconditional_return(tokens, index, lifecycle_owner[0] + 1, lifecycle_owner[1])
            or host_is_reassigned_before(tokens, index, lifecycle_owner[0] + 1)
            or host_is_reassigned_before(tokens, lifecycle_owner[0], 0)
        ):
            continue
        for callee in by_name[value]:
            if caller is None:
                reachable.add(callee)
                pending.append(callee)
            else:
                edges[caller].add(callee)

    while pending:
        caller = pending.pop()
        for callee in edges[caller]:
            if callee not in reachable:
                reachable.add(callee)
                pending.append(callee)
    return reachable


def declared_approvals_rpc_calls(tokens: list[tuple[str, str]]) -> set[str]:
    named_blocks = named_javascript_function_blocks(tokens)
    provisional_unsupported_blocks = unsupported_javascript_function_blocks(tokens, set())
    lifecycle_blocks = activation_lifecycle_method_blocks(tokens, named_blocks, provisional_unsupported_blocks)
    unsupported_blocks = unsupported_javascript_function_blocks(tokens, lifecycle_blocks)
    reachable_blocks = reachable_named_functions(tokens, named_blocks, unsupported_blocks, lifecycle_blocks)
    calls: set[str] = set()
    for index in range(len(tokens) - 4):
        sequence = tokens[index:index + 5]
        if sequence[:4] != [
            ("identifier", "host"),
            ("punctuation", "."),
            ("identifier", "request"),
            ("punctuation", "("),
        ]:
            continue
        if is_in_function_like_parameters(tokens, index):
            continue
        if is_in_block(index, unsupported_blocks):
            continue
        if (
            is_in_statically_unreachable_if_branch(tokens, index)
            or is_in_statically_unreachable_loop_body(tokens, index)
            or is_in_statically_unreachable_expression(tokens, index)
        ):
            continue
        owner = enclosing_named_function(index, named_blocks)
        if owner is not None and (
            owner not in reachable_blocks
            or block_binds_host(tokens, named_blocks[owner])
            or is_after_unconditional_return(tokens, index, named_blocks[owner][2] + 1, named_blocks[owner][3])
            or host_is_reassigned_before(tokens, index, named_blocks[owner][2] + 1)
        ):
            continue
        if owner is None:
            lifecycle_owner = next(
                (block for block in lifecycle_blocks if block[0] < index < block[1]),
                None,
            )
            if lifecycle_owner is not None:
                if (
                    lifecycle_block_binds_host(tokens, lifecycle_owner)
                    or is_after_unconditional_return(tokens, index, lifecycle_owner[0] + 1, lifecycle_owner[1])
                    or host_is_reassigned_before(tokens, index, lifecycle_owner[0] + 1)
                    or host_is_reassigned_before(tokens, lifecycle_owner[0], 0)
                ):
                    continue
            elif (
                declarations_bind_host(tokens, 0, len(tokens))
                or is_after_unconditional_return(tokens, index, 0, len(tokens))
                or host_is_reassigned_before(tokens, index, 0)
            ):
                continue
        kind, method = sequence[4]
        if kind == "string" and method in APPROVALS_FRONTEND_METHODS:
            calls.add(method)
    return calls


def has_only_approvals_host_usage(tokens: list[tuple[str, str]]) -> bool:
    """Keep the official approvals frontend's broker surface deliberately tiny."""

    for index, token in enumerate(tokens):
        # Dynamic evaluators make lexical `host` provenance unverifiable
        # without executing untrusted code.  The official frontend neither
        # needs nor permits them, so reject bare direct calls outright.
        if (
            token in {("identifier", "eval"), ("identifier", "Function")}
            and index + 1 < len(tokens)
            and tokens[index + 1] == ("punctuation", "(")
            and (index == 0 or tokens[index - 1] != ("punctuation", "."))
        ):
            return False
        if token != ("identifier", "host"):
            continue
        suffix = tokens[index + 1:index + 5]
        if suffix[:1] == [("punctuation", ")")]:
            # The reviewed activation routes the isolated settings context to
            # its local settings-page renderer.  The source hash below keeps
            # that hand-off explicit rather than permitting arbitrary host use.
            continue
        if suffix[:2] == [
            ("punctuation", "."),
            ("identifier", "context"),
        ]:
            continue
        if len(suffix) >= 3 and suffix[:3] == [
            ("punctuation", "."),
            ("identifier", "onTheme"),
            ("punctuation", "("),
        ]:
            continue
        if len(suffix) >= 4 and suffix[:3] == [
            ("punctuation", "."),
            ("identifier", "request"),
            ("punctuation", "("),
        ]:
            method_kind, method = suffix[3]
            if method_kind == "string" and method in APPROVALS_FRONTEND_METHODS:
                continue
        return False
    return True


def validate_javascript_esm_syntax(source: str, label: str) -> None:
    """Parse a frontend as ESM without importing or executing archive code."""

    node = shutil.which("node")
    if node is None:
        fail(f"{label} requires Node.js to validate ESM syntax")
    environment = os.environ.copy()
    # Do not let a caller-provided preload influence this parse-only process.
    environment.pop("NODE_OPTIONS", None)
    environment.pop("NODE_PATH", None)
    try:
        with tempfile.TemporaryDirectory(prefix="xsec-market-esm-check-") as directory:
            candidate = Path(directory) / "frontend.mjs"
            candidate.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [node, "--check", str(candidate)],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                timeout=JAVASCRIPT_SYNTAX_CHECK_TIMEOUT_SECONDS,
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"{label} ESM syntax validation could not run: {error}")
    if result.returncode != 0:
        fail(f"{label} must contain valid executable ESM syntax")


def validate_approvals_frontend(manifest: dict[str, object], source: str, label: str) -> None:
    """Verify the first non-placeholder official frontend release contract.

    This is deliberately a static, fail-closed check: marketplace validation
    must not execute an archive's untrusted JavaScript.  The manifest metadata
    and basic ESM shape are validated independently; the official approvals
    implementation itself is an exact reviewed-source allowlist, rather than
    an attempted proof of arbitrary JavaScript reachability.  The Desktop host
    remains responsible for manifest-derived permission checks at execution.
    """

    if manifest.get("name") != APPROVALS_PLUGIN_ID:
        return
    try:
        desktop = manifest["extensions"]["com.xsec.desktop"]
    except (KeyError, TypeError):
        fail(f"{label} lacks XSEC Desktop extension metadata")
    if not isinstance(desktop, dict):
        fail(f"{label} has invalid XSEC Desktop extension metadata")
    permissions = desktop.get("permissions")
    if not isinstance(permissions, dict) or not {"workspace.session.read", "pluginData.read", "pluginData.write"}.issubset(permissions):
        fail(f"{label} must declare the approvals session read permission and plugin settings permissions")
    engines = desktop.get("engines")
    if not isinstance(engines, dict) or engines.get("pluginApi") != APPROVALS_FRONTEND_PLUGIN_API_RANGE:
        fail(f"{label} must require plugin API 1.2 for the approvals frontend")
    activation_events = desktop.get("activationEvents")
    if not isinstance(activation_events, list) or APPROVALS_WORKSPACE_TOOL_ACTIVATION_EVENT not in activation_events:
        fail(f"{label} must declare the approvals workspace-tool activation event")
    contributes = desktop.get("contributes")
    workspace_tools = contributes.get("workspaceTools") if isinstance(contributes, dict) else None
    if (
        not isinstance(workspace_tools, dict)
        or workspace_tools.get("approvals") != APPROVALS_WORKSPACE_TOOL_CONTRIBUTION
    ):
        fail(f"{label} must declare the canonical approvals workspace-tool contribution")
    frontend_api = desktop.get("frontendApi")
    if not isinstance(frontend_api, dict) or frontend_api.get("version") != 2 or frontend_api.get("module") != "single-esm":
        fail(f"{label} must declare the approvals frontend API v2 single-esm contract")
    methods = frontend_api.get("methods")
    if not isinstance(methods, dict) or set(methods) != APPROVALS_FRONTEND_METHODS:
        fail(f"{label} must declare the approvals read RPC methods")
    for method, (capability, binding) in APPROVALS_FRONTEND_METHOD_CONTRACT.items():
        descriptor = methods.get(method)
        if not isinstance(descriptor, dict) or descriptor.get("capability") != capability or descriptor.get("binding") != binding:
            fail(f"{label} must bind approvals RPC methods to the session read capability or reviewed plugin settings scope ({method})")
    if re.search(r"\\u(?:[0-9A-Fa-f]{4}|\{[0-9A-Fa-f]+\})", source):
        fail(f"{label} must not contain Unicode escape sequences")
    validate_javascript_esm_syntax(source, label)
    tokens = javascript_contract_tokens(source, label)
    body = activate_body_tokens(tokens)
    if body is None:
        fail(f"{label} must export an executable activate(host) function")
    if not has_only_approvals_host_usage(body):
        fail(f"{label} must use only the approvals host broker contract")
    normalized_source = source.replace("\r\n", "\n").replace("\r", "\n")
    version = manifest.get("version")
    expected_source_sha256 = APPROVALS_FRONTEND_SOURCE_SHA256_BY_VERSION.get(version)
    if expected_source_sha256 is None:
        fail(f"{label} uses an approvals version without an approved frontend source digest")
    if hashlib.sha256(normalized_source.encode("utf-8")).hexdigest() != expected_source_sha256:
        fail(f"{label} must match the approved official approvals frontend structure")


def frontend_string_constants(tokens: list[tuple[str, str]]) -> dict[str, str]:
    dense = [token for token in tokens if token[0] != "newline"]
    constants: dict[str, str] = {}
    ambiguous: set[str] = set()
    for index in range(len(dense) - 3):
        declaration = dense[index:index + 4]
        if (
            declaration[0] == ("identifier", "const")
            and declaration[1][0] == "identifier"
            and declaration[2] == ("punctuation", "=")
            and declaration[3][0] == "string"
        ):
            if index + 4 < len(dense):
                next_kind, next_value = dense[index + 4]
                if next_kind != "punctuation" or next_value not in CONST_INITIALIZER_TERMINATORS:
                    continue
            name, value = declaration[1][1], declaration[3][1]
            if name in constants and constants[name] != value:
                ambiguous.add(name)
            else:
                constants[name] = value
    return {name: value for name, value in constants.items() if name not in ambiguous}


def matching_square_bracket(tokens: list[tuple[str, str]], opening_index: int) -> int | None:
    depth = 0
    for index in range(opening_index, len(tokens)):
        if tokens[index] == ("punctuation", "["):
            depth += 1
        elif tokens[index] == ("punctuation", "]"):
            depth -= 1
            if depth == 0:
                return index
    return None


def static_rpc_array_values(
    tokens: list[tuple[str, str]], opening: int, closing: int
) -> dict[str, str] | None:
    values: dict[str, str] = {}
    cursor = opening + 1
    while cursor < closing:
        if tokens[cursor] == ("punctuation", ","):
            cursor += 1
            continue
        entry = static_rpc_array_entry(tokens, cursor, closing)
        if entry is None:
            return None
        property_name, value, cursor = entry
        if property_name in values:
            return None
        values[property_name] = value
    return values or None


def static_rpc_array_entry(
    tokens: list[tuple[str, str]], cursor: int, closing: int
) -> tuple[str, str, int] | None:
    if tokens[cursor][0] not in {"identifier", "string"}:
        return None
    if tokens[cursor + 1:cursor + 3] != [("punctuation", ":"), ("punctuation", "[")]:
        return None
    array_closing = matching_square_bracket(tokens, cursor + 2)
    if array_closing is None or array_closing >= closing:
        return None
    value = tokens[cursor + 3]
    if value[0] != "string" or not re.fullmatch(r"xsec\.[A-Za-z0-9_.-]+", value[1]):
        return None
    if tokens[cursor + 4] not in {("punctuation", ","), ("punctuation", "]")}:
        return None
    return tokens[cursor][1], value[1], array_closing + 1


def static_rpc_array_objects(tokens: list[tuple[str, str]]) -> dict[str, dict[str, str]]:
    objects: dict[str, dict[str, str]] = {}
    for index in range(len(tokens) - 3):
        if (
            tokens[index] != ("identifier", "const")
            or tokens[index + 1][0] != "identifier"
            or tokens[index + 2:index + 4] != [("punctuation", "="), ("punctuation", "{")]
        ):
            continue
        closing = matching_brace(tokens, index + 3)
        values = static_rpc_array_values(tokens, index + 3, closing) if closing is not None else None
        if values:
            objects[tokens[index + 1][1]] = values
    return objects


def frontend_rpc_selector(
    tokens: list[tuple[str, str]], source_index: int, properties: dict[str, str]
) -> tuple[set[str] | None, int]:
    cursor = source_index + 1
    if tokens[cursor:cursor + 1] == [("punctuation", ".")]:
        if cursor + 1 >= len(tokens) or tokens[cursor + 1][0] != "identifier":
            return None, cursor
        value = properties.get(tokens[cursor + 1][1])
        return ({value} if value else None), cursor + 2
    if tokens[cursor:cursor + 1] != [("punctuation", "[")]:
        return None, cursor
    closing = matching_square_bracket(tokens, cursor)
    if closing is None:
        return None, cursor
    key_tokens = tokens[cursor + 1:closing]
    if len(key_tokens) == 1 and key_tokens[0][0] == "string":
        value = properties.get(key_tokens[0][1])
        return ({value} if value else None), closing + 1
    return set(properties.values()), closing + 1


def frontend_rpc_destructuring(
    tokens: list[tuple[str, str]], index: int
) -> tuple[str, int, int] | None:
    if tokens[index:index + 2] != [("identifier", "const"), ("punctuation", "[")]:
        return None
    closing = matching_square_bracket(tokens, index + 1)
    if closing is None or tokens[index + 2][0] != "identifier":
        return None
    if closing + 2 >= len(tokens) or tokens[closing + 1] != ("punctuation", "="):
        return None
    return tokens[index + 2][1], closing + 2, closing


def frontend_rpc_bindings(tokens: list[tuple[str, str]]) -> dict[str, set[str]]:
    bindings = {name: {value} for name, value in frontend_string_constants(tokens).items()}
    objects = static_rpc_array_objects(tokens)
    for index in range(len(tokens) - 4):
        destructuring = frontend_rpc_destructuring(tokens, index)
        if destructuring is None:
            continue
        target, source_index, _ = destructuring
        source = tokens[source_index][1] if tokens[source_index][0] == "identifier" else ""
        properties = objects.get(source)
        if not properties:
            continue
        selected, rhs_end = frontend_rpc_selector(tokens, source_index, properties)
        if rhs_end >= len(tokens) or tokens[rhs_end] not in {
            ("punctuation", ";"),
            ("punctuation", ","),
            ("punctuation", "}"),
        }:
            continue
        if selected:
            bindings[target] = selected
    return bindings


def frontend_named_function_blocks(tokens: list[tuple[str, str]]) -> dict[str, tuple[int, int]]:
    """Index ordinary named function declarations by their source span."""

    blocks: dict[str, tuple[int, int]] = {}
    for index, token in enumerate(tokens):
        if token != ("identifier", "function"):
            continue
        cursor = index + 1
        if cursor < len(tokens) and tokens[cursor] == ("punctuation", "*"):
            cursor += 1
        if cursor >= len(tokens) or tokens[cursor][0] != "identifier":
            continue
        name = tokens[cursor][1]
        opening = cursor + 1
        if opening >= len(tokens) or tokens[opening] != ("punctuation", "("):
            continue
        parameter_closing = matching_parenthesis(tokens, opening)
        if parameter_closing is None or parameter_closing + 1 >= len(tokens):
            continue
        body_opening = parameter_closing + 1
        if tokens[body_opening] != ("punctuation", "{"):
            continue
        body_closing = matching_brace(tokens, body_opening)
        if body_closing is not None:
            # Duplicate names are ambiguous; dropping them causes callers to
            # remain outside the reachability proof and fail closed.
            if name in blocks:
                blocks.pop(name)
            else:
                blocks[name] = (index, body_closing)
    return blocks


def frontend_activation_body_range(tokens: list[tuple[str, str]]) -> tuple[int, int] | None:
    """Locate the exported ``activate(host)`` body in token space."""

    dense = [(index, token) for index, token in enumerate(tokens) if token[0] != "newline"]
    for dense_index, (_, token) in enumerate(dense):
        if token != ("identifier", "export"):
            continue
        cursor = dense_index + 1
        if cursor < len(dense) and dense[cursor][1] == ("identifier", "async"):
            cursor += 1
        expected = [
            ("identifier", "function"),
            ("identifier", "activate"),
            ("punctuation", "("),
            ("identifier", "host"),
            ("punctuation", ")"),
            ("punctuation", "{"),
        ]
        if [token for _, token in dense[cursor:cursor + len(expected)]] != expected:
            continue
        opening = dense[cursor + len(expected) - 1][0]
        closing = matching_brace(tokens, opening)
        if closing is not None:
            return opening + 1, closing
    return None


def frontend_lifecycle_method_blocks(
    tokens: list[tuple[str, str]], activation: tuple[int, int]
) -> dict[str, tuple[int, int]]:
    methods: dict[str, tuple[int, int]] = {}
    depth = 0
    for index in range(activation[0], activation[1] - 1):
        token = tokens[index]
        if token == ("punctuation", "{"):
            depth += 1
            continue
        if token == ("punctuation", "}"):
            depth = max(0, depth - 1)
            continue
        if depth or tokens[index:index + 2] != [("identifier", "return"), ("punctuation", "{")]:
            continue
        closing = matching_brace(tokens, index + 1)
        if closing is None or closing > activation[1]:
            continue
        methods.update(frontend_object_lifecycle_methods(tokens, index + 1, closing))
    return methods


def frontend_object_lifecycle_methods(
    tokens: list[tuple[str, str]], opening: int, closing: int
) -> dict[str, tuple[int, int]]:
    methods: dict[str, tuple[int, int]] = {}
    depth = 1
    for index in range(opening + 1, closing):
        token = tokens[index]
        if depth == 1 and token[0] == "identifier" and token[1] in APPROVALS_FRONTEND_LIFECYCLE_METHODS:
            block = frontend_method_block(tokens, index, closing)
            if block is not None:
                methods[token[1]] = block
        if token == ("punctuation", "{"):
            depth += 1
        elif token == ("punctuation", "}"):
            depth -= 1
    return methods


def frontend_method_block(
    tokens: list[tuple[str, str]], name_index: int, limit: int
) -> tuple[int, int] | None:
    opening = name_index + 1
    if opening >= limit or tokens[opening] != ("punctuation", "("):
        return None
    parameters_end = matching_parenthesis(tokens, opening)
    if parameters_end is None or parameters_end + 1 >= limit:
        return None
    body_opening = parameters_end + 1
    if tokens[body_opening] != ("punctuation", "{"):
        return None
    body_closing = matching_brace(tokens, body_opening)
    return (body_opening, body_closing) if body_closing is not None else None


def frontend_has_executable_lifecycle(
    tokens: list[tuple[str, str]], activation: tuple[int, int]
) -> bool:
    methods = frontend_lifecycle_method_blocks(tokens, activation)
    methods.update(frontend_returned_helper_lifecycle_methods(tokens, activation))
    return set(methods) == set(APPROVALS_FRONTEND_LIFECYCLE_METHODS)


def frontend_returned_helper_names(
    tokens: list[tuple[str, str]], span: tuple[int, int]
) -> set[str]:
    names: set[str] = set()
    depth = 0
    for index in range(span[0], span[1] - 2):
        token = tokens[index]
        if token == ("punctuation", "{"):
            depth += 1
        elif token == ("punctuation", "}"):
            depth = max(0, depth - 1)
        elif depth == 0 and token == ("identifier", "return"):
            if tokens[index + 1][0] == "identifier" and tokens[index + 2] == ("punctuation", "("):
                names.add(tokens[index + 1][1])
    return names


def frontend_named_function_body(
    tokens: list[tuple[str, str]], span: tuple[int, int]
) -> tuple[int, int] | None:
    for index in range(span[0], span[1]):
        if tokens[index] == ("punctuation", "{"):
            return index + 1, span[1]
    return None


def frontend_returned_helper_lifecycle_methods(
    tokens: list[tuple[str, str]], activation: tuple[int, int]
) -> dict[str, tuple[int, int]]:
    blocks = frontend_named_function_blocks(tokens)
    methods: dict[str, tuple[int, int]] = {}
    pending = list(frontend_returned_helper_names(tokens, activation))
    seen: set[str] = set()
    while pending:
        name = pending.pop()
        if name in seen or name not in blocks or lexical_declaration_shadows_helper(tokens, name):
            continue
        seen.add(name)
        body = frontend_named_function_body(tokens, blocks[name])
        if body is None:
            continue
        methods.update(frontend_lifecycle_method_blocks(tokens, body))
        pending.extend(frontend_returned_helper_names(tokens, body))
    return methods


def frontend_contains_dynamic_evaluator(tokens: list[tuple[str, str]]) -> bool:
    """Reject evaluator spellings whose runtime behavior cannot be proven."""

    forbidden = {"eval", "Function"}
    for index, (kind, value) in enumerate(tokens):
        if kind == "identifier" and value in forbidden:
            return True
        if kind != "string" or value not in forbidden:
            continue
        if index and index + 1 < len(tokens) and tokens[index - 1:index + 2] == [
            ("punctuation", "["),
            ("string", value),
            ("punctuation", "]"),
        ]:
            return True
    return False


def matching_opening_delimiter(
    tokens: list[tuple[str, str]], closing: int, opening_token: str, closing_token: str
) -> int | None:
    depth = 0
    for index in range(closing, -1, -1):
        if tokens[index] == ("punctuation", closing_token):
            depth += 1
        elif tokens[index] == ("punctuation", opening_token):
            depth -= 1
            if depth == 0:
                return index
    return None


def frontend_destructures_request_from_host(tokens: list[tuple[str, str]]) -> bool:
    """Reject aliases that detach any member from the reviewed broker."""

    for closing, token in enumerate(tokens[:-2]):
        if token != ("punctuation", "}"):
            continue
        if tokens[closing + 1:closing + 3] != [
            ("punctuation", "="),
            ("identifier", "host"),
        ]:
            continue
        opening = matching_opening_delimiter(tokens, closing, "{", "}")
        if opening is not None:
            return True
    return False


def frontend_destructuring_writes_host(tokens: list[tuple[str, str]]) -> bool:
    for closing, token in enumerate(tokens[:-1]):
        if token not in {("punctuation", "}"), ("punctuation", "]")}:
            continue
        if tokens[closing + 1] != ("punctuation", "="):
            continue
        opening_token = "{" if token[1] == "}" else "["
        opening = matching_opening_delimiter(tokens, closing, opening_token, token[1])
        if opening is not None and ("identifier", "host") in tokens[opening + 1:closing]:
            return True
    return False


def frontend_host_binding_is_unstable(tokens: list[tuple[str, str]]) -> bool:
    return host_is_reassigned_before(tokens, len(tokens), 0) or frontend_destructuring_writes_host(tokens)


def frontend_direct_helper_calls(
    tokens: list[tuple[str, str]], blocks: dict[str, tuple[int, int]], span: tuple[int, int]
) -> list[str]:
    calls: list[str] = []
    for index in range(span[0], span[1] - 1):
        if tokens[index][0] != "identifier":
            continue
        name = tokens[index][1]
        if name not in blocks or frontend_is_member_helper_call(tokens, index):
            continue
        call_opening = frontend_helper_call_parenthesis(tokens, index, span[1])
        if call_opening is None:
            continue
        closing = matching_parenthesis(tokens, call_opening)
        if closing is None or closing + 1 >= len(tokens):
            calls.append(name)
        elif tokens[closing + 1] != ("punctuation", "{"):
            calls.append(name)
    return calls


def frontend_helper_call_parenthesis(
    tokens: list[tuple[str, str]], index: int, end: int
) -> int | None:
    if index + 1 < end and tokens[index + 1] == ("punctuation", "("):
        return index + 1
    optional_call = tokens[index + 1:index + 4] == [
        ("punctuation", "?"),
        ("punctuation", "."),
        ("punctuation", "("),
    ]
    return index + 3 if optional_call and index + 3 < end else None


def frontend_is_member_helper_call(tokens: list[tuple[str, str]], index: int) -> bool:
    if not index or tokens[index - 1] != ("punctuation", "."):
        return False
    return tokens[index - 3:index] != [
        ("punctuation", "."),
        ("punctuation", "."),
        ("punctuation", "."),
    ]


def frontend_enclosing_call_name(
    tokens: list[tuple[str, str]], index: int
) -> str | None:
    depth = 0
    for cursor in range(index - 1, -1, -1):
        token = tokens[cursor]
        if token in {("punctuation", ")"), ("punctuation", "]"), ("punctuation", "}")}:
            depth += 1
        elif token in {("punctuation", "("), ("punctuation", "["), ("punctuation", "{")}:
            if depth:
                depth -= 1
            elif token == ("punctuation", "(") and cursor:
                callee = tokens[cursor - 1]
                return callee[1] if callee[0] == "identifier" else None
            else:
                return None
        elif depth == 0 and token == ("punctuation", ";"):
            return None
    return None


def frontend_is_callback_reference(tokens: list[tuple[str, str]], index: int) -> bool:
    if index >= 2 and tokens[index - 1] == ("punctuation", "="):
        property_name = tokens[index - 2]
        if property_name[0] == "identifier" and property_name[1].startswith("on"):
            return True
    return frontend_enclosing_call_name(tokens, index) in FRONTEND_CALLBACK_APIS


def frontend_referenced_helpers(
    tokens: list[tuple[str, str]], blocks: dict[str, tuple[int, int]], span: tuple[int, int]
) -> list[str]:
    referenced: list[str] = []
    for index in range(span[0], span[1] + 1):
        token = tokens[index]
        if token[0] != "identifier" or token[1] not in blocks:
            continue
        block_start, block_end = blocks[token[1]]
        if block_start <= index <= block_end:
            continue
        if frontend_is_callback_reference(tokens, index):
            referenced.append(token[1])
    return referenced


def frontend_arrow_body(
    tokens: list[tuple[str, str]], arrow: int, limit: int
) -> tuple[int, int] | None:
    start = arrow + 2
    if start >= limit:
        return None
    if tokens[start] == ("punctuation", "{"):
        closing = matching_brace(tokens, start)
        return (start, closing) if closing is not None else None
    depth = 0
    for cursor in range(start, limit):
        token = tokens[cursor]
        if token in {("punctuation", "("), ("punctuation", "["), ("punctuation", "{")}:
            depth += 1
        elif token in {("punctuation", ")"), ("punctuation", "]"), ("punctuation", "}")}:
            if depth:
                depth -= 1
            else:
                return start, cursor
        elif depth == 0 and token in {("punctuation", ","), ("punctuation", ";")}:
            return start, cursor
    return start, limit


def frontend_arrow_binding(tokens: list[tuple[str, str]], arrow: int) -> str | None:
    for cursor in range(arrow - 1, max(-1, arrow - 12), -1):
        if tokens[cursor] != ("punctuation", "="):
            continue
        if cursor and tokens[cursor - 1][0] == "identifier":
            return tokens[cursor - 1][1]
        return None
    return None


def frontend_arrow_is_event_assignment(
    tokens: list[tuple[str, str]], arrow: int
) -> bool:
    for cursor in range(arrow - 1, max(-1, arrow - 12), -1):
        if tokens[cursor] != ("punctuation", "="):
            continue
        if cursor < 2 or tokens[cursor - 2] != ("punctuation", "."):
            return False
        property_name = tokens[cursor - 1]
        return property_name[0] == "identifier" and property_name[1].lower().startswith("on")
    return False


def frontend_arrow_is_immediately_invoked(
    tokens: list[tuple[str, str]], arrow: int, body: tuple[int, int]
) -> bool:
    closing = body[1] + 1
    if closing >= len(tokens) or tokens[closing] != ("punctuation", ")"):
        return False
    opening = matching_opening_parenthesis(tokens, closing)
    if opening is None or not opening < arrow < closing:
        return False
    if opening and tokens[opening - 1][0] in {"identifier", "number", "string"}:
        if tokens[opening - 1] not in {
            ("identifier", "await"),
            ("identifier", "return"),
            ("identifier", "throw"),
            ("identifier", "void"),
            ("identifier", "yield"),
        }:
            return False
    return closing + 1 < len(tokens) and tokens[closing + 1] == ("punctuation", "(")


def frontend_bare_arrow_call(
    tokens: list[tuple[str, str]], index: int, binding: str
) -> bool:
    if tokens[index:index + 2] != [("identifier", binding), ("punctuation", "(")]:
        return False
    if index and tokens[index - 1] == ("punctuation", "."):
        return False
    closing = matching_parenthesis(tokens, index + 1)
    return closing is None or closing + 1 >= len(tokens) or tokens[closing + 1] != ("punctuation", "{")


def frontend_arrow_is_registered(
    tokens: list[tuple[str, str]], arrow: int, body: tuple[int, int], activation: tuple[int, int]
) -> bool:
    binding = frontend_arrow_binding(tokens, arrow)
    if frontend_arrow_is_event_assignment(tokens, arrow):
        return True
    if frontend_enclosing_call_name(tokens, arrow) in FRONTEND_CALLBACK_APIS:
        return True
    if frontend_arrow_is_immediately_invoked(tokens, arrow, body):
        return True
    if not binding:
        return False
    if frontend_binding_counts(tokens).get(binding) != 1:
        return False
    for index in range(body[1] + 1, activation[1] - 1):
        if frontend_bare_arrow_call(tokens, index, binding):
            return True
        if tokens[index] == ("identifier", binding) and frontend_is_callback_reference(tokens, index):
            return True
    return False


def frontend_unregistered_closure_blocks(
    tokens: list[tuple[str, str]], activation: tuple[int, int]
) -> set[tuple[int, int]]:
    lifecycle = set(frontend_lifecycle_method_blocks(tokens, activation).values())
    blocks: set[tuple[int, int]] = set()
    controls = {"catch", "for", "if", "switch", "while", "with"}
    for index in range(activation[0], activation[1] - 1):
        if tokens[index:index + 2] == [("punctuation", "="), ("punctuation", ">")]:
            body = frontend_arrow_body(tokens, index, activation[1])
            if body is not None and not frontend_arrow_is_registered(tokens, index, body, activation):
                blocks.add(body)
        if tokens[index][0] != "identifier" or tokens[index][1] in controls:
            continue
        if index and tokens[index - 1] == ("identifier", "function"):
            continue
        block = frontend_method_block(tokens, index, activation[1])
        if block is not None and block not in lifecycle:
            blocks.add(block)
    return blocks


def frontend_reachable_token_indices(tokens: list[tuple[str, str]]) -> set[int] | None:
    """Return token indices proven reachable from exported activation."""

    activation = frontend_activation_body_range(tokens)
    if activation is None:
        return None
    blocks = frontend_named_function_blocks(tokens)
    reachable: set[int] = set(range(activation[0], activation[1]))
    for name, span in blocks.items():
        if name != "activate" and activation[0] <= span[0] < span[1] <= activation[1]:
            reachable.difference_update(range(span[0], span[1] + 1))
    for start, end in frontend_unregistered_closure_blocks(tokens, activation):
        reachable.difference_update(range(start, end + 1))
    queued = frontend_direct_helper_calls(tokens, blocks, activation)
    queued.extend(frontend_referenced_helpers(tokens, blocks, activation))
    seen: set[str] = set()
    while queued:
        name = queued.pop()
        if name in seen or name not in blocks:
            continue
        seen.add(name)
        span = blocks[name]
        reachable.update(range(span[0], span[1] + 1))
        queued.extend(frontend_direct_helper_calls(tokens, blocks, span))
        queued.extend(frontend_referenced_helpers(tokens, blocks, span))
    return reachable


def frontend_binding_counts(tokens: list[tuple[str, str]]) -> dict[str, int]:
    """Count const/let/var, function, and parameter bindings by identifier."""

    counts: dict[str, int] = {}

    def add(name: str) -> None:
        counts[name] = counts.get(name, 0) + 1

    index = 0
    while index < len(tokens):
        kind, value = tokens[index]
        if kind == "identifier" and value in {"const", "let", "var"}:
            index += 1
            if index < len(tokens) and tokens[index][0] == "identifier":
                add(tokens[index][1])
            elif index < len(tokens) and tokens[index] == ("punctuation", "["):
                closing = matching_square_bracket(tokens, index)
                if closing is not None:
                    for token in tokens[index + 1:closing]:
                        if token[0] == "identifier":
                            add(token[1])
                    index = closing
            index += 1
            continue
        # ``catch (METHOD) { ... }`` introduces a binding just like a
        # function parameter.  Count it so a top-level RPC constant cannot be
        # incorrectly resolved through a shadowed catch variable.
        if kind == "identifier" and value == "catch" and index + 1 < len(tokens) and tokens[index + 1] == ("punctuation", "("):
            closing = matching_parenthesis(tokens, index + 1)
            if closing is not None:
                for token in tokens[index + 2:closing]:
                    if token[0] == "identifier":
                        add(token[1])
                index = closing + 1
                continue
        # Class and object methods use the same parameter-binding semantics as
        # ordinary functions.  The ``name(...) {`` shape is intentionally
        # restricted to non-control identifiers and skips ``function name``
        # declarations already handled above.
        if kind == "punctuation" and value == "(" and index and tokens[index - 1][0] == "identifier":
            name = tokens[index - 1][1]
            if name not in {"if", "for", "while", "switch", "with", "catch"}:
                previous = index - 2
                if previous < 0 or tokens[previous] not in {
                    ("identifier", "function"),
                    ("punctuation", "*"),
                }:
                    closing = matching_parenthesis(tokens, index)
                    if closing is not None and closing + 1 < len(tokens) and tokens[closing + 1] == ("punctuation", "{"):
                        for token in tokens[index + 1:closing]:
                            if token[0] == "identifier":
                                add(token[1])
                        index = closing + 1
                        continue
        if kind == "identifier" and value == "function":
            index += 1
            if index < len(tokens) and tokens[index] == ("punctuation", "*"):
                index += 1
            if index < len(tokens) and tokens[index][0] == "identifier":
                add(tokens[index][1])
                index += 1
            if index < len(tokens) and tokens[index] == ("punctuation", "("):
                closing = matching_parenthesis(tokens, index)
                if closing is not None:
                    for token in tokens[index + 1:closing]:
                        if token[0] == "identifier":
                            add(token[1])
                    index = closing
            index += 1
            continue
        if (
            kind == "punctuation"
            and value == ">"
            and index > 0
            and tokens[index - 1] == ("punctuation", "=")
        ):
            cursor = index - 2
            if cursor >= 0 and tokens[cursor] == ("punctuation", ")"):
                opening = matching_opening_parenthesis(tokens, cursor)
                if opening is not None:
                    for token in tokens[opening + 1:cursor]:
                        if token[0] == "identifier":
                            add(token[1])
            elif cursor >= 0 and tokens[cursor][0] == "identifier":
                add(tokens[cursor][1])
        index += 1
    return counts


def frontend_function_owner(
    blocks: dict[str, tuple[int, int]], index: int
) -> str | None:
    candidates = [
        (function_name, start, end)
        for function_name, (start, end) in blocks.items()
        if start < index < end
    ]
    return min(candidates, key=lambda item: item[2] - item[1])[0] if candidates else None


def frontend_rpc_declarations(
    tokens: list[tuple[str, str]], name: str
) -> list[int]:
    declarations: list[int] = []
    for index in range(len(tokens) - 3):
        if tokens[index:index + 3] == [
            ("identifier", "const"),
            ("identifier", name),
            ("punctuation", "="),
        ]:
            declarations.append(index)
    for index in range(len(tokens) - 3):
        if tokens[index:index + 3] == [
            ("identifier", "const"),
            ("punctuation", "["),
            ("identifier", name),
        ]:
            declarations.append(index)
    return declarations


def frontend_enclosing_braces(
    tokens: list[tuple[str, str]], index: int
) -> set[int]:
    stack: list[int] = []
    for cursor in range(index):
        if tokens[cursor] == ("punctuation", "{"):
            stack.append(cursor)
        elif tokens[cursor] == ("punctuation", "}") and stack:
            stack.pop()
    return set(stack)


def frontend_binding_declared_in_scope(
    tokens: list[tuple[str, str]], name: str, request_index: int
) -> bool:
    """Require a resolved RPC binding to be visible at its request site."""

    declarations = frontend_rpc_declarations(tokens, name)
    if len(declarations) != 1:
        return False
    declaration = declarations[0]
    if not frontend_enclosing_braces(tokens, declaration) <= frontend_enclosing_braces(tokens, request_index):
        return False
    blocks = frontend_named_function_blocks(tokens)
    declaration_owner = frontend_function_owner(blocks, declaration)
    request_owner = frontend_function_owner(blocks, request_index)
    if declaration_owner is None:
        return request_owner is not None or declaration < request_index
    return declaration_owner == request_owner and declaration < request_index


def _bracket_request_length(dense: list[tuple[str, str]], index: int) -> int:
    if (
        index + 2 < len(dense)
        and dense[index] == ("punctuation", "[")
        and dense[index + 1] == ("string", "request")
        and dense[index + 2] == ("punctuation", "]")
    ):
        return 3
    return 0


def javascript_parenthesis_pairs(tokens: list[tuple[str, str]]) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for index, token in enumerate(tokens):
        if token == ("punctuation", "("):
            stack.append(index)
        elif token == ("punctuation", ")") and stack:
            opening = stack.pop()
            pairs[opening] = index
            pairs[index] = opening
    return pairs


def frontend_host_receiver_end(
    dense: list[tuple[str, str]], index: int, pairs: dict[int, int]
) -> int | None:
    if dense[index] == ("identifier", "host"):
        if index and dense[index - 1] == ("punctuation", "."):
            return None
        return index + 1
    if dense[index] != ("punctuation", "(") or index not in pairs:
        return None
    closing = pairs[index]
    inner = dense[index + 1:closing]
    if inner == [("identifier", "host")]:
        return closing + 1
    if len(inner) >= 3 and inner[-2:] == [
        ("punctuation", ","),
        ("identifier", "host"),
    ]:
        return closing + 1
    return None


def frontend_request_member(
    dense: list[tuple[str, str]], cursor: int
) -> tuple[int, int] | None:
    if dense[cursor:cursor + 2] == [("punctuation", "?"), ("punctuation", ".")]:
        cursor += 2
    elif cursor < len(dense) and dense[cursor] == ("punctuation", "."):
        cursor += 1
    else:
        bracket = _bracket_request_length(dense, cursor)
        return (cursor + bracket, cursor + 1) if bracket else None
    bracket = _bracket_request_length(dense, cursor)
    if bracket:
        return cursor + bracket, cursor + 1
    if cursor < len(dense) and dense[cursor] == ("identifier", "request"):
        return cursor + 1, cursor
    return None


def frontend_host_request_call(
    dense: list[tuple[str, str]], index: int, pairs: dict[int, int]
) -> tuple[int, int] | None:
    cursor = frontend_host_receiver_end(dense, index, pairs)
    if cursor is None:
        return None
    member = frontend_request_member(dense, cursor)
    if member is None:
        return None
    member_end, access = member
    optional_call = dense[member_end:member_end + 3] == [
        ("punctuation", "?"),
        ("punctuation", "."),
        ("punctuation", "("),
    ]
    call_opening = member_end + 2 if optional_call else member_end
    if call_opening >= len(dense) or dense[call_opening] != ("punctuation", "("):
        return None
    if call_opening + 1 >= len(dense):
        return None
    return call_opening + 1, access


def frontend_host_request_access(
    dense: list[tuple[str, str]], index: int, pairs: dict[int, int]
) -> int | None:
    cursor = frontend_host_receiver_end(dense, index, pairs)
    if cursor is None:
        return None
    member = frontend_request_member(dense, cursor)
    return member[1] if member else None


def host_request_argument_index(dense: list[tuple[str, str]], index: int) -> int | None:
    call = frontend_host_request_call(dense, index, javascript_parenthesis_pairs(dense))
    return call[0] if call else None


def frontend_request_forwarder_invoked(
    dense: list[tuple[str, str]], cursor: int
) -> bool:
    if cursor + 2 >= len(dense) or dense[cursor] != ("punctuation", "."):
        return False
    if dense[cursor + 1][0] != "identifier":
        return False
    if dense[cursor + 1][1] not in FRONTEND_REQUEST_FORWARDERS:
        return False
    return dense[cursor + 2] == ("punctuation", "(")


def frontend_request_access_invoked(dense: list[tuple[str, str]], access: int) -> bool:
    cursor = access + 2 if dense[access][0] == "string" else access + 1
    while cursor < len(dense) and dense[cursor] == ("punctuation", ")"):
        cursor += 1
    if cursor < len(dense) and dense[cursor] == ("punctuation", "("):
        return True
    optional_call = dense[cursor:cursor + 3] == [
        ("punctuation", "?"),
        ("punctuation", "."),
        ("punctuation", "("),
    ]
    if optional_call:
        return True
    return frontend_request_forwarder_invoked(dense, cursor)


def frontend_request_access_indices(dense: list[tuple[str, str]]) -> set[int]:
    accesses: set[int] = set()
    for index, token in enumerate(dense):
        if token == ("identifier", "request"):
            if index and dense[index - 1] == ("punctuation", "."):
                accesses.add(index)
            continue
        if token != ("string", "request") or not index or index + 1 >= len(dense):
            continue
        if dense[index - 1] == ("punctuation", "[") and dense[index + 1] == ("punctuation", "]"):
            accesses.add(index)
    return accesses


def frontend_has_dynamic_host_member(
    dense: list[tuple[str, str]], pairs: dict[int, int]
) -> bool:
    for receiver, token in enumerate(dense):
        if token not in {("identifier", "host"), ("punctuation", "(")}:
            continue
        cursor = frontend_host_receiver_end(dense, receiver, pairs)
        if cursor is None:
            continue
        if dense[cursor:cursor + 2] == [("punctuation", "?"), ("punctuation", ".")]:
            cursor += 2
        if cursor >= len(dense) or dense[cursor] != ("punctuation", "["):
            continue
        closing = matching_square_bracket(dense, cursor)
        if closing is None:
            return True
        if dense[cursor + 1:closing] != [("string", "request")]:
            return True
    return False


def frontend_canonical_host_calls(
    dense: list[tuple[str, str]], pairs: dict[int, int]
) -> tuple[list[tuple[int, int, int]], set[int]]:
    calls: list[tuple[int, int, int]] = []
    direct_accesses: set[int] = set()
    for receiver, token in enumerate(dense):
        if token not in {("identifier", "host"), ("punctuation", "(")}:
            continue
        access = frontend_host_request_access(dense, receiver, pairs)
        if access is not None:
            direct_accesses.add(access)
        call = frontend_host_request_call(dense, receiver, pairs)
        if call is not None:
            calls.append((receiver, call[0], call[1]))
    return calls, direct_accesses


def frontend_host_request_calls(
    dense: list[tuple[str, str]], label: str
) -> list[tuple[int, int, int]]:
    pairs = javascript_parenthesis_pairs(dense)
    if frontend_has_dynamic_host_member(dense, pairs):
        fail(f"{label} contains a host RPC request through a dynamic broker member")
    calls, direct_accesses = frontend_canonical_host_calls(dense, pairs)
    canonical_accesses = {access for _, _, access in calls}
    accesses = frontend_request_access_indices(dense)
    invoked_accesses = {access for access in accesses if frontend_request_access_invoked(dense, access)}
    if (direct_accesses | invoked_accesses) - canonical_accesses:
        fail(f"{label} contains a host RPC request through an unresolved receiver")
    return calls


def frontend_request_methods(
    dense: list[tuple[str, str]], argument: int,
    proof: tuple[dict[str, set[str]], dict[str, int]],
) -> set[str] | None:
    kind, value = dense[argument]
    if kind in {"string", "identifier"} and (
        argument + 1 >= len(dense)
        or dense[argument + 1] not in {("punctuation", ","), ("punctuation", ")")}
    ):
        return None
    if kind == "string":
        return {value}
    bindings, counts = proof
    if (
        kind == "identifier"
        and value in bindings
        and counts.get(value, 0) == 1
        and frontend_binding_declared_in_scope(dense, value, argument)
    ):
        return bindings[value]
    return None


def frontend_host_requests(tokens: list[tuple[str, str]], label: str) -> set[str]:
    dense = [token for token in tokens if token[0] != "newline"]
    if frontend_host_binding_is_unstable(tokens):
        fail(f"{label} cannot prove the activation host broker contract")
    if frontend_destructures_request_from_host(dense):
        fail(f"{label} cannot destructure request from the activation host broker")
    proof = (frontend_rpc_bindings(dense), frontend_binding_counts(dense))
    reachable = frontend_reachable_token_indices(tokens)
    source_indices = [index for index, token in enumerate(tokens) if token[0] != "newline"]
    calls = frontend_host_request_calls(dense, label)
    requested: set[str] = set()
    for receiver, argument, _ in calls:
        methods = frontend_request_methods(dense, argument, proof)
        if methods is None:
            fail(f"{label} contains an unresolved host RPC request argument")
        source_index = source_indices[receiver]
        is_reachable = reachable is None or source_index in reachable
        if is_in_statically_unreachable_expression(tokens, source_index):
            is_reachable = False
        if not is_reachable:
            fail(
                f"{label} does not reference declared RPC methods through "
                "activation-reachable requests"
            )
        requested.update(methods)
    if not calls:
        fail(f"{label} does not call the declared host RPC surface")
    return requested


def validate_frontend_host_requests(
    methods: dict[str, object], tokens: list[tuple[str, str]], label: str
) -> set[str]:
    requested = frontend_host_requests(tokens, label)
    undeclared = requested - set(methods)
    if undeclared:
        fail(f"{label} calls undeclared host RPC methods: {sorted(undeclared)}")
    return requested


def validate_frontend_rpc_literals(
    methods: dict[str, object],
    tokens: list[tuple[str, str]],
    label: str,
    requested: set[str] | None = None,
) -> None:
    reachable = frontend_reachable_token_indices(tokens)
    reachable_names = {
        value
        for index, (kind, value) in enumerate(tokens)
        if kind == "identifier" and (reachable is None or index in reachable)
    }
    literals = {
        value
        for index, (kind, value) in enumerate(tokens)
        if kind == "string"
        and re.fullmatch(r"xsec\.[A-Za-z0-9_.-]+", value)
        and (
            reachable is None
            or index in reachable
            or (
                index >= 3
                and tokens[index - 3] == ("identifier", "const")
                and tokens[index - 2][0] == "identifier"
                and tokens[index - 2][1] in reachable_names
                and tokens[index - 1] == ("punctuation", "=")
            )
        )
    }
    undeclared = literals - set(methods)
    if undeclared:
        fail(f"{label} references undeclared RPC methods: {sorted(undeclared)}")
    if requested is None:
        requested = frontend_host_requests(tokens, label)
    missing = set(methods) - requested
    if missing:
        fail(f"{label} does not reference declared RPC methods through an actual request: {sorted(missing)}")


def validate_official_frontend(manifest: dict[str, object], source: str, label: str) -> None:
    """Reject empty official UIs and require an executable API-v2 contract."""

    try:
        desktop = manifest["extensions"]["com.xsec.desktop"]
    except (KeyError, TypeError):
        fail(f"{label} lacks XSEC Desktop extension metadata")
    if not isinstance(desktop, dict):
        fail(f"{label} has invalid XSEC Desktop extension metadata")
    engines = desktop.get("engines")
    if not isinstance(engines, dict) or engines.get("pluginApi") not in {
        OFFICIAL_FRONTEND_PLUGIN_API_RANGE,
        WORKSPACE_TOOL_NAVIGATION_PLUGIN_API_RANGE,
        WORKSPACE_COMPOSER_PLUGIN_API_RANGE,
    }:
        fail(f"{label} must require plugin API 1.2")
    frontend_api = desktop.get("frontendApi")
    if not isinstance(frontend_api, dict) or frontend_api.get("version") != 2 or frontend_api.get("module") != "single-esm":
        fail(f"{label} must declare frontend API v2 single-esm")
    methods = frontend_api.get("methods")
    if not isinstance(methods, dict) or not methods:
        fail(f"{label} must declare at least one host RPC method")
    composer_methods = set(methods) & WORKSPACE_COMPOSER_METHODS
    if composer_methods and engines.get("pluginApi") != WORKSPACE_COMPOSER_PLUGIN_API_RANGE:
        fail(f"{label} must require plugin API 1.4 for workspace Composer writes")
    if "xsec.workspace.tool.open" in methods and not composer_methods and engines.get("pluginApi") != WORKSPACE_TOOL_NAVIGATION_PLUGIN_API_RANGE:
        fail(f"{label} must require plugin API 1.3 for workspace tool navigation")
    lowered = source.lower()
    for marker in FORBIDDEN_OFFICIAL_FRONTEND_MARKERS:
        if marker.lower() in lowered:
            fail(f"{label} contains forbidden placeholder/fallback marker: {marker}")
    if len(source.encode("utf-8")) < OFFICIAL_FRONTEND_MIN_BYTES:
        fail(f"{label} is too small to be a functional official frontend")
    validate_javascript_esm_syntax(source, label)
    tokens = javascript_contract_tokens(source, label)
    activation = frontend_activation_body_range(tokens)
    if activation is None:
        fail(f"{label} must export an executable activate(host)")
    if not frontend_has_executable_lifecycle(tokens, activation):
        fail(f"{label} must return executable mount/update/dispose lifecycle methods")
    if frontend_contains_dynamic_evaluator(tokens):
        fail(f"{label} contains a dynamic JavaScript evaluator")
    requested = validate_frontend_host_requests(methods, tokens, label)
    validate_frontend_rpc_literals(methods, tokens, label, requested)


def validate_official_settings_contract(manifest: dict[str, object], label: str) -> None:
    """Keep official settings pages and their least-privilege RPCs in sync."""

    plugin_id = manifest.get("name")
    contract = OFFICIAL_PLUGIN_SETTINGS_CONTRACT.get(plugin_id) if isinstance(plugin_id, str) else None
    if contract is None:
        return
    try:
        desktop = manifest["extensions"]["com.xsec.desktop"]
    except (KeyError, TypeError):
        fail(f"{label} lacks XSEC Desktop extension metadata")
    if not isinstance(desktop, dict):
        fail(f"{label} has invalid XSEC Desktop extension metadata")
    contributes = desktop.get("contributes")
    pages = contributes.get("settingsPages") if isinstance(contributes, dict) else None
    page_id = contract["page"]
    expected_title = contract["title"]
    page = pages.get(page_id) if isinstance(pages, dict) and isinstance(page_id, str) else None
    if not isinstance(page, dict) or page.get("title") != expected_title or page.get("group") != "plugins" or page.get("page") != page_id:
        fail(f"{label} must declare the canonical plugin settings page")
    activation_events = desktop.get("activationEvents")
    if not isinstance(activation_events, list) or f"onSettingsPage:{page_id}" not in activation_events:
        fail(f"{label} must activate for its canonical plugin settings page")
    permissions = desktop.get("permissions")
    if not isinstance(permissions, dict) or not {"pluginData.read", "pluginData.write"}.issubset(permissions):
        fail(f"{label} must declare pluginData read/write permissions for settings")
    frontend_api = desktop.get("frontendApi")
    methods = frontend_api.get("methods") if isinstance(frontend_api, dict) else None
    expected_methods = contract["methods"]
    if not isinstance(methods, dict) or not isinstance(expected_methods, dict):
        fail(f"{label} has no settings RPC declaration")
    for method, descriptor_contract in expected_methods.items():
        capability, binding = descriptor_contract
        descriptor = methods.get(method)
        if not isinstance(descriptor, dict) or descriptor.get("capability") != capability or descriptor.get("binding") != binding:
            fail(f"{label} must bind {method} to the canonical plugin settings permission")
    optional_methods = contract.get("optionalMethods", {})
    if not isinstance(optional_methods, dict):
        fail(f"{label} has invalid optional settings RPC declarations")
    for method, (capability, binding) in optional_methods.items():
        if method not in methods:
            continue
        descriptor = methods[method]
        if (
            not isinstance(descriptor, dict)
            or descriptor.get("capability") != capability
            or descriptor.get("binding") != binding
        ):
            fail(f"{label} must bind {method} to the canonical plugin settings permission")


def validate_codex_manifest(plugin_id: str, plugin_dir: Path, version: str) -> None:
    """Ensure the Codex discovery descriptor cannot advertise an old package."""

    codex_manifest = plugin_dir / ".codex-plugin" / "plugin.json"
    metadata = read_json(codex_manifest, f"Codex manifest for {plugin_id}")
    if metadata.get("name") != plugin_id or metadata.get("version") != version:
        fail(f"Codex manifest for {plugin_id} must match the root package name and version")


def zip_member_is_regular_file(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return not info.is_dir() and stat.S_IFMT(mode) in {0, stat.S_IFREG}


def target_filesystem_path(path: PurePosixPath, name: str) -> str:
    """Normalize a ZIP member as a Windows-compatible installer would."""

    parts: list[str] = []
    for part in path.parts:
        nfc_part = unicodedata.normalize("NFC", part)
        if any(character in WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS for character in nfc_part):
            fail(f"archive contains a Windows-forbidden character in path component {part!r} of {name!r}")
        if any(ord(character) <= 0x1F for character in nfc_part):
            fail(f"archive contains a Windows control character in path component {part!r} of {name!r}")
        trimmed_part = nfc_part.rstrip(" .")
        normalized_part = trimmed_part.casefold()
        if not normalized_part:
            fail(f"archive contains an empty target filesystem path component in {name!r}")
        # Windows recognises COM¹, COM², COM³ (and the LPT equivalents) as
        # aliases for the corresponding numbered device names.  NFC does not
        # fold those superscript digits, so handle this small Windows-specific
        # equivalence before checking the reserved-name list.
        device_name = trimmed_part.split(".", 1)[0].translate(WINDOWS_DEVICE_SUPERSCRIPT_DIGITS).casefold()
        if device_name in WINDOWS_RESERVED_DEVICE_NAMES:
            fail(f"archive contains a Windows reserved device-name component {part!r} in {name!r}")
        parts.append(normalized_part)
    return "/".join(parts)


def zip_member_kind(name: str, info: zipfile.ZipInfo) -> str:
    """Return the target type after rejecting ZIP member types we never install."""

    if info.flag_bits & 0x1:
        fail(f"archive entry {name!r} must not be encrypted")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        fail(f"archive entry {name!r} must not be a symbolic link")
    kind = stat.S_IFMT(mode)
    if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
        fail(f"archive entry {name!r} must be a regular file or directory")
    return "directory" if info.is_dir() or kind == stat.S_IFDIR else "file"


def validate_zip_member(name: str, info: zipfile.ZipInfo, entries: dict[str, str]) -> None:
    if "\\" in name or name.startswith("/"):
        fail(f"archive contains unsafe entry path {name!r}")
    path = PurePosixPath(name)
    if not name or path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        fail(f"archive contains unsafe entry path {name!r}")
    normalized_name = target_filesystem_path(path, name)
    member_kind = zip_member_kind(name, info)
    if normalized_name in entries:
        fail(f"archive contains duplicate or target-filesystem collision for entry {name!r}")

    parts = normalized_name.split("/")
    for length in range(1, len(parts)):
        ancestor = "/".join(parts[:length])
        if entries.get(ancestor) == "file":
            fail(f"archive contains a file/directory target-filesystem collision for entry {name!r}")

    # A prior child makes this path an implicit directory on extraction.  A
    # file cannot replace that directory even when the two ZIP names differ
    # only by case, Unicode normalization, or trailing Windows-insignificant
    # characters.  An explicit directory is compatible with existing child
    # entries and is intentionally allowed.
    if member_kind == "file" and any(existing.startswith(normalized_name + "/") for existing in entries):
        fail(f"archive contains a file/directory target-filesystem collision for entry {name!r}")
    entries[normalized_name] = member_kind


def validate_archive(
    path: Path,
    plugin_id: str,
    version: str,
    *,
    require_current_official_frontend_contract: bool = True,
) -> dict[str, object]:
    """Validate one packaged artifact.

    Every historical release is subjected to package-integrity, archive-safety,
    manifest, and entrypoint checks.  The API-v2 official-frontend contract is
    deliberately a current-source policy: applying a newly introduced source
    contract to an older immutable Stable artifact would make a valid rollback
    target impossible to retain.  Callers validating the current Beta release
    keep the stricter default enabled.
    """
    if not zipfile.is_zipfile(path):
        fail(f"artifact {path} is not a ZIP archive")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ZIP_ENTRIES:
                fail(f"artifact {path} has an invalid number of entries")
            entries: dict[str, str] = {}
            members: dict[str, zipfile.ZipInfo] = {}
            total_size = 0
            for info in infos:
                validate_zip_member(info.filename, info, entries)
                members[PurePosixPath(info.filename).as_posix()] = info
                if info.file_size > MAX_ZIP_FILE_BYTES:
                    fail(f"archive entry {info.filename!r} exceeds the uncompressed size limit")
                total_size += info.file_size
                if total_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                    fail(f"artifact {path} exceeds the total uncompressed size limit")
                if info.file_size and (not info.compress_size or info.file_size / info.compress_size > MAX_ZIP_COMPRESSION_RATIO):
                    fail(f"archive entry {info.filename!r} exceeds the compression-ratio limit")
            try:
                manifest_bytes = archive.read("plugin.json")
            except KeyError:
                fail(f"artifact {path} does not include root plugin.json")
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        fail(f"cannot safely read artifact {path}: {error}")
    if len(manifest_bytes) > MAX_ZIP_FILE_BYTES:
        fail(f"artifact {path} plugin.json exceeds the size limit")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"artifact {path} plugin.json is invalid: {error}")
    if not isinstance(manifest, dict):
        fail(f"artifact {path} plugin.json must be an object")
    if manifest.get("name") != plugin_id:
        fail(f"artifact {path} plugin.json name does not match {plugin_id}")
    if manifest.get("version") != version:
        fail(f"artifact {path} plugin.json version does not match {version}")
    entrypoints = desktop_entrypoints(manifest, f"artifact {path} plugin.json")
    for entrypoint_name, entrypoint_path in entrypoints:
        entrypoint = members.get(entrypoint_path.as_posix())
        if entrypoint is None:
            fail(f"artifact {path} does not include XSEC Desktop entrypoint {entrypoint_name} at {entrypoint_path.as_posix()}")
        if not zip_member_is_regular_file(entrypoint):
            fail(f"artifact {path} XSEC Desktop entrypoint {entrypoint_name} must be a regular file")
    if plugin_id in DEFAULT_OFFICIAL_PLUGIN_IDS:
        frontend_path = dict(entrypoints).get("frontend")
        if frontend_path is None:
            fail(f"artifact {path} official plugin must declare a frontend entrypoint")
        try:
            with zipfile.ZipFile(path) as archive:
                frontend_source = archive.read(frontend_path.as_posix()).decode("utf-8")
        except (OSError, RuntimeError, UnicodeDecodeError, zipfile.BadZipFile) as error:
            fail(f"artifact {path} official frontend cannot be read as UTF-8: {error}")
        if require_current_official_frontend_contract:
            if plugin_id == APPROVALS_PLUGIN_ID:
                validate_approvals_frontend(manifest, frontend_source, f"artifact {path} approvals frontend")
            validate_official_frontend(manifest, frontend_source, f"artifact {path} official frontend")
            validate_official_settings_contract(manifest, f"artifact {path} official settings")
    return manifest


def marketplace_entries(root: Path) -> list[tuple[str, Path, dict[str, object]]]:
    marketplace_path = root / MARKETPLACE_RELATIVE_PATH
    if is_link(marketplace_path):
        fail("marketplace metadata must not be a symbolic link")
    marketplace = read_json(marketplace_path, str(marketplace_path))
    if marketplace.get("name") != "xsec-official":
        fail("marketplace name must be xsec-official")
    entries = marketplace.get("plugins")
    if not isinstance(entries, list):
        fail("marketplace plugins must be a list")
    result: list[tuple[str, Path, dict[str, object]]] = []
    seen_ids: set[str] = set()
    default_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            fail("marketplace entries must be objects")
        plugin_id = entry.get("name")
        if not isinstance(plugin_id, str) or not plugin_id:
            fail("marketplace entry name must be a non-empty string")
        if plugin_id in seen_ids:
            fail(f"marketplace contains duplicate plugin {plugin_id}")
        seen_ids.add(plugin_id)
        source = entry.get("source")
        if not isinstance(source, dict) or source.get("source") != "local":
            fail(f"marketplace plugin {plugin_id} must use a local source")
        source_path = source.get("path")
        expected_path = f"./{SNAPSHOT_ROOT_RELATIVE_PATH.as_posix()}/{plugin_id}"
        if source_path != expected_path:
            fail(f"marketplace plugin {plugin_id} source.path must be {expected_path}")
        plugin_dir = root / SNAPSHOT_ROOT_RELATIVE_PATH / plugin_id
        if is_link(plugin_dir) or not plugin_dir.is_dir():
            fail(f"marketplace plugin {plugin_id} source directory is unavailable or a symbolic link")
        policy = entry.get("policy")
        if not isinstance(policy, dict):
            fail(f"marketplace plugin {plugin_id} must have an installation policy")
        if policy.get("installation") == "INSTALLED_BY_DEFAULT":
            if policy.get("authentication") != "ON_INSTALL":
                fail(f"default marketplace plugin {plugin_id} must authenticate on install")
            default_ids.add(plugin_id)
        result.append((plugin_id, plugin_dir, entry))
    if default_ids != set(DEFAULT_OFFICIAL_PLUGIN_IDS):
        missing = sorted(set(DEFAULT_OFFICIAL_PLUGIN_IDS) - default_ids)
        unexpected = sorted(default_ids - set(DEFAULT_OFFICIAL_PLUGIN_IDS))
        fail(f"default official plugin set mismatch (missing={missing}, unexpected={unexpected})")
    return result


def validate_artifacts(
    plugin_id: str,
    release_path: Path,
    version: str,
    artifacts: object,
    label: str,
    *,
    require_current_official_frontend_contract: bool = False,
) -> list[tuple[Path, str, dict[str, object]]]:
    if not isinstance(artifacts, list) or not artifacts:
        fail(f"{label} has no artifacts")
    result: list[tuple[Path, str, dict[str, object]]] = []
    seen_targets: set[tuple[str, str]] = set()
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or not {"os", "arch", "url", "sha256"} <= set(artifact)
            or set(artifact) - {"os", "arch", "url", "sha256", "signature"}
        ):
            fail(f"release metadata for {plugin_id} contains an unsupported artifact schema")
        os_name, arch = artifact.get("os"), artifact.get("arch")
        if not isinstance(os_name, str) or not os_name or not isinstance(arch, str) or not arch:
            fail(f"release metadata for {plugin_id} artifact must have non-empty os and arch")
        if (os_name, arch) in seen_targets:
            fail(f"{label} has duplicate {os_name}/{arch} artifacts")
        seen_targets.add((os_name, arch))
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            fail(f"release metadata for {plugin_id} has a non-canonical SHA-256 digest")
        if "signature" in artifact and (not isinstance(artifact["signature"], str) or not artifact["signature"]):
            fail(f"release metadata for {plugin_id} has an invalid artifact signature")
        relative = safe_relative_path(artifact.get("url"), f"artifact URL for {plugin_id}")
        artifact_path = resolve_below(release_path.parent, relative, f"artifact URL for {plugin_id}")
        if sha256(artifact_path) != digest:
            fail(f"artifact SHA-256 does not match release metadata for {plugin_id}")
        manifest = validate_archive(
            artifact_path,
            plugin_id,
            version,
            require_current_official_frontend_contract=require_current_official_frontend_contract,
        )
        result.append((artifact_path, version, manifest))
    return result


def validate_release_index(plugin_id: str, plugin_dir: Path) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    """Validate release metadata and return its records keyed by release ID.

    Schema v1 remains readable for a rolling Desktop migration.  New builds
    and all new publication documents must use v2; `validate_source` enforces
    that requirement on the generated output.
    """

    release_path = plugin_dir / ".xsec-market" / "releases.json"
    if is_link(release_path.parent) or is_link(release_path):
        fail(f"release metadata for {plugin_id} must not use symbolic links")
    release = read_json(release_path, str(release_path))
    if release.get("pluginId") != plugin_id:
        fail(f"release metadata for {plugin_id} has an invalid schemaVersion or pluginId")
    releases = release.get("releases")
    if not isinstance(releases, list) or not releases:
        fail(f"release metadata for {plugin_id} must have at least one release")
    schema_version = release.get("schemaVersion")
    records: dict[str, dict[str, object]] = {}
    if schema_version == 1:
        seen_release_keys: set[tuple[str, str]] = set()
        for index, item in enumerate(releases):
            label = f"release metadata for {plugin_id} legacy release {index}"
            if not isinstance(item, dict):
                fail(f"release metadata for {plugin_id} contains a non-object release")
            version, channel = item.get("version"), item.get("channel")
            if not isinstance(version, str) or not version or channel not in {"beta", "stable"}:
                fail(f"release metadata for {plugin_id} has an invalid legacy version or channel")
            if (version, channel) in seen_release_keys:
                fail(f"release metadata for {plugin_id} duplicates {version}/{channel}")
            seen_release_keys.add((version, channel))
            try:
                engines = require_release_engines(item.get("engines"), label)
            except ValueError as error:
                fail(str(error))
            artifacts = item.get("artifacts")
            validate_artifacts(plugin_id, release_path, version, artifacts, label)
            if not isinstance(artifacts, list):  # already guarded, helps type narrowing
                raise AssertionError("artifacts unexpectedly absent")
            identifier = release_id(version, engines, artifacts)
            records[identifier] = {
                "releaseId": identifier,
                "version": version,
                "engines": engines,
                "artifacts": artifacts,
            }
        return release, records

    if schema_version != 2 or set(release) != {"schemaVersion", "pluginId", "releases", "channels"}:
        fail(f"release metadata for {plugin_id} has an unsupported schema")
    versions: set[str] = set()
    for index, item in enumerate(releases):
        label = f"release metadata for {plugin_id} release {index}"
        if not isinstance(item, dict) or set(item) != {"releaseId", "version", "engines", "artifacts"}:
            fail(f"{label} has an unsupported schema")
        identifier, version, engines, artifacts = (
            item.get("releaseId"),
            item.get("version"),
            item.get("engines"),
            item.get("artifacts"),
        )
        if not isinstance(identifier, str) or not RELEASE_ID_PATTERN.fullmatch(identifier):
            fail(f"{label} has an invalid releaseId")
        if not isinstance(version, str) or not version:
            fail(f"{label} has an invalid version")
        try:
            engines = require_release_engines(engines, label)
        except ValueError as error:
            fail(str(error))
        validate_artifacts(plugin_id, release_path, version, artifacts, label)
        if not isinstance(artifacts, list):
            raise AssertionError("artifacts unexpectedly absent")
        if identifier != release_id(version, engines, artifacts):
            fail(f"{label} releaseId does not match immutable release content")
        if identifier in records:
            fail(f"release metadata for {plugin_id} contains duplicate releaseIds")
        if version in versions:
            fail(f"release metadata for {plugin_id} contains multiple immutable releases for version {version}")
        versions.add(version)
        records[identifier] = item
    channels = release.get("channels")
    if not isinstance(channels, dict) or set(channels) != {"beta", "stable"}:
        fail(f"release metadata for {plugin_id} must contain beta and stable channel pointers")
    beta = channels.get("beta")
    beta_target = beta.get("releaseId") if isinstance(beta, dict) and set(beta) == {"releaseId"} else None
    if not isinstance(beta_target, str) or beta_target not in records:
        fail(f"release metadata for {plugin_id} beta pointer must reference an immutable release")
    stable = channels.get("stable")
    if stable is not None:
        stable_target = stable.get("releaseId") if isinstance(stable, dict) and set(stable) == {"releaseId"} else None
        if not isinstance(stable_target, str) or stable_target not in records:
            fail(f"release metadata for {plugin_id} stable pointer must be null or reference an immutable release")
    return release, records


def validate_release(plugin_id: str, plugin_dir: Path) -> list[tuple[Path, str, dict[str, object]]]:
    """Compatibility helper retained for tests that need all archived releases."""

    release, records = validate_release_index(plugin_id, plugin_dir)
    release_path = plugin_dir / ".xsec-market" / "releases.json"
    result: list[tuple[Path, str, dict[str, object]]] = []
    if release.get("schemaVersion") == 1:
        items = release["releases"]
    else:
        items = records.values()
    for item in items:
        if not isinstance(item, dict):
            raise AssertionError("validated release item must be an object")
        result.extend(validate_artifacts(plugin_id, release_path, str(item["version"]), item["artifacts"], f"release metadata for {plugin_id}"))
    return result


def validate_source_manifest(plugin_id: str, plugin_dir: Path) -> dict[str, object]:
    manifest = read_json(plugin_dir / "plugin.json", f"plugin manifest for {plugin_id}")
    if manifest.get("name") != plugin_id:
        fail(f"plugin manifest name does not match marketplace entry {plugin_id}")
    if not isinstance(manifest.get("version"), str) or not manifest["version"]:
        fail(f"plugin manifest {plugin_id} has no version")
    try:
        engines = manifest["extensions"]["com.xsec.desktop"]["engines"]
    except (KeyError, TypeError):
        fail(f"plugin manifest {plugin_id} lacks XSEC Desktop engine metadata")
    try:
        require_release_engines(engines, f"plugin manifest {plugin_id}")
    except ValueError as error:
        fail(str(error))
    entrypoints = desktop_entrypoints(manifest, f"plugin manifest {plugin_id}")
    resolved_entrypoints: dict[str, Path] = {}
    for entrypoint_name, entrypoint_path in entrypoints:
        resolved_entrypoints[entrypoint_name] = resolve_below(
            plugin_dir,
            entrypoint_path,
            f"plugin manifest {plugin_id} entrypoint {entrypoint_name}",
        )
    if plugin_id in DEFAULT_OFFICIAL_PLUGIN_IDS:
        validate_codex_manifest(plugin_id, plugin_dir, manifest["version"])
        frontend = resolved_entrypoints.get("frontend")
        if frontend is None:
            fail(f"plugin manifest {plugin_id} must declare a frontend entrypoint")
        try:
            frontend_source = frontend.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            fail(f"plugin manifest {plugin_id} official frontend cannot be read as UTF-8: {error}")
        if plugin_id == APPROVALS_PLUGIN_ID:
            validate_approvals_frontend(manifest, frontend_source, f"plugin manifest {plugin_id} approvals frontend")
        validate_official_frontend(manifest, frontend_source, f"plugin manifest {plugin_id} official frontend")
        validate_official_settings_contract(manifest, f"plugin manifest {plugin_id} official settings")
    return manifest


def validate_source(source_root: Path, built_root: Path) -> None:
    source_entries = marketplace_entries(source_root)
    built_entries = marketplace_entries(built_root)
    if (source_root / MARKETPLACE_RELATIVE_PATH).read_bytes() != (built_root / MARKETPLACE_RELATIVE_PATH).read_bytes():
        fail("temporary marketplace metadata differs from source metadata")
    built_by_id = {plugin_id: plugin_dir for plugin_id, plugin_dir, _ in built_entries}
    if {plugin_id for plugin_id, _, _ in source_entries} != set(built_by_id):
        fail("temporary marketplace plugin set differs from source plugin set")
    for plugin_id, source_dir, _ in source_entries:
        source_manifest = validate_source_manifest(plugin_id, source_dir)
        built_plugin_dir = built_by_id[plugin_id]
        source_release, source_records = validate_release_index(plugin_id, source_dir)
        generated_release, generated_records = validate_release_index(plugin_id, built_plugin_dir)
        if generated_release.get("schemaVersion") != 2:
            fail(f"temporary output for {plugin_id} must migrate release metadata to schema v2")
        generated_channels = generated_release.get("channels")
        if not isinstance(generated_channels, dict):
            fail(f"temporary output for {plugin_id} has no channel pointers")
        beta = generated_channels.get("beta")
        beta_id = beta.get("releaseId") if isinstance(beta, dict) else None
        generated_item = generated_records.get(beta_id) if isinstance(beta_id, str) else None
        if generated_item is None:
            fail(f"temporary output for {plugin_id} beta pointer does not select a release")
        if (
            generated_item.get("version") != source_manifest["version"]
            or generated_item.get("engines") != source_manifest["extensions"]["com.xsec.desktop"]["engines"]
        ):
            fail(f"temporary beta release metadata for {plugin_id} does not match its source manifest")

        # A regular build may append an immutable release and advance beta, but
        # must never mutate an already-published v2 record or stable pointer.
        if source_release.get("schemaVersion") == 2:
            for identifier, source_item in source_records.items():
                if generated_records.get(identifier) != source_item:
                    fail(f"temporary output for {plugin_id} mutated immutable release {identifier}")
            source_channels = source_release.get("channels")
            if isinstance(source_channels, dict) and generated_channels.get("stable") != source_channels.get("stable"):
                fail(f"temporary output for {plugin_id} moved the stable channel pointer")

        candidate_artifacts = validate_artifacts(
            plugin_id,
            built_plugin_dir / ".xsec-market" / "releases.json",
            str(generated_item["version"]),
            generated_item["artifacts"],
            f"temporary beta release metadata for {plugin_id}",
            require_current_official_frontend_contract=True,
        )
        if len(candidate_artifacts) != 1 or candidate_artifacts[0][1] != source_manifest["version"]:
            fail(f"temporary output for {plugin_id} does not contain exactly its current beta artifact")
        with tempfile.TemporaryDirectory(prefix="xsec-market-repro-") as directory:
            reproducible = Path(directory) / candidate_artifacts[0][0].name
            write_zip(source_dir, reproducible)
            if reproducible.read_bytes() != candidate_artifacts[0][0].read_bytes():
                fail(f"beta artifact for {plugin_id} is not deterministic from its source tree")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    source_parser = subcommands.add_parser("source", help="validate source and a generated build")
    source_parser.add_argument("--source-root", type=Path, default=ROOT)
    source_parser.add_argument("--built-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate_source(args.source_root.resolve(), args.built_root.resolve())
    except MarketplaceValidationError as error:
        raise SystemExit(f"marketplace validation failed: {error}") from error
    print(f"marketplace {args.command} validation passed")


if __name__ == "__main__":
    main()
