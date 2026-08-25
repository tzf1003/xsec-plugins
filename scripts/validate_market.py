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

from build_market import MARKETPLACE_RELATIVE_PATH, ROOT, is_link, sha256, write_zip
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
})
APPROVALS_FRONTEND_CAPABILITY = "workspace.session.read"
APPROVALS_FRONTEND_BINDING = "session"
JAVASCRIPT_SYNTAX_CHECK_TIMEOUT_SECONDS = 10


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


def javascript_contract_tokens(source: str, label: str) -> list[tuple[str, str]]:
    """Tokenize the small JavaScript subset used by static frontend checks.

    Marketplace validation must never import or execute a plugin archive.  The
    tokenizer deliberately recognizes comments, string/template literals and
    slash-delimited literal candidates so an `activate` or RPC snippet merely
    written as data cannot satisfy the release contract.  Because the checker
    intentionally does not parse or execute plugins, slash pairs are consumed
    conservatively even where JavaScript could interpret them as division;
    that can reject an unusual valid program, but never accepts a placeholder.
    """

    tokens: list[tuple[str, str]] = []
    index = 0
    length = len(source)
    while index < length:
        character = source[index]
        if character.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = length if newline == -1 else newline + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end == -1:
                fail(f"{label} contains an unterminated JavaScript block comment")
            index = end + 2
            continue
        if character == "/":
            end = consume_javascript_regex(source, index)
            if end is not None:
                tokens.append(("regex", source[index:end]))
                index = end
                continue
        if character in {"'", '"', "`"}:
            quote = character
            start = index + 1
            index += 1
            escaped = False
            while index < length:
                current = source[index]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    tokens.append(("string", source[start:index]))
                    index += 1
                    break
                index += 1
            else:
                fail(f"{label} contains an unterminated JavaScript string")
            continue
        if character.isalpha() or character in {"_", "$"}:
            start = index
            index += 1
            while index < length and (source[index].isalnum() or source[index] in {"_", "$"}):
                index += 1
            tokens.append(("identifier", source[start:index]))
            continue
        tokens.append(("punctuation", character))
        index += 1
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


def named_javascript_function_blocks(tokens: list[tuple[str, str]]) -> list[tuple[str, int, int, int]]:
    """Find ordinary named function blocks in an activation implementation.

    The frontend contract does not try to implement a JavaScript evaluator. It
    only needs a small call graph to distinguish an activation helper that is
    invoked from an inert nested helper that is never reached. Unsupported
    function forms holding broker calls are rejected below.
    """

    blocks: list[tuple[str, int, int, int]] = []
    for index in range(len(tokens)):
        cursor = index
        if tokens[cursor] == ("identifier", "async"):
            cursor += 1
        if cursor + 2 >= len(tokens):
            continue
        if tokens[cursor] != ("identifier", "function"):
            continue
        name_kind, name = tokens[cursor + 1]
        if name_kind != "identifier" or tokens[cursor + 2] != ("punctuation", "("):
            continue
        closing_parenthesis = matching_parenthesis(tokens, cursor + 2)
        if closing_parenthesis is None or closing_parenthesis + 1 >= len(tokens) or tokens[closing_parenthesis + 1] != ("punctuation", "{"):
            continue
        opening_brace = closing_parenthesis + 1
        closing_brace = matching_brace(tokens, opening_brace)
        if closing_brace is not None:
            blocks.append((name, index, opening_brace, closing_brace))
    return blocks


def unsupported_javascript_function_blocks(tokens: list[tuple[str, str]]) -> list[tuple[int, int]]:
    """Return lexical function-like blocks the small call graph cannot prove."""

    blocks: list[tuple[int, int]] = []
    for index in range(len(tokens) - 2):
        # Arrow functions may hold a broker request, but their invocation is
        # not represented by this intentionally narrow verifier.
        if tokens[index:index + 3] == [
            ("punctuation", "="),
            ("punctuation", ">"),
            ("punctuation", "{"),
        ]:
            closing = matching_brace(tokens, index + 2)
            if closing is not None:
                blocks.append((index + 2, closing))
        # Expression-bodied arrows do not have a brace-delimited body.  Keep
        # their body out of the proof as well; the next top-level statement
        # separator (or surrounding object/class block) ends the expression.
        if tokens[index:index + 2] == [
            ("punctuation", "="),
            ("punctuation", ">"),
        ] and (index + 2 >= len(tokens) or tokens[index + 2] != ("punctuation", "{")):
            parenthesis_depth = 0
            bracket_depth = 0
            cursor = index + 2
            while cursor < len(tokens):
                token = tokens[cursor]
                if token == ("punctuation", "("):
                    parenthesis_depth += 1
                elif token == ("punctuation", ")") and parenthesis_depth:
                    parenthesis_depth -= 1
                elif token == ("punctuation", "["):
                    bracket_depth += 1
                elif token == ("punctuation", "]") and bracket_depth:
                    bracket_depth -= 1
                elif parenthesis_depth == 0 and bracket_depth == 0 and token in {
                    ("punctuation", ";"),
                    ("punctuation", ","),
                    ("punctuation", "}"),
                }:
                    break
                cursor += 1
            blocks.append((index + 1, cursor))
        # Likewise a class body cannot be an activation call-graph node.
        if tokens[index] == ("identifier", "class"):
            for cursor in range(index + 1, len(tokens)):
                if tokens[cursor] == ("punctuation", "{"):
                    closing = matching_brace(tokens, cursor)
                    if closing is not None:
                        blocks.append((cursor, closing))
                    break
                if tokens[cursor] == ("punctuation", ";"):
                    break
    return blocks


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


def is_in_block(index: int, blocks: list[tuple[int, int]]) -> bool:
    return any(opening_brace < index < closing_brace for opening_brace, closing_brace in blocks)


def reachable_named_functions(
    tokens: list[tuple[str, str]],
    blocks: list[tuple[str, int, int, int]],
    unsupported_blocks: list[tuple[int, int]],
) -> set[int]:
    """Build a conservative call graph rooted at activation lifecycle code."""

    by_name: dict[str, list[int]] = {}
    for block_index, (name, _, _, _) in enumerate(blocks):
        by_name.setdefault(name, []).append(block_index)
    reachable: set[int] = set()
    pending: list[int] = []
    edges: dict[int, set[int]] = {block_index: set() for block_index in range(len(blocks))}

    for index in range(len(tokens) - 1):
        kind, value = tokens[index]
        if kind != "identifier" or value not in by_name or tokens[index + 1] != ("punctuation", "("):
            continue
        # The declaration's own ``name(...)`` is not a call edge.
        if any(declaration_start <= index <= opening_brace for _, declaration_start, opening_brace, _ in blocks):
            continue
        # A call captured by an unsupported closure cannot establish a
        # reachability proof for a named helper.
        if is_in_block(index, unsupported_blocks):
            continue
        caller = enclosing_named_function(index, blocks)
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
    unsupported_blocks = unsupported_javascript_function_blocks(tokens)
    reachable_blocks = reachable_named_functions(tokens, named_blocks, unsupported_blocks)
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
        if is_in_block(index, unsupported_blocks):
            continue
        owner = enclosing_named_function(index, named_blocks)
        if owner is not None and owner not in reachable_blocks:
            continue
        kind, method = sequence[4]
        if kind == "string" and method in APPROVALS_FRONTEND_METHODS:
            calls.add(method)
    return calls


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
    must not execute an archive's untrusted JavaScript.  It proves that the
    approvals package declares the v2 broker contract and exports its expected
    activation function, while the Desktop host remains responsible for
    manifest-derived permission checks at execution time.
    """

    if manifest.get("name") != APPROVALS_PLUGIN_ID:
        return
    try:
        desktop = manifest["extensions"]["com.xsec.desktop"]
    except (KeyError, TypeError):
        fail(f"{label} lacks XSEC Desktop extension metadata")
    if not isinstance(desktop, dict):
        fail(f"{label} has invalid XSEC Desktop extension metadata")
    frontend_api = desktop.get("frontendApi")
    if not isinstance(frontend_api, dict) or frontend_api.get("version") != 2 or frontend_api.get("module") != "single-esm":
        fail(f"{label} must declare the approvals frontend API v2 single-esm contract")
    methods = frontend_api.get("methods")
    if not isinstance(methods, dict) or set(methods) != APPROVALS_FRONTEND_METHODS:
        fail(f"{label} must declare the approvals read RPC methods")
    for method in APPROVALS_FRONTEND_METHODS:
        descriptor = methods.get(method)
        if not isinstance(descriptor, dict) or descriptor.get("capability") != APPROVALS_FRONTEND_CAPABILITY or descriptor.get("binding") != APPROVALS_FRONTEND_BINDING:
            fail(f"{label} must bind approvals RPC methods to the session read capability")
    validate_javascript_esm_syntax(source, label)
    tokens = javascript_contract_tokens(source, label)
    body = activate_body_tokens(tokens)
    if body is None:
        fail(f"{label} must export an executable activate(host) function")
    if declared_approvals_rpc_calls(body) != APPROVALS_FRONTEND_METHODS:
        fail(f"{label} must implement the declared approvals RPC requests")


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


def validate_archive(path: Path, plugin_id: str, version: str) -> dict[str, object]:
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
    if plugin_id == APPROVALS_PLUGIN_ID:
        frontend_path = dict(entrypoints).get("frontend")
        if frontend_path is None:
            fail(f"artifact {path} approvals plugin must declare a frontend entrypoint")
        try:
            with zipfile.ZipFile(path) as archive:
                frontend_source = archive.read(frontend_path.as_posix()).decode("utf-8")
        except (OSError, RuntimeError, UnicodeDecodeError, zipfile.BadZipFile) as error:
            fail(f"artifact {path} approvals frontend cannot be read as UTF-8: {error}")
        validate_approvals_frontend(manifest, frontend_source, f"artifact {path} approvals frontend")
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
        expected_path = f"./plugins/{plugin_id}"
        if source_path != expected_path:
            fail(f"marketplace plugin {plugin_id} source.path must be {expected_path}")
        plugin_dir = root / "plugins" / plugin_id
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


def validate_release(plugin_id: str, plugin_dir: Path) -> list[tuple[Path, str, dict[str, object]]]:
    release_path = plugin_dir / ".xsec-market" / "releases.json"
    if is_link(release_path.parent) or is_link(release_path):
        fail(f"release metadata for {plugin_id} must not use symbolic links")
    release = read_json(release_path, str(release_path))
    if release.get("schemaVersion") != 1 or release.get("pluginId") != plugin_id:
        fail(f"release metadata for {plugin_id} has an invalid schemaVersion or pluginId")
    releases = release.get("releases")
    if not isinstance(releases, list) or not releases:
        fail(f"release metadata for {plugin_id} must have at least one release")
    result: list[tuple[Path, str, dict[str, object]]] = []
    seen_release_keys: set[tuple[str, str]] = set()
    for item in releases:
        if not isinstance(item, dict):
            fail(f"release metadata for {plugin_id} contains a non-object release")
        version, channel = item.get("version"), item.get("channel")
        if not isinstance(version, str) or not version or not isinstance(channel, str) or not channel:
            fail(f"release metadata for {plugin_id} has an invalid version or channel")
        if (version, channel) in seen_release_keys:
            fail(f"release metadata for {plugin_id} duplicates {version}/{channel}")
        seen_release_keys.add((version, channel))
        artifacts = item.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            fail(f"release metadata for {plugin_id} {version}/{channel} has no artifacts")
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                fail(f"release metadata for {plugin_id} contains a non-object artifact")
            if not isinstance(artifact.get("os"), str) or not isinstance(artifact.get("arch"), str):
                fail(f"release metadata for {plugin_id} artifact must have os and arch")
            digest = artifact.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                fail(f"release metadata for {plugin_id} has a non-canonical SHA-256 digest")
            relative = safe_relative_path(artifact.get("url"), f"artifact URL for {plugin_id}")
            artifact_path = resolve_below(release_path.parent, relative, f"artifact URL for {plugin_id}")
            if sha256(artifact_path) != digest:
                fail(f"artifact SHA-256 does not match release metadata for {plugin_id}")
            manifest = validate_archive(artifact_path, plugin_id, version)
            result.append((artifact_path, version, manifest))
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
    if not isinstance(engines, dict):
        fail(f"plugin manifest {plugin_id} has invalid XSEC Desktop engine metadata")
    entrypoints = desktop_entrypoints(manifest, f"plugin manifest {plugin_id}")
    resolved_entrypoints: dict[str, Path] = {}
    for entrypoint_name, entrypoint_path in entrypoints:
        resolved_entrypoints[entrypoint_name] = resolve_below(
            plugin_dir,
            entrypoint_path,
            f"plugin manifest {plugin_id} entrypoint {entrypoint_name}",
        )
    if plugin_id == APPROVALS_PLUGIN_ID:
        frontend = resolved_entrypoints.get("frontend")
        if frontend is None:
            fail(f"plugin manifest {plugin_id} must declare a frontend entrypoint")
        try:
            frontend_source = frontend.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            fail(f"plugin manifest {plugin_id} approvals frontend cannot be read as UTF-8: {error}")
        validate_approvals_frontend(manifest, frontend_source, f"plugin manifest {plugin_id} approvals frontend")
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
        generated_release = read_json(
            built_plugin_dir / ".xsec-market" / "releases.json",
            f"temporary release metadata for {plugin_id}",
        )
        generated_releases = generated_release.get("releases")
        if not isinstance(generated_releases, list) or len(generated_releases) != 1 or not isinstance(generated_releases[0], dict):
            fail(f"temporary output for {plugin_id} must contain exactly one stable release")
        generated_item = generated_releases[0]
        if (
            generated_item.get("version") != source_manifest["version"]
            or generated_item.get("channel") != "stable"
            or generated_item.get("engines") != source_manifest["extensions"]["com.xsec.desktop"]["engines"]
        ):
            fail(f"temporary release metadata for {plugin_id} does not match its source manifest")
        artifacts = validate_release(plugin_id, built_plugin_dir)
        expected_artifact_name = f"{plugin_id}-{source_manifest['version']}-any-any.xsec-plugin"
        if len(artifacts) != 1 or artifacts[0][0].name != expected_artifact_name or artifacts[0][1] != source_manifest["version"]:
            fail(f"temporary output for {plugin_id} does not contain exactly its current stable artifact")
        with tempfile.TemporaryDirectory(prefix="xsec-market-repro-") as directory:
            reproducible = Path(directory) / expected_artifact_name
            write_zip(source_dir, reproducible)
            if reproducible.read_bytes() != artifacts[0][0].read_bytes():
                fail(f"artifact for {plugin_id} is not deterministic from its source tree")


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
