"""Load and enforce the trusted one-time layout migration content plan."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath


PLAN = Path(__file__).with_suffix(".json")
HEX = frozenset("0123456789abcdef")


def support_hashes() -> dict[str, str]:
    try:
        values = json.loads(PLAN.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("布局迁移计划不可用") from error
    valid = isinstance(values, dict) and values and all(
        isinstance(relative, str) and not relative.startswith("/") and ".." not in PurePosixPath(relative).parts
        and isinstance(digest, str) and len(digest) == 64 and set(digest) <= HEX
        for relative, digest in values.items()
    )
    if not valid:
        raise ValueError("布局迁移计划无效")
    return {relative: digest for relative, digest in values.items()}


def verify_support_hashes(root: Path, support: dict[str, str]) -> None:
    for relative, digest in support.items():
        path = root / relative
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"布局迁移支持文件哈希不匹配: {relative}")
