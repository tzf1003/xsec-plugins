#!/usr/bin/env python3
"""Build and verify the minimum protected-main policy for Factory releases.

The workflow wrapper obtains the current branch-protection document with the
GitHub REST API, passes it through this module, and writes the returned
document back.  Keeping the policy transformation local and deterministic
makes it reviewable and lets tests prove that a later console edit cannot
silently remove the two Factory merge boundaries.

This does not call GitHub and deliberately preserves unrelated required
checks/review restrictions from the existing protection document.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


GITHUB_ACTIONS_APP_ID = 15368
ANY_APP_ID = -1
# ``factory-final-merge-gate`` has an intentionally different lifetime and a
# dedicated PR-only GitHub App bypass.  It belongs to the exact-head Ruleset,
# never to this classic branch-protection document.  Retaining it here would
# let a stale classic status satisfy the finalizer or double-lock normal PRs.
REQUIRED_CLASSIC_FACTORY_CHECKS = ("source-gate",)
# Earlier revisions proposed freshness as a global required check; it does not
# provide a durable context for every PR. The finalizer gate moved to a
# separate Ruleset for the same reason.
RETIRED_CLASSIC_FACTORY_CHECKS = ("source-freshness-gate", "factory-final-merge-gate")


class ProtectionPolicyError(ValueError):
    """The live branch-protection response cannot safely be strengthened."""


def fail(message: str) -> None:
    raise ProtectionPolicyError(message)


def object_or_none(value: object, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        fail(f"{label} must be an object or null")
    return value


def enabled(value: object, label: str, *, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, dict) or not isinstance(value.get("enabled"), bool):
        fail(f"{label} must contain a boolean enabled field")
    return bool(value["enabled"])


def preserved_checks(protection: dict[str, Any]) -> dict[str, int]:
    """Normalize current required checks into the update endpoint schema.

    GitHub's GET response may carry legacy ``contexts`` separately from
    app-pinned ``checks`` and can express an unpinned check with ``app_id``
    ``null``.  The PUT endpoint represents the latter as ``app_id: -1``.  A
    context duplicated in both fields is the normal GET representation of its
    pinned check, so only legacy names absent from ``checks`` become any-app
    checks.  This preserves unrelated merge requirements while the Factory
    gates themselves are overwritten with the GitHub Actions app identity.
    """

    required = object_or_none(protection.get("required_status_checks"), "required_status_checks")
    if required is None:
        fail("main must already have branch protection before Factory policy can be enabled")
    checks = required.get("checks", [])
    if not isinstance(checks, list):
        fail("required_status_checks.checks must be a list")
    result: dict[str, int] = {}
    for check in checks:
        if not isinstance(check, dict):
            fail("required_status_checks.checks entries must be objects")
        context = check.get("context")
        app_id = check.get("app_id")
        if not isinstance(context, str) or not context:
            fail("required status check has an invalid context")
        if app_id is None:
            normalized_app_id = ANY_APP_ID
        elif isinstance(app_id, int) and not isinstance(app_id, bool):
            normalized_app_id = app_id
        else:
            fail(f"required status check {context} has an invalid app_id")
        if context in result and result[context] != normalized_app_id:
            fail(f"required status check {context} is ambiguously pinned to multiple apps")
        result[context] = normalized_app_id
    contexts = required.get("contexts", [])
    if not isinstance(contexts, list):
        fail("required_status_checks.contexts must be a list")
    for context in contexts:
        if not isinstance(context, str) or not context:
            fail("required_status_checks.contexts contains an invalid context")
        result.setdefault(context, ANY_APP_ID)
    return result


def normalized_actor_lists(value: object, label: str) -> dict[str, list[str]] | None:
    """Convert GET actor objects into the branch-protection PUT schema."""

    source = object_or_none(value, label)
    if source is None:
        return None
    result: dict[str, list[str]] = {}
    for field, identity in (("users", "login"), ("teams", "slug"), ("apps", "slug")):
        entries = source.get(field, [])
        if not isinstance(entries, list):
            fail(f"{label}.{field} must be a list")
        names: list[str] = []
        for entry in entries:
            if isinstance(entry, str):
                name = entry
            elif isinstance(entry, dict) and isinstance(entry.get(identity), str):
                name = entry[identity]
            else:
                fail(f"{label}.{field} has an invalid {identity}")
            if not name:
                fail(f"{label}.{field} has an empty {identity}")
            names.append(name)
        result[field] = names
    return result


def normalized_review_policy(value: object) -> dict[str, Any] | None:
    source = object_or_none(value, "required_pull_request_reviews")
    if source is None:
        return None
    result: dict[str, Any] = {}
    for field in (
        "dismiss_stale_reviews",
        "require_code_owner_reviews",
        "require_last_push_approval",
        "required_approving_review_count",
    ):
        if field in source:
            result[field] = source[field]
    for field in ("dismissal_restrictions", "bypass_pull_request_allowances"):
        if field in source:
            result[field] = normalized_actor_lists(source[field], f"required_pull_request_reviews.{field}")
    return result


def desired_policy(protection: dict[str, Any]) -> dict[str, Any]:
    """Return the classic protected-main payload without the finalizer gate."""

    if not isinstance(protection, dict):
        fail("branch protection response must be a JSON object")
    checks = preserved_checks(protection)
    for context in RETIRED_CLASSIC_FACTORY_CHECKS:
        checks.pop(context, None)
    for context in REQUIRED_CLASSIC_FACTORY_CHECKS:
        checks[context] = GITHUB_ACTIONS_APP_ID

    # The API returns legacy ``contexts`` even for app-pinned ``checks``. Do
    # not submit either legacy names *or an empty ``contexts`` array*: GitHub
    # rejects a request that contains both fields, even when the latter is
    # empty. Keeping only ``checks`` preserves the GitHub Actions pin, so a
    # user-created status of the same name cannot satisfy the requirement.
    required_reviews = normalized_review_policy(protection.get("required_pull_request_reviews"))
    restrictions = normalized_actor_lists(protection.get("restrictions"), "restrictions")
    return {
        "required_status_checks": {
            "strict": True,
            "checks": [
                {"context": context, "app_id": app_id}
                for context, app_id in sorted(checks.items())
            ],
        },
        "enforce_admins": True,
        "required_pull_request_reviews": required_reviews,
        "restrictions": restrictions,
        "required_linear_history": enabled(protection.get("required_linear_history"), "required_linear_history"),
        "allow_force_pushes": False,
        "allow_deletions": False,
        "block_creations": enabled(protection.get("block_creations"), "block_creations"),
        "required_conversation_resolution": True,
        "lock_branch": enabled(protection.get("lock_branch"), "lock_branch"),
        "allow_fork_syncing": enabled(protection.get("allow_fork_syncing"), "allow_fork_syncing"),
    }


def verify_policy(protection: dict[str, Any]) -> None:
    """Raise unless the live response still contains every fail-closed gate."""

    checks = preserved_checks(protection)
    for context in REQUIRED_CLASSIC_FACTORY_CHECKS:
        if checks.get(context) != GITHUB_ACTIONS_APP_ID:
            fail(f"required status check {context} is not pinned to github-actions")
    if "factory-final-merge-gate" in checks:
        fail("factory-final-merge-gate must be enforced by the dedicated finalizer Ruleset, not classic branch protection")
    required = object_or_none(protection.get("required_status_checks"), "required_status_checks")
    assert required is not None
    if required.get("strict") is not True:
        fail("required status checks must be strict")
    if enabled(protection.get("enforce_admins"), "enforce_admins") is not True:
        fail("administrators must be subject to branch protection")
    if enabled(protection.get("required_conversation_resolution"), "required_conversation_resolution") is not True:
        fail("pull-request conversations must be resolved")
    if enabled(protection.get("allow_force_pushes"), "allow_force_pushes"):
        fail("force pushes must remain disabled")
    if enabled(protection.get("allow_deletions"), "allow_deletions"):
        fail("branch deletion must remain disabled")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProtectionPolicyError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="live branch-protection GET response")
    parser.add_argument("--output", type=Path, help="write strengthened PUT payload here")
    parser.add_argument("--verify", action="store_true", help="verify input rather than generating a payload")
    args = parser.parse_args()
    if args.verify == (args.output is not None):
        parser.error("supply exactly one of --output or --verify")
    try:
        policy = read_json(args.input)
        if args.verify:
            verify_policy(policy)
        else:
            assert args.output is not None
            args.output.write_text(json.dumps(desired_policy(policy), sort_keys=True, separators=(",", ":")), encoding="utf-8")
        return 0
    except ProtectionPolicyError as error:
        print(f"Factory main protection policy failed: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
