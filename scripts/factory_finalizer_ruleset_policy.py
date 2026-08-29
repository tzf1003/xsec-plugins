#!/usr/bin/env python3
"""Manage the one exact-head finalizer Ruleset without touching other rulesets.

GitHub's classic branch-protection API cannot give the Factory finalizer a
dedicated, PR-only GitHub App bypass.  This module describes the narrowly
scoped repository Ruleset that carries that responsibility.  It intentionally
does not try to repair an existing Ruleset with the same name: a malformed
lookalike is a configuration/security incident and must be fixed explicitly
before the protected workflow can continue.

The ``XSEC_MARKETPLACE_FINALIZER_APP_ID`` value is the numeric GitHub App
integration ID.  It is emitted as the sole ``Integration`` bypass actor and
as nothing else; no actor discovery or name-based fallback is permitted.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


GITHUB_ACTIONS_INTEGRATION_ID = 15368
RULESET_NAME = "xsec-marketplace-final-exact-head"
RULESET_TARGET = "branch"
MAIN_REF = "refs/heads/main"
FINAL_GATE_CONTEXT = "factory-final-merge-gate"


class FinalizerRulesetPolicyError(ValueError):
    """A Ruleset cannot safely provide the Factory final-merge boundary."""


def fail(message: str) -> None:
    raise FinalizerRulesetPolicyError(message)


def integer(value: object, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{label} must be an integer")
    if positive and value < 1:
        fail(f"{label} must be a positive integer")
    return value


def finalizer_app_id(value: object) -> int:
    """Return the configured GitHub App integration ID, or fail closed."""

    if isinstance(value, int) and not isinstance(value, bool):
        return integer(value, "XSEC_MARKETPLACE_FINALIZER_APP_ID", positive=True)
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal():
        fail("XSEC_MARKETPLACE_FINALIZER_APP_ID must be a positive decimal GitHub App ID")
    parsed = int(value)
    if parsed < 1:
        fail("XSEC_MARKETPLACE_FINALIZER_APP_ID must be a positive decimal GitHub App ID")
    return parsed


def expected_ruleset(app_id: object) -> dict[str, Any]:
    """Build the complete create/update payload for the finalizer Ruleset."""

    integration_id = finalizer_app_id(app_id)
    return {
        "name": RULESET_NAME,
        "target": RULESET_TARGET,
        "enforcement": "active",
        "bypass_actors": [
            {
                "actor_id": integration_id,
                "actor_type": "Integration",
                "bypass_mode": "pull_request",
            }
        ],
        "conditions": {
            "ref_name": {
                "include": [MAIN_REF],
                "exclude": [],
            }
        },
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {
                            "context": FINAL_GATE_CONTEXT,
                            "integration_id": GITHUB_ACTIONS_INTEGRATION_ID,
                        }
                    ],
                    "strict_required_status_checks_policy": True,
                },
            }
        ],
    }


def object_value(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def list_value(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be a list")
    return value


def verify_ruleset(ruleset: object, app_id: object) -> None:
    """Prove a fetched same-name Ruleset is exactly the expected boundary.

    API response metadata (``id``, timestamps, URLs, source fields) is allowed,
    but every security-relevant field is exact.  In particular, extra bypass
    actors, required checks, refs, or Rules are rejected rather than silently
    retained by an update request.
    """

    source = object_value(ruleset, "ruleset")
    expected = expected_ruleset(app_id)

    if source.get("name") != RULESET_NAME:
        fail(f"ruleset name must be {RULESET_NAME}")
    if source.get("target") != RULESET_TARGET:
        fail("finalizer Ruleset target must be branch")
    if source.get("enforcement") != "active":
        fail("finalizer Ruleset enforcement must be active")

    conditions = object_value(source.get("conditions"), "ruleset.conditions")
    ref_name = object_value(conditions.get("ref_name"), "ruleset.conditions.ref_name")
    if set(conditions) != {"ref_name"}:
        fail("finalizer Ruleset may only contain a ref_name condition")
    if ref_name.get("include") != [MAIN_REF] or ref_name.get("exclude") != []:
        fail("finalizer Ruleset must target exactly refs/heads/main")

    bypass_actors = list_value(source.get("bypass_actors"), "ruleset.bypass_actors")
    if bypass_actors != expected["bypass_actors"]:
        fail("finalizer Ruleset must have exactly one PR-only configured GitHub App bypass actor")

    rules = list_value(source.get("rules"), "ruleset.rules")
    if len(rules) != 1:
        fail("finalizer Ruleset must have exactly one rule")
    rule = object_value(rules[0], "ruleset.rules[0]")
    if rule.get("type") != "required_status_checks":
        fail("finalizer Ruleset must use required_status_checks")
    if set(rule) != {"type", "parameters"}:
        fail("finalizer Ruleset required-status rule has unexpected fields")
    parameters = object_value(rule.get("parameters"), "ruleset.rules[0].parameters")
    expected_parameters = expected["rules"][0]["parameters"]
    if parameters != expected_parameters:
        fail("finalizer Ruleset required status policy is not the exact GitHub-Actions strict final gate")


def management_plan(rulesets: object, app_id: object) -> dict[str, Any]:
    """Return the only allowed create/update plan without inspecting others.

    The list endpoint returns a *summary* of each Ruleset, not necessarily its
    security-sensitive conditions, bypass actors, or rules.  It may therefore
    only identify a unique same-name ID.  The protected caller must fetch that
    exact ID and run ``verify_ruleset`` before any PUT; treating a summary as a
    complete policy would make the create path fail or, worse, confuse an API
    shape change with a valid ruleset.
    """

    entries = list_value(rulesets, "repository rulesets response")
    matches: list[dict[str, Any]] = []
    for index, candidate in enumerate(entries):
        item = object_value(candidate, f"repository rulesets response[{index}]")
        name = item.get("name")
        if not isinstance(name, str):
            fail(f"repository rulesets response[{index}].name must be a string")
        if name == RULESET_NAME:
            matches.append(item)
    if len(matches) > 1:
        fail(f"more than one Ruleset is named {RULESET_NAME}")

    desired = expected_ruleset(app_id)
    if not matches:
        return {"action": "create", "ruleset_id": None, "ruleset": desired}

    existing = matches[0]
    return {
        "action": "update",
        "ruleset_id": integer(existing.get("id"), "finalizer Ruleset id", positive=True),
        "ruleset": desired,
    }


def read_json(path: Path, *, expect: type[list[Any]] | type[dict[str, Any]]) -> Any:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FinalizerRulesetPolicyError(f"cannot read {path}: {error}") from error
    if not isinstance(value, expect):
        name = "JSON array" if expect is list else "JSON object"
        fail(f"{path} must contain a {name}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--finalizer-app-id",
        default=os.environ.get("XSEC_MARKETPLACE_FINALIZER_APP_ID"),
        help="numeric GitHub App integration ID (defaults to XSEC_MARKETPLACE_FINALIZER_APP_ID)",
    )
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--rulesets", type=Path, help="GET /repos/{owner}/{repo}/rulesets response")
    modes.add_argument("--ruleset", type=Path, help="one GET/POST/PUT repository Ruleset response")
    parser.add_argument("--output", type=Path, help="write a create/update plan when using --rulesets")
    parser.add_argument("--verify", action="store_true", help="verify --ruleset instead of planning")
    args = parser.parse_args()
    if args.rulesets is not None and args.output is None:
        parser.error("--rulesets requires --output")
    if args.ruleset is not None and not args.verify:
        parser.error("--ruleset requires --verify")
    if args.rulesets is not None and args.verify:
        parser.error("--verify is only valid with --ruleset")

    try:
        app_id = finalizer_app_id(args.finalizer_app_id)
        if args.rulesets is not None:
            plan = management_plan(read_json(args.rulesets, expect=list), app_id)
            assert args.output is not None
            args.output.write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        else:
            assert args.ruleset is not None
            verify_ruleset(read_json(args.ruleset, expect=dict), app_id)
        return 0
    except FinalizerRulesetPolicyError as error:
        print(f"Factory finalizer Ruleset policy failed: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
