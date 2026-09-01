#!/usr/bin/env python3
"""Classify and fail closed on validated Marketplace publication merges.

The release workflows only create source-gated pull requests. This helper runs
against the protected ``main`` push after that PR is merged. It derives
the publication channel from the immutable release-index delta and signed
Factory layout, never from a PR title or a user-editable merge subject.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from build_market import SNAPSHOT_ROOT_RELATIVE_PATH, load_release_document
from kms_marketplace_publisher import OFFICIAL_STATUS_PURPOSE, MarketplaceKmsPublisherError, marketplace_documents, sidecar_path_for


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ID_PATTERN = r"[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?"
SNAPSHOT_ROOT = SNAPSHOT_ROOT_RELATIVE_PATH.as_posix()
RELEASE_PATH_PATTERN = re.compile(rf"^{re.escape(SNAPSHOT_ROOT)}/({PLUGIN_ID_PATTERN})/\.xsec-market/releases\.json$")
RELEASE_SIDECAR_PATTERN = re.compile(rf"^{re.escape(SNAPSHOT_ROOT)}/{PLUGIN_ID_PATTERN}/\.xsec-market/releases\.json\.sig\.jws\.json$")
PLUGIN_PATH_PATTERN = re.compile(rf"^{re.escape(SNAPSHOT_ROOT)}/({PLUGIN_ID_PATTERN})/(.+)$")
MARKETPLACE_SOURCE_PATH_PATTERN = re.compile(rf"^\./{re.escape(SNAPSHOT_ROOT)}/({PLUGIN_ID_PATTERN})$")
PUBLICATION_PATH_PATTERN = re.compile(rf"^\.xsec-factory/official-publications/({PLUGIN_ID_PATTERN})\.json$")
PUBLICATION_PROOF_PATTERN = re.compile(rf"^\.xsec-factory/official-publication-proofs/({PLUGIN_ID_PATTERN})\.json$")
ADOPTION_PATH_PATTERN = re.compile(rf"^\.xsec-factory/official-adoptions/({PLUGIN_ID_PATTERN})\.json$")
ADOPTION_PROOF_PATTERN = re.compile(rf"^\.xsec-factory/official-adoption-proofs/({PLUGIN_ID_PATTERN})\.json$")
STATUS_PATH_PATTERN = re.compile(rf"^\.xsec-factory/official-status/({PLUGIN_ID_PATTERN})\.json$")
STATUS_PROOF_PATTERN = re.compile(rf"^\.xsec-factory/official-status-proofs/({PLUGIN_ID_PATTERN})\.json$")
GITLINK_PATH_PATTERN = re.compile(rf"^plugins/({PLUGIN_ID_PATTERN})$")
MARKETPLACE_INDEX = ".agents/plugins/marketplace.json"
MARKETPLACE_SIDECAR = ".agents/plugins/marketplace.json.sig.jws.json"
REGISTRY_PATH = ".xsec-factory/official-registry.json"
PROJECT_WORKSPACE_PLUGIN_ID = "com.xsec.project-workspace"
SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99}[A-Za-z0-9])?$")


class PromotionVerificationError(ValueError):
    """The protected-main change is not a safe validated publication."""


def fail(message: str) -> None:
    raise PromotionVerificationError(message)


def git_bytes(root: Path, arguments: list[str]) -> bytes:
    environment = os.environ.copy()
    environment.pop("GIT_REPLACE_REF_BASE", None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    completed = subprocess.run(
        ["git", "--no-replace-objects", *arguments],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"Git verification command failed: {detail or 'unknown error'}")
    return completed.stdout


def git_text(root: Path, arguments: list[str]) -> str:
    return git_bytes(root, arguments).decode("utf-8", errors="strict").strip()


def git_succeeds(root: Path, arguments: list[str]) -> bool:
    environment = os.environ.copy()
    environment.pop("GIT_REPLACE_REF_BASE", None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return subprocess.run(
        ["git", "--no-replace-objects", *arguments],
        cwd=str(root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        check=False,
    ).returncode == 0


def json_blob(root: Path, revision: str, path: str, label: str) -> dict[str, object]:
    try:
        value = json.loads(git_bytes(root, ["show", f"{revision}:{path}"]).decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, PromotionVerificationError) as error:
        raise PromotionVerificationError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def release_document_from_blob(plugin_id: str, payload: bytes) -> dict[str, object]:
    """Use the shared strict parser without trusting worktree conversion."""

    with tempfile.TemporaryDirectory(prefix="xsec-merged-marketplace-release-") as directory:
        path = Path(directory) / "releases.json"
        path.write_bytes(payload)
        try:
            return load_release_document(path, plugin_id)
        except (OSError, ValueError) as error:
            raise PromotionVerificationError(f"merged release history is invalid for {plugin_id}: {error}") from error


def empty_release_document(plugin_id: str) -> dict[str, object]:
    """Return the exact v2 in-memory shape for a plugin with no prior release.

    ``build_market.load_release_document`` deliberately treats a missing
    release index as an empty history so the Factory can publish a newly added
    plugin for the first time.  Protected-main verification must use the same
    baseline semantics, while still requiring the post-change index to exist
    and pass the strict parser.
    """

    return {
        "schemaVersion": 2,
        "pluginId": plugin_id,
        "releases": [],
        "channels": {"beta": {"releaseId": None}, "stable": None},
    }


def release_pointer(document: dict[str, object], channel: str) -> str | None:
    channels = document.get("channels")
    pointer = channels.get(channel) if isinstance(channels, dict) else None
    value = pointer.get("releaseId") if isinstance(pointer, dict) else None
    if value is not None and not isinstance(value, str):
        fail(f"merged {channel} pointer is invalid")
    return value


def changed_paths(root: Path, before: str, after: str) -> list[str]:
    return [path for path in git_text(root, ["diff", "--name-only", "--no-renames", before, after]).splitlines() if path]


def require_candidate_revisions(root: Path, before: str, after: str) -> None:
    """Require a candidate range rooted in the exact protected-main base.

    The final-merge workflow already makes this check before constructing its
    detached candidate worktree.  Keeping it here means the narrow, non-release
    Factory candidates get the same fail-closed contract as publication diffs
    when this helper is used independently.
    """

    if not SHA_PATTERN.fullmatch(before) or not SHA_PATTERN.fullmatch(after):
        fail("before and after must be lowercase 40-character Git SHAs")
    if not git_succeeds(root, ["merge-base", "--is-ancestor", before, after]):
        fail("Factory candidate must retain the protected-main base revision")


def exact_changed_paths(root: Path, before: str, after: str, expected: set[str], label: str) -> None:
    """Reject additions, deletions, renames, and unrelated candidate paths."""

    paths = changed_paths(root, before, after)
    if len(paths) != len(expected) or set(paths) != expected:
        unexpected = sorted(set(paths).symmetric_difference(expected))
        fail(f"{label} changed an unauthorized path set: {', '.join(unexpected) or '<duplicate paths>'}")


def verify_first_party_adoption_candidate(root: Path, before: str, after: str) -> dict[str, object]:
    """Authenticate one of the two non-release first-party adoption PRs.

    Cloud KMS cannot attest bytes that only exist in the workflow checkout. A
    protected staging PR therefore adds the immutable unsigned assertion first;
    a later KMS-generated activation PR adds only its sidecar and flips the
    validated Registry row. Both diffs are deliberately narrow so neither can
    carry arbitrary Factory or workflow changes through the finalizer.
    """

    require_candidate_revisions(root, before, after)
    paths = changed_paths(root, before, after)
    adoption_paths = [path for path in paths if ADOPTION_PATH_PATTERN.fullmatch(path)]
    proof_paths = [path for path in paths if ADOPTION_PROOF_PATTERN.fullmatch(path)]

    if len(adoption_paths) == 1 and not proof_paths:
        adoption_path = adoption_paths[0]
        match = ADOPTION_PATH_PATTERN.fullmatch(adoption_path)
        if match is None:  # Defensive: the filtered list above guarantees this.
            fail("first-party adoption staging candidate has an invalid adoption document path")
        plugin_id = match.group(1)
        exact_changed_paths(root, before, after, {adoption_path}, "first-party adoption staging candidate")
        if git_succeeds(root, ["cat-file", "-e", f"{before}:{adoption_path}"]) or not git_succeeds(
            root, ["cat-file", "-e", f"{after}:{adoption_path}"]
        ):
            fail("first-party adoption staging candidate must add exactly one adoption document")
        proof_path = f".xsec-factory/official-adoption-proofs/{plugin_id}.json"
        if git_succeeds(root, ["cat-file", "-e", f"{before}:{proof_path}"]) or git_succeeds(
            root, ["cat-file", "-e", f"{after}:{proof_path}"]
        ):
            fail("first-party adoption staging candidate must not contain a KMS sidecar")
        before_registry = git_bytes(root, ["show", f"{before}:{REGISTRY_PATH}"])
        after_registry = git_bytes(root, ["show", f"{after}:{REGISTRY_PATH}"])
        if before_registry != after_registry:
            fail("first-party adoption staging candidate may not modify the Registry")
        registry = json_blob(root, after, REGISTRY_PATH, "candidate official Factory registry")
        entries = registry.get("plugins")
        matching = [entry for entry in entries if isinstance(entry, dict) and entry.get("pluginId") == plugin_id] if isinstance(entries, list) else []
        if len(matching) != 1 or matching[0].get("status") != "pending-adoption":
            fail("first-party adoption staging candidate must retain one pending Registry entry")
        return {"kind": "adoption-stage", "plugin_id": plugin_id, "adoption_path": adoption_path}

    if not adoption_paths and len(proof_paths) == 1:
        proof_path = proof_paths[0]
        match = ADOPTION_PROOF_PATTERN.fullmatch(proof_path)
        if match is None:  # Defensive: the filtered list above guarantees this.
            fail("first-party adoption activation candidate has an invalid KMS proof path")
        plugin_id = match.group(1)
        adoption_path = f".xsec-factory/official-adoptions/{plugin_id}.json"
        exact_changed_paths(root, before, after, {REGISTRY_PATH, proof_path}, "first-party adoption activation candidate")
        if not git_succeeds(root, ["cat-file", "-e", f"{before}:{adoption_path}"]) or not git_succeeds(
            root, ["cat-file", "-e", f"{after}:{adoption_path}"]
        ) or git_bytes(root, ["show", f"{before}:{adoption_path}"]) != git_bytes(root, ["show", f"{after}:{adoption_path}"]):
            fail("first-party adoption activation candidate must retain its validated adoption document byte-for-byte")
        if git_succeeds(root, ["cat-file", "-e", f"{before}:{proof_path}"]) or not git_succeeds(
            root, ["cat-file", "-e", f"{after}:{proof_path}"]
        ):
            fail("first-party adoption activation candidate must add one matching KMS proof")
        before_registry = json_blob(root, before, REGISTRY_PATH, "baseline official Factory registry")
        after_registry = json_blob(root, after, REGISTRY_PATH, "candidate official Factory registry")
        before_plugins = before_registry.get("plugins")
        after_plugins = after_registry.get("plugins")
        if not isinstance(before_plugins, list) or not isinstance(after_plugins, list) or len(before_plugins) != len(after_plugins):
            fail("first-party adoption activation candidate must preserve the Registry plugin list")
        if {key: value for key, value in before_registry.items() if key != "plugins"} != {
            key: value for key, value in after_registry.items() if key != "plugins"
        }:
            fail("first-party adoption activation candidate may not modify Registry metadata")
        seen = 0
        for before_entry, after_entry in zip(before_plugins, after_plugins, strict=True):
            if not isinstance(before_entry, dict) or not isinstance(after_entry, dict):
                fail("first-party adoption activation candidate Registry entries must be objects")
            if before_entry.get("pluginId") != after_entry.get("pluginId"):
                fail("first-party adoption activation candidate may not reorder or replace Registry entries")
            if before_entry.get("pluginId") == plugin_id:
                seen += 1
                if before_entry.get("status") != "pending-adoption" or after_entry.get("status") != "active":
                    fail("first-party adoption activation candidate must change its one Registry entry from pending-adoption to active")
                if {key: value for key, value in before_entry.items() if key != "status"} != {
                    key: value for key, value in after_entry.items() if key != "status"
                }:
                    fail("first-party adoption activation candidate may only change its Registry status")
            elif before_entry != after_entry:
                fail("first-party adoption activation candidate may not modify another Registry entry")
        if seen != 1:
            fail("first-party adoption activation candidate must activate exactly one pending Registry entry")
        return {"kind": "adoption-activation", "plugin_id": plugin_id, "adoption_path": adoption_path}

    fail("first-party adoption candidate must be exactly one staging or one activation transition")


def verify_retained_sidecar_refresh_candidate(root: Path, before: str, after: str) -> dict[str, object]:
    """Require a repair candidate to modify one retained release JWS sidecar.

    This is intentionally separate from normal ``maintenance`` classification:
    a Factory-managed repair is eligible for a final exact-head gate only when
    it cannot carry any Marketplace, source, artifact, Registry, or workflow
    change alongside its newly issued detached JWS.
    """

    require_candidate_revisions(root, before, after)
    paths = changed_paths(root, before, after)
    if len(paths) != 1 or RELEASE_SIDECAR_PATTERN.fullmatch(paths[0]) is None:
        fail("retained sidecar refresh candidate must change exactly one releases.json KMS sidecar")
    # RELEASE_SIDECAR_PATTERN intentionally has no capture group because it is
    # also used as a boolean allowlist elsewhere. The validated path has the
    # fixed Factory snapshot form, so extracting this component is
    # unambiguous after the full-match check above.
    plugin_id = paths[0].split("/", 3)[2]
    release_path = f"{SNAPSHOT_ROOT}/{plugin_id}/.xsec-market/releases.json"
    if not git_succeeds(root, ["cat-file", "-e", f"{before}:{release_path}"]) or not git_succeeds(
        root, ["cat-file", "-e", f"{after}:{release_path}"]
    ):
        fail("retained sidecar refresh candidate must retain its immutable release index")
    if git_bytes(root, ["show", f"{before}:{release_path}"]) != git_bytes(root, ["show", f"{after}:{release_path}"]):
        fail("retained sidecar refresh candidate may not modify its immutable release index")
    return {"kind": "retained-sidecar-refresh", "plugin_id": plugin_id, "sidecar_path": paths[0]}


def allowed_paths(
    channel: str,
    paths: list[str],
    promoted_ids: set[str],
    *,
    renewable_sidecars: set[str],
    first_party_gitlink_ids: set[str] | None = None,
) -> None:
    """Permit only the generated Factory surfaces for a signed release PR."""

    for path in paths:
        if path in renewable_sidecars or RELEASE_PATH_PATTERN.fullmatch(path):
            continue
        if channel == "beta" and path == MARKETPLACE_INDEX:
            continue
        plugin_path = PLUGIN_PATH_PATTERN.fullmatch(path)
        if channel == "beta" and plugin_path and plugin_path.group(1) in promoted_ids:
            # Source snapshots and newly-built immutable artifacts belong only
            # to a release index whose Beta pointer advances in this PR.
            continue
        gitlink_path = GITLINK_PATH_PATTERN.fullmatch(path)
        if channel == "beta" and gitlink_path and first_party_gitlink_ids and gitlink_path.group(1) in first_party_gitlink_ids:
            continue
        publication_path = PUBLICATION_PATH_PATTERN.fullmatch(path)
        if publication_path and publication_path.group(1) in promoted_ids:
            continue
        publication_proof = PUBLICATION_PROOF_PATTERN.fullmatch(path)
        if publication_proof and publication_proof.group(1) in promoted_ids:
            continue
        adoption_path = ADOPTION_PATH_PATTERN.fullmatch(path)
        if adoption_path and adoption_path.group(1) in promoted_ids:
            continue
        adoption_proof = ADOPTION_PROOF_PATTERN.fullmatch(path)
        if adoption_proof and adoption_proof.group(1) in promoted_ids:
            continue
        status_path = STATUS_PATH_PATTERN.fullmatch(path)
        if status_path and status_path.group(1) in promoted_ids:
            continue
        status_proof = STATUS_PROOF_PATTERN.fullmatch(path)
        if status_proof and status_proof.group(1) in promoted_ids:
            continue
        fail(f"merged {channel} publication changed an unauthorized path: {path}")


def renewable_sidecars(root: Path, promoted_ids: set[str]) -> set[str]:
    """Allow only the current immutable KMS batch and promoted releases."""

    try:
        root_path = root.resolve(strict=True)
        active = {
            sidecar_path_for(document).resolve(strict=False).relative_to(root_path).as_posix()
            for document in marketplace_documents(root)
            if document.purpose != OFFICIAL_STATUS_PURPOSE
        }
    except (MarketplaceKmsPublisherError, OSError, ValueError) as error:
        raise PromotionVerificationError("publication has an invalid active KMS document layout") from error
    active.update(f"{SNAPSHOT_ROOT}/{plugin_id}/.xsec-market/releases.json.sig.jws.json" for plugin_id in promoted_ids)
    return active


def one_plugin_entry(
    document: dict[str, object],
    *,
    key: str,
    id_key: str,
    plugin_id: str,
    label: str,
) -> tuple[list[object], int, dict[str, object]]:
    entries = document.get(key)
    if not isinstance(entries, list):
        fail(f"{label} has no {key} list")
    matches = [
        (index, entry)
        for index, entry in enumerate(entries)
        if isinstance(entry, dict) and entry.get(id_key) == plugin_id
    ]
    if len(matches) != 1:
        fail(f"{label} must contain one {plugin_id} entry")
    index, entry = matches[0]
    return entries, index, entry


def verify_default_set_payloads(
    *,
    before_registry: dict[str, object],
    after_registry: dict[str, object],
    before_marketplace: dict[str, object],
    after_marketplace: dict[str, object],
) -> None:
    before_rows, registry_index, before_row = one_plugin_entry(
        before_registry,
        key="plugins",
        id_key="pluginId",
        plugin_id=PROJECT_WORKSPACE_PLUGIN_ID,
        label="Factory registry",
    )
    after_rows = after_registry.get("plugins")
    expected_row = dict(before_row)
    expected_row["status"] = "disabled"
    if before_row.get("trustTier") != "first-party" or before_row.get("status") != "active":
        fail("project workspace must start as an active first-party Registry entry")
    expected_registry = dict(before_registry)
    expected_registry["plugins"] = [*before_rows[:registry_index], expected_row, *before_rows[registry_index + 1 :]]
    if after_registry != expected_registry or not isinstance(after_rows, list):
        fail("default-set transition may only disable the project workspace Registry entry")
    before_entries, market_index, removed = one_plugin_entry(
        before_marketplace,
        key="plugins",
        id_key="name",
        plugin_id=PROJECT_WORKSPACE_PLUGIN_ID,
        label="Marketplace index",
    )
    expected_marketplace = dict(before_marketplace)
    expected_marketplace["plugins"] = [*before_entries[:market_index], *before_entries[market_index + 1 :]]
    if removed.get("policy") != {"installation": "INSTALLED_BY_DEFAULT", "authentication": "ON_INSTALL"}:
        fail("project workspace Marketplace entry has an invalid default policy")
    if after_marketplace != expected_marketplace:
        fail("default-set transition may only remove project workspace from discovery")


def verify_default_set_transition(root: Path, before: str, after: str) -> dict[str, object]:
    require_candidate_revisions(root, before, after)
    paths = changed_paths(root, before, after)
    expected_paths = renewable_sidecars(root, set()) | {MARKETPLACE_INDEX, REGISTRY_PATH}
    if set(paths) != expected_paths or len(paths) != len(expected_paths):
        fail("default-set transition changed paths outside the KMS-authenticated maintenance batch")
    verify_default_set_payloads(
        before_registry=json_blob(root, before, REGISTRY_PATH, "prior Factory registry"),
        after_registry=json_blob(root, after, REGISTRY_PATH, "candidate Factory registry"),
        before_marketplace=json_blob(root, before, MARKETPLACE_INDEX, "prior Marketplace index"),
        after_marketplace=json_blob(root, after, MARKETPLACE_INDEX, "candidate Marketplace index"),
    )
    return {"kind": "default-set-maintenance", "plugin_id": PROJECT_WORKSPACE_PLUGIN_ID, "promotions": []}


def active_registered_source(
    root: Path,
    revision: str,
    *,
    plugin_id: str,
) -> dict[str, str] | None:
    """Return the fixed source identity for one active Registry v2 row.

    The publication and no-pointer smoke-cycle classifiers both need this
    check.  Keeping it independent of an appended provenance event is
    important: reopening a smoke cycle deliberately reuses an existing,
    immutable Beta event instead of manufacturing another one.
    """

    if not git_succeeds(root, ["cat-file", "-e", f"{revision}:{REGISTRY_PATH}"]):
        return None
    registry = json_blob(root, revision, REGISTRY_PATH, "official Factory registry")
    entries = registry.get("plugins")
    if not isinstance(entries, list):
        fail("official Factory registry has no plugin list")
    matching = [entry for entry in entries if isinstance(entry, dict) and entry.get("pluginId") == plugin_id]
    if not matching:
        return None
    if len(matching) != 1:
        fail(f"official Factory registry has duplicate {plugin_id} rows")
    registration = matching[0]
    if registration.get("status") != "active":
        fail(f"registered publication plugin {plugin_id} is not active")
    source = registration.get("source")
    trust_tier = registration.get("trustTier")
    if (
        trust_tier not in {"external", "first-party"}
        or not isinstance(source, dict)
        or not isinstance(source.get("repository"), str)
        or not REPOSITORY_PATTERN.fullmatch(source["repository"])
        or not isinstance(source.get("path"), str)
    ):
        fail(f"registered publication plugin {plugin_id} has invalid source identity")
    refs = source.get("refs")
    if not isinstance(refs, dict) or refs.get("beta") != "refs/heads/beta" or refs.get("stable") != "refs/heads/main":
        fail(f"registered publication plugin {plugin_id} has invalid source refs")
    return {
        "repository": str(source["repository"]),
        "path": str(source["path"]),
        "beta_ref": "refs/heads/beta",
        "stable_ref": "refs/heads/main",
        "trust_tier": str(trust_tier),
    }


def gitlink_revision(root: Path, revision: str, plugin_id: str) -> str | None:
    """Read one exact Gitlink revision without consulting its worktree."""

    path = f"plugins/{plugin_id}"
    listing = git_text(root, ["ls-tree", revision, "--", path])
    if not listing:
        return None
    try:
        header, listed_path = listing.split("\t", maxsplit=1)
        mode, object_type, source_sha = header.split(" ", maxsplit=2)
    except ValueError as error:
        raise PromotionVerificationError("first-party Gitlink tree entry is invalid") from error
    if listed_path != path or mode != "160000" or object_type != "commit" or not SHA_PATTERN.fullmatch(source_sha):
        fail("first-party Gitlink tree entry is invalid")
    return source_sha


def require_first_party_gitlink(
    root: Path,
    before: str,
    after: str,
    *,
    plugin_id: str,
    source: dict[str, str],
) -> str | None:
    """Bind a first-party Beta publication to its exact source Gitlink."""

    identity = active_registered_source(root, after, plugin_id=plugin_id)
    if identity is None or identity["trust_tier"] != "first-party":
        return None
    path = f"plugins/{plugin_id}"
    if identity["path"] != path:
        fail("first-party publication has an invalid source path")
    before_sha = gitlink_revision(root, before, plugin_id)
    after_sha = gitlink_revision(root, after, plugin_id)
    if after_sha != source["sha"]:
        fail("first-party Beta publication Gitlink does not match its authenticated source SHA")
    if before_sha == after_sha:
        fail("first-party Beta publication did not advance its Gitlink")
    return path


def registry_source_binding(
    root: Path,
    before: str,
    after: str,
    *,
    plugin_id: str,
    channel: str,
    release_id: str,
) -> dict[str, str] | None:
    """Return the newly-recorded source tuple for a registered plugin.

    Legacy built-ins have no Registry v2 row and deliberately return ``None``.
    Registered plugins must append one exact provenance event in this PR; an
    earlier event cannot be replayed after its source branch has moved.
    """

    source = active_registered_source(root, after, plugin_id=plugin_id)
    if source is None:
        return None
    expected_ref = source["beta_ref"] if channel == "beta" else source["stable_ref"]
    evidence_path = f".xsec-factory/official-publications/{plugin_id}.json"
    if not git_succeeds(root, ["cat-file", "-e", f"{after}:{evidence_path}"]):
        fail(f"registered publication plugin {plugin_id} lacks immutable source evidence")
    after_evidence = json_blob(root, after, evidence_path, f"publication evidence for {plugin_id}")
    after_events = after_evidence.get("events")
    if not isinstance(after_events, list):
        fail(f"publication evidence for {plugin_id} has invalid events")
    before_events: list[object] = []
    if git_succeeds(root, ["cat-file", "-e", f"{before}:{evidence_path}"]):
        before_evidence = json_blob(root, before, evidence_path, f"baseline publication evidence for {plugin_id}")
        value = before_evidence.get("events")
        if not isinstance(value, list):
            fail(f"baseline publication evidence for {plugin_id} has invalid events")
        before_events = value
    if after_events[: len(before_events)] != before_events:
        fail(f"publication evidence for {plugin_id} rewrote historical events")
    matches: list[dict[str, object]] = []
    for event in after_events[len(before_events) :]:
        if not isinstance(event, dict) or event.get("channel") != channel or event.get("releaseId") != release_id:
            continue
        event_source = event.get("source")
        if not isinstance(event_source, dict):
            continue
        if (
            event_source.get("repository") == source["repository"]
            and event_source.get("path") == source["path"]
            and event_source.get("ref") == expected_ref
            and isinstance(event_source.get("sha"), str)
            and SHA_PATTERN.fullmatch(event_source["sha"])
        ):
            matches.append(event_source)
    if len(matches) != 1:
        fail(f"registered publication plugin {plugin_id} must append one exact {channel} source event")
    return {"repository": source["repository"], "ref": expected_ref, "sha": str(matches[0]["sha"])}


def beta_main_gate_binding(
    root: Path,
    after: str,
    *,
    plugin_id: str,
    release_id: str,
    beta_source: dict[str, str],
) -> dict[str, str]:
    """Read the main SHA that made a registered Beta's smoke decision.

    Release provenance authenticates the immutable Beta source, but is silent
    about the concurrently compared ``main`` ref.  The Factory status is the
    only permitted place for that transient, review-bound decision.  Require
    it for every registered Beta PR so a later main push cannot turn an old
    green result into an unvalidated Desktop smoke request.
    """

    identity = active_registered_source(root, after, plugin_id=plugin_id)
    if identity is None:
        fail("registered Beta smoke gate has no active source identity")
    status_path = f".xsec-factory/official-status/{plugin_id}.json"
    if not git_succeeds(root, ["cat-file", "-e", f"{after}:{status_path}"]):
        fail(f"registered Beta publication plugin {plugin_id} has no Factory status")
    status = json_blob(root, after, status_path, f"Factory status for {plugin_id}")
    source = status.get("source")
    release = status.get("release")
    publication = status.get("publication")
    if not isinstance(source, dict) or not isinstance(release, dict) or not isinstance(publication, dict):
        fail(f"registered Beta publication plugin {plugin_id} has malformed Factory status")
    if set(source) != {"repository", "path", "refs", "betaSha", "stableSha", "mainGateSha"}:
        fail(f"registered Beta publication plugin {plugin_id} Factory status has invalid source fields")
    if (
        source.get("repository") != identity["repository"]
        or source.get("path") != identity["path"]
        or source.get("refs") != {"beta": identity["beta_ref"], "stable": identity["stable_ref"]}
        or source.get("betaSha") != beta_source["sha"]
        or source.get("stableSha") is not None
        or not isinstance(source.get("mainGateSha"), str)
        or not SHA_PATTERN.fullmatch(source["mainGateSha"])
    ):
        fail(f"registered Beta publication plugin {plugin_id} Factory status is not bound to its Beta/main source tuple")
    if release.get("betaReleaseId") != release_id or publication.get("state") not in {"waiting_for_beta", "waiting_for_smoke"}:
        fail(f"registered Beta publication plugin {plugin_id} Factory status is not an in-flight Beta smoke gate")
    if publication.get("smokeRunUrl") is not None or publication.get("marketplaceRevision") is not None:
        fail(f"registered Beta publication plugin {plugin_id} Factory status prematurely claims smoke evidence")
    return {"repository": identity["repository"], "ref": identity["stable_ref"], "sha": source["mainGateSha"]}


def verify_merged_publication(root: Path, before: str, after: str, channel: str) -> dict[str, object]:
    if not SHA_PATTERN.fullmatch(before) or not SHA_PATTERN.fullmatch(after):
        fail("before and after must be lowercase 40-character Git SHAs")
    if channel not in {"beta", "stable"}:
        fail("channel must be beta or stable")
    if not git_succeeds(root, ["merge-base", "--is-ancestor", before, after]):
        fail("protected main push must retain the prior protected revision")
    paths = changed_paths(root, before, after)
    release_paths = [(match.group(1), path) for path in paths if (match := RELEASE_PATH_PATTERN.fullmatch(path))]
    if not paths:
        fail("merged publication did not change any Factory files")
    if MARKETPLACE_SIDECAR not in paths or not release_paths:
        fail("merged publication must refresh the Marketplace sidecar and at least one release index")

    promoted: list[dict[str, object]] = []
    promoted_ids = {plugin_id for plugin_id, _ in release_paths}
    first_party_gitlink_ids = {
        plugin_id
        for plugin_id in promoted_ids
        if (identity := active_registered_source(root, after, plugin_id=plugin_id)) is not None
        and identity["trust_tier"] == "first-party"
    }
    allowed_paths(
        channel,
        paths,
        promoted_ids,
        renewable_sidecars=renewable_sidecars(root, promoted_ids),
        first_party_gitlink_ids=first_party_gitlink_ids,
    )
    for plugin_id, release_path in release_paths:
        sidecar = f"{SNAPSHOT_ROOT}/{plugin_id}/.xsec-market/releases.json.sig.jws.json"
        if sidecar not in paths:
            fail("merged publication must refresh every changed release KMS sidecar")
        if git_succeeds(root, ["cat-file", "-e", f"{before}:{release_path}"]):
            before_document = release_document_from_blob(plugin_id, git_bytes(root, ["show", f"{before}:{release_path}"]))
        else:
            before_document = empty_release_document(plugin_id)
        after_document = release_document_from_blob(plugin_id, git_bytes(root, ["show", f"{after}:{release_path}"]))
        before_stable = release_pointer(before_document, "stable")
        after_stable = release_pointer(after_document, "stable")
        before_beta = release_pointer(before_document, "beta")
        after_beta = release_pointer(after_document, "beta")
        if channel == "stable":
            if before_document.get("releases") != after_document.get("releases"):
                fail("merged Stable promotion rewrote immutable release history")
            if before_beta != after_beta:
                fail("merged Stable promotion changed the Beta pointer")
            if after_stable is None or after_stable == before_stable:
                fail("merged Stable promotion did not move the Stable pointer")
            release_id = after_stable
        else:
            before_records = before_document.get("releases")
            after_records = after_document.get("releases")
            if not isinstance(before_records, list) or not isinstance(after_records, list):
                fail("merged Beta publication has invalid immutable release history")
            if after_records[: len(before_records)] != before_records:
                fail("merged Beta publication rewrote immutable release history")
            if after_stable != before_stable:
                fail("merged Beta publication changed the Stable pointer")
            if after_beta is None or after_beta == before_beta:
                fail("merged Beta publication did not move the Beta pointer")
            if not after_records or not isinstance(after_records[-1], dict) or after_records[-1].get("releaseId") != after_beta:
                fail("merged Beta publication must select its appended immutable release")
            release_id = after_beta
        source = registry_source_binding(root, before, after, plugin_id=plugin_id, channel=channel, release_id=release_id)
        record: dict[str, object] = {"plugin_id": plugin_id, "release_id": release_id}
        if source is not None:
            record["source"] = source
            if channel == "beta":
                require_first_party_gitlink(root, before, after, plugin_id=plugin_id, source=source)
                record["main_source"] = beta_main_gate_binding(
                    root,
                    after,
                    plugin_id=plugin_id,
                    release_id=release_id,
                    beta_source=source,
                )
        promoted.append(record)
    if channel == "stable" and not promoted:
        fail("merged Stable promotion must change at least one releases.json document")
    return {"kind": channel, "promotions": promoted}


def verify_stable_maintenance(root: Path, before: str, after: str, paths: list[str]) -> dict[str, object]:
    """Authenticate an external Stable completion that moves no pointer.

    A source-main callback can be idempotent when Stable already selects the
    current Beta release. It still needs one newly signed provenance event and
    status update, but must never look like a fresh beta build or a Desktop
    smoke publication. Return its exact source tuple so the final merge gate
    can reject a ref that advanced while this completion waited for review.
    """

    publications = [
        match.group(1)
        for path in paths
        if (match := PUBLICATION_PATH_PATTERN.fullmatch(path))
    ]
    statuses = [match.group(1) for path in paths if (match := STATUS_PATH_PATTERN.fullmatch(path))]
    if len(publications) != 1 or len(statuses) != 1 or statuses[0] != publications[0]:
        fail("no-pointer Stable completion must change one matching provenance and status document")
    plugin_id = publications[0]
    evidence_proof = f".xsec-factory/official-publication-proofs/{plugin_id}.json"
    if evidence_proof not in paths:
        fail("no-pointer Stable completion must refresh its provenance KMS sidecar")
    release_path = f"{SNAPSHOT_ROOT}/{plugin_id}/.xsec-market/releases.json"
    if not git_succeeds(root, ["cat-file", "-e", f"{before}:{release_path}"]) or not git_succeeds(
        root, ["cat-file", "-e", f"{after}:{release_path}"]
    ):
        fail("no-pointer Stable completion has no retained release index")
    before_document = release_document_from_blob(plugin_id, git_bytes(root, ["show", f"{before}:{release_path}"]))
    after_document = release_document_from_blob(plugin_id, git_bytes(root, ["show", f"{after}:{release_path}"]))
    if before_document != after_document:
        fail("no-pointer Stable completion rewrote its immutable release index")
    beta_release = release_pointer(after_document, "beta")
    stable_release = release_pointer(after_document, "stable")
    if beta_release is None or stable_release != beta_release:
        fail("no-pointer Stable completion must retain the current Beta as Stable")
    source = registry_source_binding(
        root,
        before,
        after,
        plugin_id=plugin_id,
        channel="stable",
        release_id=stable_release,
    )
    if source is None:
        fail("no-pointer Stable completion must belong to an active registered source")
    if any(GITLINK_PATH_PATTERN.fullmatch(path) for path in paths):
        fail("no-pointer Stable completion may not change a first-party Gitlink")
    return {
        "kind": "stable-maintenance",
        "promotions": [{"plugin_id": plugin_id, "release_id": stable_release, "source": source}],
    }


def verify_source_only_beta(
    root: Path,
    before: str,
    after: str,
    paths: list[str],
    *,
    allow_unsigned_official_status_plugin_id: str | None = None,
) -> dict[str, object]:
    """Authenticate one source-only Beta cycle for an existing artifact.

    A split source may add a new Beta commit that deterministically rebuilds an
    existing releaseId. The Factory must still append and sign the exact source
    provenance and expose the new Beta/main gate; treating this as ordinary
    maintenance would silently drop the new source identity, while treating it
    as a smoke recheck would incorrectly require the prior Beta SHA.
    """

    require_candidate_revisions(root, before, after)
    publications = [
        match.group(1)
        for path in paths
        if (match := PUBLICATION_PATH_PATTERN.fullmatch(path))
    ]
    statuses = [match.group(1) for path in paths if (match := STATUS_PATH_PATTERN.fullmatch(path))]
    if len(publications) != 1 or len(statuses) != 1 or publications[0] != statuses[0]:
        fail("source-only Beta must change one matching provenance and status document")
    plugin_id = publications[0]
    release_path = f"{SNAPSHOT_ROOT}/{plugin_id}/.xsec-market/releases.json"
    release_sidecar = f"{release_path}.sig.jws.json"
    evidence_path = f".xsec-factory/official-publications/{plugin_id}.json"
    evidence_proof_path = f".xsec-factory/official-publication-proofs/{plugin_id}.json"
    status_path = f".xsec-factory/official-status/{plugin_id}.json"
    status_proof_path = f".xsec-factory/official-status-proofs/{plugin_id}.json"
    required_paths = {MARKETPLACE_SIDECAR, release_sidecar, evidence_path, evidence_proof_path, status_path}
    if allow_unsigned_official_status_plugin_id is None:
        required_paths.add(status_proof_path)
    elif allow_unsigned_official_status_plugin_id != plugin_id:
        fail("pending status authentication does not match the source-only Beta plugin")
    if not required_paths.issubset(paths):
        fail("source-only Beta must refresh Marketplace, release, provenance, and status sidecars")
    if allow_unsigned_official_status_plugin_id is None and not git_succeeds(root, ["cat-file", "-e", f"{after}:{status_proof_path}"]):
        fail("source-only Beta must retain its status KMS proof")
    if not git_succeeds(root, ["cat-file", "-e", f"{before}:{MARKETPLACE_INDEX}"]) or not git_succeeds(
        root, ["cat-file", "-e", f"{after}:{MARKETPLACE_INDEX}"]
    ):
        fail("source-only Beta must retain the Marketplace index")
    if git_bytes(root, ["show", f"{before}:{MARKETPLACE_INDEX}"]) != git_bytes(root, ["show", f"{after}:{MARKETPLACE_INDEX}"]):
        fail("source-only Beta may not rewrite the Marketplace index")
    if not git_succeeds(root, ["cat-file", "-e", f"{before}:{release_path}"]) or not git_succeeds(
        root, ["cat-file", "-e", f"{after}:{release_path}"]
    ):
        fail("source-only Beta has no retained release index")
    before_release = release_document_from_blob(plugin_id, git_bytes(root, ["show", f"{before}:{release_path}"]))
    after_release = release_document_from_blob(plugin_id, git_bytes(root, ["show", f"{after}:{release_path}"]))
    if before_release != after_release:
        fail("source-only Beta rewrote immutable release metadata")
    beta_release = release_pointer(after_release, "beta")
    if beta_release is None:
        fail("source-only Beta requires a current Beta release")
    source = registry_source_binding(
        root,
        before,
        after,
        plugin_id=plugin_id,
        channel="beta",
        release_id=beta_release,
    )
    if source is None:
        fail("source-only Beta must belong to an active registered source")
    gitlink_path = require_first_party_gitlink(root, before, after, plugin_id=plugin_id, source=source)
    main_source = beta_main_gate_binding(
        root,
        after,
        plugin_id=plugin_id,
        release_id=beta_release,
        beta_source=source,
    )
    try:
        root_resolved = root.resolve(strict=True)
        active_kms_sidecars = {
            sidecar_path_for(document).resolve(strict=False).relative_to(root_resolved).as_posix()
            for document in marketplace_documents(root)
        }
    except (MarketplaceKmsPublisherError, OSError, ValueError) as error:
        raise PromotionVerificationError("source-only Beta has an invalid active KMS document layout") from error
    for path in paths:
        if path in required_paths or path in active_kms_sidecars or path == gitlink_path:
            continue
        fail(f"source-only Beta changed an unauthorized path: {path}")
    return {
        "kind": "beta",
        "promotions": [{"plugin_id": plugin_id, "release_id": beta_release, "source": source, "main_source": main_source}],
    }


def verify_beta_smoke_ready(
    root: Path,
    before: str,
    after: str,
    paths: list[str],
    *,
    allow_unsigned_official_status_plugin_id: str | None = None,
) -> dict[str, object]:
    """Authenticate one no-pointer main-gate recheck for an existing Beta.

    A source ``main`` event can make an already immutable Beta reproducible
    without appending a release record.  This candidate is intentionally not
    generic maintenance: it is the only shape that may reopen Desktop smoke,
    and binds both exact source branch heads so the finalizer can reject a
    decision that became stale while the generated PR waited for review.
    A first-party recheck may also catch up a stale development Gitlink to
    that retained Beta SHA.
    """

    require_candidate_revisions(root, before, after)
    status_paths = [match.group(1) for path in paths if (match := STATUS_PATH_PATTERN.fullmatch(path))]
    if len(status_paths) != 1:
        fail("no-pointer Beta smoke transition must change exactly one Factory status document")
    plugin_id = status_paths[0]
    release_path = f"{SNAPSHOT_ROOT}/{plugin_id}/.xsec-market/releases.json"
    release_sidecar = f"{release_path}.sig.jws.json"
    evidence_path = f".xsec-factory/official-publications/{plugin_id}.json"
    proof_path = f".xsec-factory/official-publication-proofs/{plugin_id}.json"
    status_path = f".xsec-factory/official-status/{plugin_id}.json"
    status_proof_path = f".xsec-factory/official-status-proofs/{plugin_id}.json"
    required_paths = {MARKETPLACE_SIDECAR, release_sidecar, proof_path, status_path}
    if allow_unsigned_official_status_plugin_id is None:
        required_paths.add(status_proof_path)
    elif allow_unsigned_official_status_plugin_id != plugin_id:
        fail("pending status authentication does not match the no-pointer Beta plugin")
    if not required_paths.issubset(paths):
        fail("no-pointer Beta smoke transition must refresh Marketplace, release, provenance, and status sidecars")
    if allow_unsigned_official_status_plugin_id is None and not git_succeeds(root, ["cat-file", "-e", f"{after}:{status_proof_path}"]):
        fail("no-pointer Beta smoke transition must retain its status KMS proof")
    marketplace = json_blob(root, after, MARKETPLACE_INDEX, "retained Marketplace index")
    entries = marketplace.get("plugins")
    if not isinstance(entries, list):
        fail("no-pointer Beta smoke transition retained Marketplace index has invalid plugins")
    active_release_sidecars: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("source"), dict):
            fail("no-pointer Beta smoke transition retained Marketplace index has an invalid plugin source")
        source_path = entry["source"].get("path")
        if not isinstance(source_path, str):
            fail("no-pointer Beta smoke transition retained Marketplace source path is invalid")
        # The marketplace's public source contract intentionally uses an
        # explicit repository-relative Factory snapshot path. Registry and
        # status documents use the source repository's ``plugins/<id>`` path,
        # so accepting that representation here would both reject production
        # snapshots and weaken this candidate's Marketplace-bound allowlist.
        match = MARKETPLACE_SOURCE_PATH_PATTERN.fullmatch(source_path)
        if match is None:
            fail("no-pointer Beta smoke transition retained Marketplace source path is not canonical")
        active_release_sidecars.add(f"{SNAPSHOT_ROOT}/{match.group(1)}/.xsec-market/releases.json.sig.jws.json")
    # A normal KMS renewal can refresh proof sidecars for every *other* active
    # Factory document while this one status changes.  These are signatures,
    # not source-of-truth documents, so allow the exact sidecar set derived
    # from the post-change Marketplace layout and still reject any underlying
    # status/provenance/release/index content rewrite for another plugin.
    try:
        root_resolved = root.resolve(strict=True)
        active_kms_sidecars = {
            sidecar_path_for(document).resolve(strict=False).relative_to(root_resolved).as_posix()
            for document in marketplace_documents(root)
        }
    except (MarketplaceKmsPublisherError, OSError, ValueError) as error:
        raise PromotionVerificationError("no-pointer Beta smoke transition has an invalid active KMS document layout") from error
    if not active_release_sidecars.issubset(active_kms_sidecars):
        fail("no-pointer Beta smoke transition active release sidecar allowlist is incomplete")
    gitlink_path = f"plugins/{plugin_id}" if f"plugins/{plugin_id}" in paths else None
    for path in paths:
        if path in required_paths or path in active_kms_sidecars or path == gitlink_path:
            continue
        fail(f"no-pointer Beta smoke transition changed an unauthorized path: {path}")
    for path, label in ((MARKETPLACE_INDEX, "Marketplace index"), (release_path, "Beta release index"), (evidence_path, "Beta provenance")):
        if not git_succeeds(root, ["cat-file", "-e", f"{before}:{path}"]) or not git_succeeds(
            root, ["cat-file", "-e", f"{after}:{path}"]
        ):
            fail(f"no-pointer Beta smoke transition must retain its {label}")
        if git_bytes(root, ["show", f"{before}:{path}"]) != git_bytes(root, ["show", f"{after}:{path}"]):
            fail(f"no-pointer Beta smoke transition may not rewrite its {label}")

    before_release = release_document_from_blob(plugin_id, git_bytes(root, ["show", f"{before}:{release_path}"]))
    after_release = release_document_from_blob(plugin_id, git_bytes(root, ["show", f"{after}:{release_path}"]))
    if before_release != after_release:
        fail("no-pointer Beta smoke transition rewrote immutable release metadata")
    beta_release = release_pointer(after_release, "beta")
    stable_release = release_pointer(after_release, "stable")
    if beta_release is None:
        fail("no-pointer Beta smoke transition requires a current Beta release")

    before_status = json_blob(root, before, status_path, "baseline Factory status")
    after_status = json_blob(root, after, status_path, "candidate Factory status")
    for status, label in ((before_status, "baseline"), (after_status, "candidate")):
        if set(status) != {"schemaVersion", "pluginId", "trustTier", "source", "release", "publication"}:
            fail(f"no-pointer Beta smoke transition has an invalid {label} Factory status shape")
        if status.get("pluginId") != plugin_id:
            fail("no-pointer Beta smoke transition status has the wrong plugin ID")
        if not isinstance(status.get("source"), dict) or not isinstance(status.get("release"), dict) or not isinstance(
            status.get("publication"), dict
        ):
            fail("no-pointer Beta smoke transition status sections must be objects")
    before_source = before_status["source"]
    after_source = after_status["source"]
    expected_source_keys = {"repository", "path", "refs", "betaSha", "stableSha", "mainGateSha"}
    if set(before_source) != expected_source_keys or set(after_source) != expected_source_keys:
        fail("no-pointer Beta smoke transition status has an invalid source shape")
    source_identity = active_registered_source(root, after, plugin_id=plugin_id)
    if source_identity is None:
        fail("no-pointer Beta smoke transition must belong to an active registered source")
    expected_refs = {"beta": source_identity["beta_ref"], "stable": source_identity["stable_ref"]}
    for source, label in ((before_source, "baseline"), (after_source, "candidate")):
        if (
            source.get("repository") != source_identity["repository"]
            or source.get("path") != source_identity["path"]
            or source.get("refs") != expected_refs
            or not isinstance(source.get("betaSha"), str)
            or not SHA_PATTERN.fullmatch(source["betaSha"])
            or source.get("stableSha") is not None
            or not isinstance(source.get("mainGateSha"), str)
            or not SHA_PATTERN.fullmatch(source["mainGateSha"])
        ):
            fail(f"no-pointer Beta smoke transition {label} status is not bound to the registered source")
    if before_source["betaSha"] != after_source["betaSha"]:
        fail("no-pointer Beta smoke transition may not change its immutable Beta source SHA")
    if before_source["mainGateSha"] == after_source["mainGateSha"]:
        fail("no-pointer Beta smoke transition must record a newly compared registered main SHA")
    if gitlink_path is not None and require_first_party_gitlink(
        root,
        before,
        after,
        plugin_id=plugin_id,
        source={"sha": after_source["betaSha"]},
    ) != gitlink_path:
        fail("no-pointer Beta smoke transition may not change a first-party Gitlink")

    expected_release = {"betaReleaseId": beta_release, "stableReleaseId": stable_release}
    if before_status["release"] != expected_release or after_status["release"] != expected_release:
        fail("no-pointer Beta smoke transition status does not retain current release pointers")
    before_publication = before_status["publication"]
    after_publication = after_status["publication"]
    expected_publication_keys = {"state", "deliveryId", "factoryRunUrl", "smokeRunUrl", "marketplaceRevision"}
    if set(before_publication) != expected_publication_keys or set(after_publication) != expected_publication_keys:
        fail("no-pointer Beta smoke transition status has an invalid publication shape")
    before_state = before_publication.get("state")
    after_state = after_publication.get("state")
    if before_state not in {"waiting_for_beta", "waiting_for_smoke"} or after_state not in {
        "waiting_for_beta",
        "waiting_for_smoke",
    }:
        fail("no-pointer Beta smoke transition must retain an in-flight Beta gate state")
    if (
        before_publication.get("smokeRunUrl") is not None
        or before_publication.get("marketplaceRevision") is not None
        or after_publication.get("smokeRunUrl") is not None
        or after_publication.get("marketplaceRevision") is not None
    ):
        fail("no-pointer Beta smoke transition must not claim Desktop smoke evidence")

    evidence = json_blob(root, after, evidence_path, "retained Beta provenance")
    events = evidence.get("events")
    if not isinstance(events, list):
        fail("no-pointer Beta smoke transition retained provenance has invalid events")
    beta_events = [
        event
        for event in events
        if isinstance(event, dict)
        and event.get("channel") == "beta"
        and event.get("releaseId") == beta_release
        and isinstance(event.get("source"), dict)
        and event["source"].get("repository") == source_identity["repository"]
        and event["source"].get("path") == source_identity["path"]
        and event["source"].get("ref") == source_identity["beta_ref"]
        and event["source"].get("sha") == after_source["betaSha"]
    ]
    if len(beta_events) != 1:
        fail("no-pointer Beta smoke transition status must match one immutable Beta provenance event")
    return {
        "kind": "beta-smoke-ready",
        "promotions": [
            {
                "plugin_id": plugin_id,
                "release_id": beta_release,
                "source": {"repository": source_identity["repository"], "ref": source_identity["beta_ref"], "sha": after_source["betaSha"]},
                "main_source": {
                    "repository": source_identity["repository"],
                    "ref": source_identity["stable_ref"],
                    "sha": after_source["mainGateSha"],
                },
            }
        ],
    }


def classify_merged_change(
    root: Path,
    before: str,
    after: str,
    *,
    allow_unsigned_official_status_plugin_id: str | None = None,
) -> dict[str, object]:
    """Return ``none`` for ordinary commits, without reading commit metadata."""

    paths = changed_paths(root, before, after)
    if not paths:
        return {"kind": "none"}
    has_release = any(RELEASE_PATH_PATTERN.fullmatch(path) for path in paths)
    if not has_release:
        if REGISTRY_PATH in paths or MARKETPLACE_INDEX in paths:
            return verify_default_set_transition(root, before, after)
        # First-party adoption is a two-PR transition: protected main first
        # records an unsigned immutable assertion, then a production KMS
        # workflow adds its sidecar and activates the Registry. Neither step
        # is a Desktop smoke publication, but both must be recognized here so
        # the post-merge dispatcher exits cleanly instead of treating a
        # review-gated migration as a malformed release transition.
        if any(ADOPTION_PATH_PATTERN.fullmatch(path) or ADOPTION_PROOF_PATTERN.fullmatch(path) for path in paths):
            return verify_first_party_adoption_candidate(root, before, after)
        # A review-gated retained-sidecar repair must not recurse into a new
        # release, and it does not represent a Desktop smoke publication.
        if all(path == MARKETPLACE_SIDECAR or RELEASE_SIDECAR_PATTERN.fullmatch(path) for path in paths):
            return {"kind": "maintenance"}
        # A no-pointer external Stable completion can append signed provenance
        # and update its observable status after an already selected release.
        # It must not loop into the built-in beta publisher merely because a
        # reviewer used a conventional merge subject. It also must not trigger
        # a second Desktop smoke: that state change is downstream of an
        # earlier validated Beta smoke callback.
        auxiliary = [
            path == MARKETPLACE_SIDECAR
            or RELEASE_SIDECAR_PATTERN.fullmatch(path)
            or PUBLICATION_PATH_PATTERN.fullmatch(path)
            or PUBLICATION_PROOF_PATTERN.fullmatch(path)
            or STATUS_PATH_PATTERN.fullmatch(path)
            or STATUS_PROOF_PATTERN.fullmatch(path)
            or GITLINK_PATH_PATTERN.fullmatch(path)
            for path in paths
        ]
        if all(auxiliary) and MARKETPLACE_SIDECAR in paths and any(
            PUBLICATION_PATH_PATTERN.fullmatch(path) or STATUS_PATH_PATTERN.fullmatch(path) for path in paths
        ):
            # Legacy built-ins can have harmless signed maintenance without a
            # Registry v2 source. Registered Factory evidence is stricter: it
            # must authenticate as one exact source-only Beta cycle, a
            # main-gate smoke recheck, or a Stable completion.
            if git_succeeds(root, ["cat-file", "-e", f"{after}:{REGISTRY_PATH}"]):
                try:
                    return verify_source_only_beta(
                        root,
                        before,
                        after,
                        paths,
                        allow_unsigned_official_status_plugin_id=allow_unsigned_official_status_plugin_id,
                    )
                except PromotionVerificationError as source_beta_error:
                    try:
                        return verify_beta_smoke_ready(
                            root,
                            before,
                            after,
                            paths,
                            allow_unsigned_official_status_plugin_id=allow_unsigned_official_status_plugin_id,
                        )
                    except PromotionVerificationError as beta_error:
                        try:
                            return verify_stable_maintenance(root, before, after, paths)
                        except PromotionVerificationError as stable_error:
                            fail(
                                "no-pointer Factory change is not a safe source-only Beta, Beta smoke, or Stable completion: "
                                f"source-only-beta: {source_beta_error}; beta-smoke-ready: {beta_error}; "
                                f"stable-maintenance: {stable_error}"
                            )
            return {"kind": "maintenance"}
        return {"kind": "none"}
    candidates: list[dict[str, object]] = []
    errors: list[str] = []
    for channel in ("beta", "stable"):
        try:
            candidates.append(verify_merged_publication(root, before, after, channel))
        except PromotionVerificationError as error:
            errors.append(f"{channel}: {error}")
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        fail("release-index change is not a safe generated Marketplace publication: " + "; ".join(errors))
    fail("release-index change ambiguously matches both Beta and Stable publication")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--channel", choices=("beta", "stable"))
    parser.add_argument("--classify", action="store_true")
    parser.add_argument(
        "--allow-unsigned-official-status-plugin-id",
        help="only while authenticating one pending reconcile candidate status",
    )
    parser.add_argument("--verify-first-party-adoption-candidate", action="store_true")
    parser.add_argument("--verify-retained-sidecar-refresh-candidate", action="store_true")
    parser.add_argument("--verify-default-set-transition-candidate", action="store_true")
    args = parser.parse_args()
    modes = sum(
        (
            args.classify,
            args.channel is not None,
            args.verify_first_party_adoption_candidate,
            args.verify_retained_sidecar_refresh_candidate,
            args.verify_default_set_transition_candidate,
        )
    )
    if modes != 1:
        parser.error("supply exactly one verification mode")
    if args.allow_unsigned_official_status_plugin_id is not None and not args.classify:
        parser.error("--allow-unsigned-official-status-plugin-id requires --classify")
    try:
        root = args.root.resolve()
        if args.classify:
            result = classify_merged_change(
                root,
                args.before,
                args.after,
                allow_unsigned_official_status_plugin_id=args.allow_unsigned_official_status_plugin_id,
            )
        elif args.channel is not None:
            result = verify_merged_publication(root, args.before, args.after, args.channel)
        elif args.verify_first_party_adoption_candidate:
            result = verify_first_party_adoption_candidate(root, args.before, args.after)
        elif args.verify_retained_sidecar_refresh_candidate:
            result = verify_retained_sidecar_refresh_candidate(root, args.before, args.after)
        else:
            result = verify_default_set_transition(root, args.before, args.after)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except PromotionVerificationError as error:
        print(f"Merged Marketplace publication verification failed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
