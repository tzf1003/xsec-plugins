#!/usr/bin/env python3
"""Classify and fail closed on reviewed Marketplace publication merges.

The release workflows only create review-required pull requests. This helper
runs against the protected ``main`` push after that PR is merged. It derives
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

from build_market import load_release_document


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ID_PATTERN = r"[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?"
RELEASE_PATH_PATTERN = re.compile(rf"^plugins/({PLUGIN_ID_PATTERN})/\.xsec-market/releases\.json$")
RELEASE_SIDECAR_PATTERN = re.compile(rf"^plugins/{PLUGIN_ID_PATTERN}/\.xsec-market/releases\.json\.sig\.jws\.json$")
PLUGIN_PATH_PATTERN = re.compile(rf"^plugins/({PLUGIN_ID_PATTERN})/(.+)$")
PUBLICATION_PATH_PATTERN = re.compile(rf"^\.xsec-factory/official-publications/({PLUGIN_ID_PATTERN})\.json$")
PUBLICATION_PROOF_PATTERN = re.compile(rf"^\.xsec-factory/official-publication-proofs/({PLUGIN_ID_PATTERN})\.json$")
ADOPTION_PATH_PATTERN = re.compile(rf"^\.xsec-factory/official-adoptions/({PLUGIN_ID_PATTERN})\.json$")
ADOPTION_PROOF_PATTERN = re.compile(rf"^\.xsec-factory/official-adoption-proofs/({PLUGIN_ID_PATTERN})\.json$")
STATUS_PATH_PATTERN = re.compile(rf"^\.xsec-factory/official-status/({PLUGIN_ID_PATTERN})\.json$")
MARKETPLACE_INDEX = ".agents/plugins/marketplace.json"
MARKETPLACE_SIDECAR = ".agents/plugins/marketplace.json.sig.jws.json"
REGISTRY_PATH = ".xsec-factory/official-registry.json"
SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99}[A-Za-z0-9])?$")


class PromotionVerificationError(ValueError):
    """The protected-main change is not a safe reviewed publication."""


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


def allowed_paths(channel: str, paths: list[str], promoted_ids: set[str]) -> None:
    """Permit only the generated Factory surfaces for a signed release PR."""

    for path in paths:
        if path == MARKETPLACE_SIDECAR or RELEASE_SIDECAR_PATTERN.fullmatch(path) or RELEASE_PATH_PATTERN.fullmatch(path):
            continue
        if channel == "beta" and path == MARKETPLACE_INDEX:
            continue
        plugin_path = PLUGIN_PATH_PATTERN.fullmatch(path)
        if channel == "beta" and plugin_path and plugin_path.group(1) in promoted_ids:
            # Source snapshots and newly-built immutable artifacts belong only
            # to a release index whose Beta pointer advances in this PR.
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
        fail(f"merged {channel} publication changed an unauthorized path: {path}")


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

    if not git_succeeds(root, ["cat-file", "-e", f"{after}:{REGISTRY_PATH}"]):
        return None
    registry = json_blob(root, after, REGISTRY_PATH, "official Factory registry")
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
    if (
        not isinstance(source, dict)
        or not isinstance(source.get("repository"), str)
        or not REPOSITORY_PATTERN.fullmatch(source["repository"])
        or not isinstance(source.get("path"), str)
    ):
        fail(f"registered publication plugin {plugin_id} has invalid source identity")
    refs = source.get("refs")
    expected_ref = "refs/heads/beta" if channel == "beta" else "refs/heads/main"
    if not isinstance(refs, dict) or refs.get("beta") != "refs/heads/beta" or refs.get("stable") != "refs/heads/main":
        fail(f"registered publication plugin {plugin_id} has invalid source refs")
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
    return {"repository": str(source["repository"]), "ref": expected_ref, "sha": str(matches[0]["sha"])}


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
    allowed_paths(channel, paths, promoted_ids)
    for plugin_id, release_path in release_paths:
        sidecar = f"plugins/{plugin_id}/.xsec-market/releases.json.sig.jws.json"
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
        promoted.append(record)
    if channel == "stable" and len(promoted) != 1:
        fail("merged Stable promotion must change exactly one releases.json document")
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
    release_path = f"plugins/{plugin_id}/.xsec-market/releases.json"
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
    return {
        "kind": "stable-maintenance",
        "promotions": [{"plugin_id": plugin_id, "release_id": stable_release, "source": source}],
    }


def classify_merged_change(root: Path, before: str, after: str) -> dict[str, object]:
    """Return ``none`` for ordinary commits, without reading commit metadata."""

    paths = changed_paths(root, before, after)
    if not paths:
        return {"kind": "none"}
    has_release = any(RELEASE_PATH_PATTERN.fullmatch(path) for path in paths)
    if not has_release:
        # A review-gated retained-sidecar repair must not recurse into a new
        # release, and it does not represent a Desktop smoke publication.
        if all(path == MARKETPLACE_SIDECAR or RELEASE_SIDECAR_PATTERN.fullmatch(path) for path in paths):
            return {"kind": "maintenance"}
        # A no-pointer external Stable completion can append signed provenance
        # and update its observable status after an already selected release.
        # It must not loop into the built-in beta publisher merely because a
        # reviewer used a conventional merge subject. It also must not trigger
        # a second Desktop smoke: that state change is downstream of an
        # earlier reviewed Beta smoke callback.
        auxiliary = [
            path == MARKETPLACE_SIDECAR
            or RELEASE_SIDECAR_PATTERN.fullmatch(path)
            or PUBLICATION_PATH_PATTERN.fullmatch(path)
            or PUBLICATION_PROOF_PATTERN.fullmatch(path)
            or STATUS_PATH_PATTERN.fullmatch(path)
            for path in paths
        ]
        if all(auxiliary) and MARKETPLACE_SIDECAR in paths and any(
            PUBLICATION_PATH_PATTERN.fullmatch(path) or STATUS_PATH_PATTERN.fullmatch(path) for path in paths
        ):
            # Legacy built-ins can have harmless signed maintenance without a
            # Registry v2 source. Registered Factory evidence is stricter: it
            # must authenticate as the exact no-pointer Stable completion.
            if git_succeeds(root, ["cat-file", "-e", f"{after}:{REGISTRY_PATH}"]):
                return verify_stable_maintenance(root, before, after, paths)
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
    args = parser.parse_args()
    if args.classify == (args.channel is not None):
        parser.error("supply exactly one of --classify or --channel")
    try:
        root = args.root.resolve()
        result = classify_merged_change(root, args.before, args.after) if args.classify else verify_merged_publication(root, args.before, args.after, str(args.channel))
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except PromotionVerificationError as error:
        print(f"Merged Marketplace publication verification failed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
