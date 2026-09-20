"""Verify append-only SemVer publications and their registered source bindings."""

from pathlib import Path

import verify_merged_stable_promotion as legacy


def version_record(root: Path, revisions: tuple[str, str], release: tuple[str, str]) -> dict[str, object]:
    before, after = revisions
    plugin_id, release_path = release
    previous = legacy.empty_release_document(plugin_id)
    if legacy.git_succeeds(root, ["cat-file", "-e", f"{before}:{release_path}"]):
        previous = legacy.release_document_from_blob(plugin_id, legacy.git_bytes(root, ["show", f"{before}:{release_path}"]))
    current = legacy.release_document_from_blob(plugin_id, legacy.git_bytes(root, ["show", f"{after}:{release_path}"]))
    if len(current["releases"]) != len(previous["releases"]) + 1:
        legacy.fail("version publication must append exactly one immutable release per plugin")
    # The retained schema records publication provenance in its historical beta fields.
    release_id = legacy.release_transition_id(previous, current, "beta")
    source = legacy.registry_source_binding(root, before, after, plugin_id=plugin_id, channel="beta", release_id=release_id)
    if source is None:
        legacy.fail("version publication requires an active registered source")
    legacy.require_first_party_gitlink(root, before, after, plugin_id=plugin_id, source=source)
    main_source = legacy.beta_main_gate_binding(root, after, plugin_id=plugin_id, release_id=release_id, beta_source=source)
    return {"plugin_id": plugin_id, "release_id": release_id, "source": source, "main_source": main_source}


def verify_version_publication(root: Path, before: str, after: str) -> dict[str, object]:
    legacy.require_candidate_revisions(root, before, after)
    paths = legacy.changed_paths(root, before, after)
    releases = [(match.group(1), path) for path in paths if (match := legacy.RELEASE_PATH_PATTERN.fullmatch(path))]
    if not releases:
        legacy.fail("version publication must append an immutable release")
    if any(legacy.is_publish_kms_sidecar(path) for path in paths):
        legacy.fail("version publication may only change version metadata, source snapshots and artifacts")
    plugin_ids = {plugin_id for plugin_id, _ in releases}
    first_party_ids = {
        plugin_id for plugin_id in plugin_ids
        if (source := legacy.active_registered_source(root, after, plugin_id=plugin_id)) is not None
        and source["trust_tier"] == "first-party"
    }
    legacy.allowed_paths("beta", paths, plugin_ids, renewable_sidecars=set(), first_party_gitlink_ids=first_party_ids)
    records = [version_record(root, (before, after), release) for release in releases]
    return {"kind": "version", "promotions": records}
