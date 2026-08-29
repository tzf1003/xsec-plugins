#!/usr/bin/env python3
"""Publish XSEC official-marketplace KMS JWS sidecars through Cloud.

This script deliberately has no private signing-key input.  A protected
GitHub Actions job obtains an ephemeral OIDC token and sends the exact bytes
of each marketplace document to the production Cloud broker.  Cloud binds the
document digest and the workflow commit to a Vercel KMS JWS.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from build_market import WINDOWS_RESERVED_DEVICE_NAMES


ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE_INDEX_SUBJECT = ".agents/plugins/marketplace.json"
OFFICIAL_PUBLICATIONS_RELATIVE_PATH = Path(".xsec-factory") / "official-publications"
OFFICIAL_PUBLICATION_PROOFS_RELATIVE_PATH = Path(".xsec-factory") / "official-publication-proofs"
OFFICIAL_ADOPTIONS_RELATIVE_PATH = Path(".xsec-factory") / "official-adoptions"
OFFICIAL_ADOPTION_PROOFS_RELATIVE_PATH = Path(".xsec-factory") / "official-adoption-proofs"
# This document is not consumed by Desktop.  It binds the external source
# provenance kept by the Factory to the same protected OIDC/KMS publication
# boundary as the Marketplace index and release records.
OFFICIAL_PUBLICATION_PROVENANCE_PURPOSE = "xsec.plugin-marketplace.provenance"
# First-party adoptions are intentionally a different KMS purpose.  A
# provenance proof says that a source checkout produced a new Factory
# publication; an adoption proof says that a protected migration bound an
# already-published built-in snapshot/release history to its new source repo.
# Keeping the subjects and sidecars separate prevents either assertion from
# being replayed as the other.
OFFICIAL_ADOPTION_PROVENANCE_PURPOSE = "xsec.plugin-marketplace.first-party-adoption"
BROKER_AUDIENCE = "xsec-kms-document-signing-v1"
PRODUCTION_BROKER_URL = "https://api.54321000.xyz/v2/internal/signing/documents"
GITHUB_ACTIONS_OIDC_HOST_SUFFIX = ".actions.githubusercontent.com"
OFFICIAL_MARKETPLACE_KMS_ISSUER_ID = "dc24288e-f77c-4c13-81a7-f649afbe7b73"
OFFICIAL_MARKETPLACE_KMS_ISSUER_URL = f"https://kms.vercel.com/{OFFICIAL_MARKETPLACE_KMS_ISSUER_ID}"
MAX_BROKER_RESPONSE_BYTES = 64 * 1024
MAX_KMS_JWKS_BYTES = 256 * 1024
MAX_KMS_JWKS_KEYS = 32
MAX_KMS_JWS_SIGNING_INPUT_BYTES = 24 * 1024
PINNED_KMS_JWKS_URL = f"{OFFICIAL_MARKETPLACE_KMS_ISSUER_URL}/jwks.json"
GITHUB_SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
OFFICIAL_PLUGIN_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$")
CURRENT_SOURCE_REVISION_ENV = "XSEC_MARKETPLACE_SOURCE_REVISION"

# This is deliberately a fixed built-in-only program.  The Factory already
# requires Node 24 for its source gate; using its platform Ed25519 primitive
# avoids adding an unpinned Python crypto dependency while keeping KMS key
# rotation in the issuer JWKS.  Untrusted sidecar values are supplied only as
# JSON on stdin, never interpolated into code, an argv item, or a shell.
NODE_ED25519_VERIFY_PROGRAM = r"""
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const request = JSON.parse(readFileSync(0, "utf8"));
const key = createPublicKey({
  key: { kty: "OKP", crv: "Ed25519", x: request.public_key_x },
  format: "jwk",
});
const valid = verify(
  null,
  Buffer.from(request.signing_input_b64, "base64"),
  key,
  Buffer.from(request.signature_b64, "base64"),
);
process.exitCode = valid ? 0 : 1;
"""


class MarketplaceKmsPublisherError(ValueError):
    """The broker or a generated sidecar violates the Desktop protocol."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class MarketplaceDocument:
    purpose: str
    subject: str
    path: Path
    # Marketplace release/index sidecars live beside the document because
    # Desktop knows those locations. Factory provenance is internal metadata,
    # so its sidecar lives in a separate namespace to avoid filename aliasing
    # between a valid dotted plugin ID and a ``.sig.jws.json`` suffix.
    sidecar_path: Path | None = None


def fail(message: str) -> None:
    raise MarketplaceKmsPublisherError(message)


def stable_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def is_link(path: Path) -> bool:
    """Cover POSIX links and Windows directory junctions before reads/writes."""

    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def canonical_base64url_decode(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not BASE64URL_PATTERN.fullmatch(value) or len(value) % 4 == 1:
        fail(f"{label} must be unpadded canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise MarketplaceKmsPublisherError(f"{label} is not valid base64url") from error
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        fail(f"{label} must be canonical base64url")
    return decoded


def json_object(value: bytes | str, label: str) -> dict[str, object]:
    try:
        parsed = json.loads(value)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MarketplaceKmsPublisherError(f"{label} is not valid JSON") from error
    if not isinstance(parsed, dict):
        fail(f"{label} must be a JSON object")
    return parsed


def exact_keys(value: Mapping[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        fail(f"{label} has an unsupported schema")


def required_string(value: Mapping[str, object], key: str, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        fail(f"{label}.{key} must be a non-empty string")
    return item


def required_int(value: Mapping[str, object], key: str, label: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool):
        fail(f"{label}.{key} must be an integer")
    return item


def safe_document_path(root: Path, subject: str, *, must_exist: bool) -> Path:
    path = PurePosixPath(subject)
    if (
        not subject
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
    ):
        fail(f"marketplace document subject is unsafe: {subject!r}")
    if is_link(root):
        fail(f"marketplace root must not be a symbolic link: {root}")
    root_resolved = root.resolve(strict=True)
    current = root
    for part in path.parts:
        current = current / part
        if is_link(current):
            fail(f"marketplace document must not traverse symbolic links: {subject}")
    try:
        resolved = current.resolve(strict=must_exist)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise MarketplaceKmsPublisherError(f"marketplace document must remain below repository root: {subject}") from error
    if must_exist and not resolved.is_file():
        fail(f"marketplace document is unavailable: {subject}")
    return resolved


def canonical_plugin_subject(source_path: object) -> str:
    if not isinstance(source_path, str) or not source_path:
        fail("marketplace plugin source.path must be a non-empty string")
    path = PurePosixPath(source_path)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        fail("marketplace plugin source.path must remain below plugins/")
    if path.parts[0] != "plugins":
        fail("marketplace plugin source.path must be below plugins/")
    return "/".join(path.parts)


def official_publication_provenance_document(root: Path, plugin_id: str) -> MarketplaceDocument:
    """Return the one KMS document that authenticates Factory provenance.

    Keep the subject and sidecar location fixed independently of untrusted
    evidence contents.  The Cloud broker has a matching narrow allowlist, and
    the separate proof directory avoids turning one plugin ID into another
    plugin's adjacent sidecar filename.
    """

    if (
        not isinstance(plugin_id, str)
        or not OFFICIAL_PLUGIN_ID_PATTERN.fullmatch(plugin_id)
        or ".." in plugin_id
        or "--" in plugin_id
        or plugin_id.split(".", 1)[0].casefold() in WINDOWS_RESERVED_DEVICE_NAMES
    ):
        fail("official Factory provenance plugin ID is unsafe")
    subject = (OFFICIAL_PUBLICATIONS_RELATIVE_PATH / f"{plugin_id}.json").as_posix()
    proof_subject = (OFFICIAL_PUBLICATION_PROOFS_RELATIVE_PATH / f"{plugin_id}.json").as_posix()
    return MarketplaceDocument(
        OFFICIAL_PUBLICATION_PROVENANCE_PURPOSE,
        subject,
        safe_document_path(root, subject, must_exist=True),
        safe_document_path(root, proof_subject, must_exist=False),
    )


def official_publication_provenance_documents(root: Path) -> list[MarketplaceDocument]:
    """Enumerate only canonical Factory provenance documents for KMS signing."""

    publication_root = root / OFFICIAL_PUBLICATIONS_RELATIVE_PATH
    if not publication_root.exists():
        return []
    if is_link(publication_root) or not publication_root.is_dir():
        fail("official Factory provenance directory must be a regular directory")
    proof_root = root / OFFICIAL_PUBLICATION_PROOFS_RELATIVE_PATH
    if proof_root.exists() and (is_link(proof_root) or not proof_root.is_dir()):
        fail("official Factory provenance proof directory must be a regular directory")

    documents: list[MarketplaceDocument] = []
    for evidence in sorted(publication_root.iterdir(), key=lambda candidate: candidate.name):
        if is_link(evidence) or not evidence.is_file() or evidence.suffix != ".json":
            fail(f"official Factory provenance directory has an unsafe entry: {evidence.name}")
        plugin_id = evidence.name.removesuffix(".json")
        document = official_publication_provenance_document(root, plugin_id)
        # `safe_document_path` and the current directory entry must resolve
        # to the same regular file, otherwise a race or odd filesystem alias
        # could make KMS sign bytes other than those enumerated above.
        if document.path != evidence.resolve(strict=True):
            fail(f"official Factory provenance path does not match its subject: {evidence.name}")
        documents.append(document)
    return documents


def official_adoption_provenance_document(root: Path, plugin_id: str) -> MarketplaceDocument:
    """Return the fixed KMS document for a first-party migration proof."""

    if (
        not isinstance(plugin_id, str)
        or not OFFICIAL_PLUGIN_ID_PATTERN.fullmatch(plugin_id)
        or ".." in plugin_id
        or "--" in plugin_id
        or plugin_id.split(".", 1)[0].casefold() in WINDOWS_RESERVED_DEVICE_NAMES
    ):
        fail("official Factory adoption plugin ID is unsafe")
    subject = (OFFICIAL_ADOPTIONS_RELATIVE_PATH / f"{plugin_id}.json").as_posix()
    proof_subject = (OFFICIAL_ADOPTION_PROOFS_RELATIVE_PATH / f"{plugin_id}.json").as_posix()
    return MarketplaceDocument(
        OFFICIAL_ADOPTION_PROVENANCE_PURPOSE,
        subject,
        safe_document_path(root, subject, must_exist=True),
        safe_document_path(root, proof_subject, must_exist=False),
    )


def official_adoption_provenance_documents(root: Path) -> list[MarketplaceDocument]:
    """Enumerate only fixed-path first-party adoption proofs for KMS signing."""

    adoption_root = root / OFFICIAL_ADOPTIONS_RELATIVE_PATH
    if not adoption_root.exists():
        return []
    if is_link(adoption_root) or not adoption_root.is_dir():
        fail("official Factory adoption directory must be a regular directory")
    proof_root = root / OFFICIAL_ADOPTION_PROOFS_RELATIVE_PATH
    if proof_root.exists() and (is_link(proof_root) or not proof_root.is_dir()):
        fail("official Factory adoption proof directory must be a regular directory")
    documents: list[MarketplaceDocument] = []
    for adoption in sorted(adoption_root.iterdir(), key=lambda item: item.name):
        if is_link(adoption) or not adoption.is_file() or adoption.suffix != ".json":
            fail(f"official Factory adoption directory has an unsafe entry: {adoption.name}")
        plugin_id = adoption.name.removesuffix(".json")
        document = official_adoption_provenance_document(root, plugin_id)
        if document.path != adoption.resolve(strict=True):
            fail(f"official Factory adoption path does not match its subject: {adoption.name}")
        documents.append(document)
    return documents


def marketplace_documents(root: Path) -> list[MarketplaceDocument]:
    index_path = safe_document_path(root, MARKETPLACE_INDEX_SUBJECT, must_exist=True)
    marketplace = json_object(index_path.read_bytes(), MARKETPLACE_INDEX_SUBJECT)
    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list):
        fail("marketplace.json plugins must be a list")
    documents = [MarketplaceDocument("xsec.plugin-marketplace.index", MARKETPLACE_INDEX_SUBJECT, index_path)]
    subjects = {MARKETPLACE_INDEX_SUBJECT}
    for entry in plugins:
        if not isinstance(entry, dict):
            fail("marketplace.json plugins entries must be objects")
        source = entry.get("source")
        if not isinstance(source, dict):
            fail("marketplace plugin entry must contain source")
        plugin_root = canonical_plugin_subject(source.get("path"))
        subject = f"{plugin_root}/.xsec-market/releases.json"
        if subject in subjects:
            fail(f"marketplace release document is duplicated: {subject}")
        subjects.add(subject)
        documents.append(
            MarketplaceDocument(
                "xsec.plugin-marketplace.release",
                subject,
                safe_document_path(root, subject, must_exist=True),
            )
        )
    documents.extend(official_publication_provenance_documents(root))
    documents.extend(official_adoption_provenance_documents(root))
    return [documents[0], *sorted(documents[1:], key=lambda document: document.subject)]


def retained_release_document(root: Path, plugin_id: str) -> MarketplaceDocument:
    """Resolve exactly one retained immutable release document for refresh.

    Sidecar repair is deliberately narrower than normal publication: it can
    only re-sign the existing ``releases.json`` for a plugin that the current
    Marketplace already discovers.  In particular, callers cannot use this
    helper to sign the mutable marketplace index, arbitrary repository paths,
    or Factory provenance documents.
    """

    if (
        not isinstance(plugin_id, str)
        or not OFFICIAL_PLUGIN_ID_PATTERN.fullmatch(plugin_id)
        or ".." in plugin_id
        or "--" in plugin_id
        or plugin_id.split(".", 1)[0].casefold() in WINDOWS_RESERVED_DEVICE_NAMES
    ):
        fail("retained release refresh plugin ID is unsafe")
    subject = f"plugins/{plugin_id}/.xsec-market/releases.json"
    matching = [document for document in marketplace_documents(root) if document.subject == subject]
    if len(matching) != 1 or matching[0].purpose != "xsec.plugin-marketplace.release":
        fail("retained release refresh must name a current Marketplace release document")
    return matching[0]


def validate_sidecar(
    sidecar_bytes: bytes,
    document: MarketplaceDocument,
    source_revision: str,
    *,
    now: int | None = None,
) -> dict[str, object]:
    """Validate the exact non-cryptographic protocol enforced by Desktop.

    Signature verification itself is intentionally the Desktop smoke-test
    responsibility: it must use the KMS issuer's live JWKS.  This check catches
    malformed, replayed, cross-purpose, or wrongly bound broker output before
    it can enter the marketplace repository.
    """

    if not GITHUB_SHA_PATTERN.fullmatch(source_revision):
        fail("source revision must be a lowercase 40-character Git SHA")
    sidecar = json_object(sidecar_bytes, f"KMS sidecar for {document.subject}")
    exact_keys(sidecar, {"schema_version", "envelope_b64", "jws"}, "KMS sidecar")
    if required_int(sidecar, "schema_version", "KMS sidecar") != 1:
        fail("KMS sidecar schema_version must be 1")
    envelope_bytes = canonical_base64url_decode(sidecar.get("envelope_b64"), "KMS sidecar envelope_b64")
    envelope = json_object(envelope_bytes, "KMS document envelope")
    exact_keys(
        envelope,
        {"schema_version", "purpose", "subject", "content_sha256", "source_revision", "issued_at"},
        "KMS document envelope",
    )
    if required_int(envelope, "schema_version", "KMS document envelope") != 1:
        fail("KMS document envelope schema_version must be 1")
    if required_string(envelope, "purpose", "KMS document envelope") != document.purpose:
        fail("KMS document envelope purpose does not match the document")
    if required_string(envelope, "subject", "KMS document envelope") != document.subject:
        fail("KMS document envelope subject does not match the document")
    if required_string(envelope, "source_revision", "KMS document envelope") != source_revision:
        fail("KMS document envelope source revision does not match GitHub Actions SHA")
    digest = required_string(envelope, "content_sha256", "KMS document envelope")
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        fail("KMS document envelope content_sha256 must be lowercase SHA-256")
    if digest != hashlib.sha256(document.path.read_bytes()).hexdigest():
        fail("KMS document envelope digest does not match the exact document bytes")
    issued_at = required_int(envelope, "issued_at", "KMS document envelope")
    current_time = int(time.time()) if now is None else now
    if issued_at <= 0 or issued_at > current_time + 300:
        fail("KMS document envelope issued_at is implausible")

    jws = sidecar.get("jws")
    if not isinstance(jws, dict):
        fail("KMS sidecar jws must be an object")
    exact_keys(jws, {"protected", "payload", "signature"}, "KMS sidecar jws")
    protected = required_string(jws, "protected", "KMS sidecar jws")
    protected_header = json_object(canonical_base64url_decode(protected, "KMS JWS protected header"), "KMS JWS protected header")
    supported_header_parameters = {"alg", "kid", "b64", "crit", "typ", "iss"}
    unsupported_header_parameters = sorted(set(protected_header).difference(supported_header_parameters))
    if unsupported_header_parameters:
        # Parameter names are public JWS metadata, but keep the diagnostic
        # bounded and JSON-escaped so a malformed broker response cannot
        # inject untrusted text into an Actions log.
        rendered = ",".join(json.dumps(parameter, ensure_ascii=True) for parameter in unsupported_header_parameters[:16])
        suffix = ",..." if len(unsupported_header_parameters) > 16 else ""
        fail(f"KMS JWS protected header has unsupported parameters: {rendered}{suffix}")
    if protected_header.get("alg") != "EdDSA" or not isinstance(protected_header.get("kid"), str) or not protected_header["kid"]:
        fail("KMS JWS protected header must include EdDSA and kid")
    detached_payload = protected_header.get("b64") is False and protected_header.get("crit") == ["b64"]
    encoded_payload = (
        ("b64" not in protected_header or protected_header.get("b64") is True)
        and "crit" not in protected_header
    )
    if not detached_payload and not encoded_payload:
        fail("KMS JWS payload encoding must be standard base64url or RFC 7797 detached")
    typ = protected_header.get("typ")
    if "typ" in protected_header and typ != "application/xsec-signed-document+json":
        fail("KMS JWS protected header typ is unsupported")
    issuer = protected_header.get("iss")
    if "iss" in protected_header and issuer != OFFICIAL_MARKETPLACE_KMS_ISSUER_URL:
        fail("KMS JWS protected header issuer does not match the pinned marketplace issuer")
    if detached_payload and jws.get("payload") != "":
        fail("detached KMS JWS payload must be empty")
    if encoded_payload and jws.get("payload") != base64.urlsafe_b64encode(envelope_bytes).decode("ascii").rstrip("="):
        fail("base64url KMS JWS payload does not bind the signed envelope")
    if len(canonical_base64url_decode(required_string(jws, "signature", "KMS sidecar jws"), "KMS JWS signature")) != 64:
        fail("KMS JWS signature must contain an Ed25519 signature")
    return sidecar


def validate_historical_sidecar(
    sidecar_bytes: bytes,
    document: MarketplaceDocument,
    *,
    now: int | None = None,
) -> str:
    """Validate a retained sidecar using the revision embedded in its envelope.

    Marketplace documents in the active index are freshly signed by the current
    protected run. A withdrawn plugin's immutable release document is not in
    that index, so its retained sidecar must instead remain bound to the
    historical protected revision recorded in its own envelope.
    """

    sidecar = json_object(sidecar_bytes, f"KMS sidecar for {document.subject}")
    exact_keys(sidecar, {"schema_version", "envelope_b64", "jws"}, "KMS sidecar")
    envelope = json_object(
        canonical_base64url_decode(sidecar.get("envelope_b64"), "KMS sidecar envelope_b64"),
        "KMS document envelope",
    )
    exact_keys(
        envelope,
        {"schema_version", "purpose", "subject", "content_sha256", "source_revision", "issued_at"},
        "KMS document envelope",
    )
    source_revision = required_string(envelope, "source_revision", "KMS document envelope")
    validate_sidecar(sidecar_bytes, document, source_revision, now=now)
    return source_revision


def download_pinned_issuer_jwks() -> bytes:
    """Fetch only the fixed official Marketplace issuer JWKS, without redirects."""

    request = Request(PINNED_KMS_JWKS_URL, headers={"Accept": "application/json"})
    try:
        with build_opener(NoRedirect()).open(request, timeout=15) as response:
            if response.status != 200 or response.geturl() != PINNED_KMS_JWKS_URL:
                fail("pinned KMS issuer JWKS returned an unexpected response")
            payload = response.read(MAX_KMS_JWKS_BYTES + 1)
    except HTTPError as error:
        raise MarketplaceKmsPublisherError("pinned KMS issuer JWKS is unavailable") from error
    except URLError as error:
        raise MarketplaceKmsPublisherError("pinned KMS issuer JWKS is unavailable") from error
    if len(payload) > MAX_KMS_JWKS_BYTES:
        fail("pinned KMS issuer JWKS exceeds the size limit")
    if not payload:
        fail("pinned KMS issuer JWKS is empty")
    return payload


def pinned_issuer_ed25519_key(jwks_bytes: bytes, kid: str) -> str:
    """Resolve one strict Ed25519 signing key from the pinned issuer JWKS."""

    if not isinstance(kid, str) or not kid or len(kid) > 256:
        fail("KMS JWS protected header kid is invalid")
    if not jwks_bytes or len(jwks_bytes) > MAX_KMS_JWKS_BYTES:
        fail("pinned KMS issuer JWKS is empty or exceeds the size limit")
    jwks = json_object(jwks_bytes, "pinned KMS issuer JWKS")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_KMS_JWKS_KEYS:
        fail("pinned KMS issuer JWKS has an invalid key set")
    selected: Mapping[str, object] | None = None
    seen_kids: set[str] = set()
    for index, value in enumerate(keys):
        if not isinstance(value, dict):
            fail(f"pinned KMS issuer JWKS key {index} is invalid")
        key_id = value.get("kid")
        if not isinstance(key_id, str) or not key_id or len(key_id) > 256 or key_id in seen_kids:
            fail("pinned KMS issuer JWKS contains an invalid or duplicate key id")
        seen_kids.add(key_id)
        if key_id == kid:
            selected = value
    if selected is None:
        fail("KMS JWS key id is not published by the pinned issuer")
    if (
        selected.get("kty") != "OKP"
        or selected.get("crv") != "Ed25519"
        or selected.get("alg") != "EdDSA"
        or selected.get("use") != "sig"
    ):
        fail("KMS JWS key does not meet the pinned EdDSA signing-key requirements")
    key_x = selected.get("x")
    if not isinstance(key_x, str) or len(canonical_base64url_decode(key_x, "KMS JWK public key")) != 32:
        fail("KMS JWK public key must be a 32-byte Ed25519 key")
    return key_x


def historical_jws_verification_material(sidecar_bytes: bytes) -> tuple[str, bytes, bytes]:
    """Return the trusted-key selector and RFC 7515/7797 signing input."""

    sidecar = json_object(sidecar_bytes, "KMS sidecar")
    jws = sidecar.get("jws")
    if not isinstance(jws, dict):
        fail("KMS sidecar jws must be an object")
    protected = required_string(jws, "protected", "KMS sidecar jws")
    header = json_object(canonical_base64url_decode(protected, "KMS JWS protected header"), "KMS JWS protected header")
    kid = required_string(header, "kid", "KMS JWS protected header")
    envelope_bytes = canonical_base64url_decode(sidecar.get("envelope_b64"), "KMS sidecar envelope_b64")
    if header.get("b64") is False and header.get("crit") == ["b64"]:
        signing_payload = envelope_bytes
    else:
        signing_payload = required_string(jws, "payload", "KMS sidecar jws").encode("ascii")
    signature = canonical_base64url_decode(jws.get("signature"), "KMS JWS signature")
    signing_input = protected.encode("ascii") + b"." + signing_payload
    if len(signing_input) > MAX_KMS_JWS_SIGNING_INPUT_BYTES:
        fail("KMS JWS signing input exceeds the size limit")
    return kid, signing_input, signature


def verify_ed25519_signature_with_node(public_key_x: str, signing_input: bytes, signature: bytes) -> None:
    """Verify a bounded JWS input using Node's built-in Ed25519 implementation."""

    node = shutil.which("node")
    if node is None:
        fail("Node.js is required to verify the pinned KMS JWS signature")
    request = stable_json(
        {
            "public_key_x": public_key_x,
            "signing_input_b64": base64.b64encode(signing_input).decode("ascii"),
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }
    )
    # Do not allow a caller-controlled NODE_OPTIONS/NODE_PATH preload to change
    # the result of this trust decision. The verifier imports only Node core
    # modules and accepts all untrusted values through stdin.
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"NODE_OPTIONS", "NODE_PATH", "NODE_REPL_HISTORY", "NODE_V8_COVERAGE"}
    }
    try:
        completed = subprocess.run(
            [node, "--input-type=module", "--eval", NODE_ED25519_VERIFY_PROGRAM],
            input=request,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=ROOT,
            env=environment,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MarketplaceKmsPublisherError("pinned KMS JWS signature verification is unavailable") from error
    if completed.returncode != 0:
        fail("pinned KMS JWS signature verification failed")


def verify_historical_sidecar_signature(
    sidecar_bytes: bytes,
    document: MarketplaceDocument,
    *,
    now: int | None = None,
    jwks_bytes: bytes | None = None,
) -> str:
    """Validate and cryptographically verify a retained KMS document sidecar.

    Disabled plugins are deliberately absent from the active marketplace index,
    so Desktop does not reach their release sidecars during normal smoke tests.
    This helper therefore performs the same pinned-issuer key selection and
    Ed25519 verification before a retained release history can pass Factory
    validation. `jwks_bytes` exists only for deterministic unit tests; normal
    callers always download the fixed issuer endpoint.
    """

    source_revision = validate_historical_sidecar(sidecar_bytes, document, now=now)
    kid, signing_input, signature = historical_jws_verification_material(sidecar_bytes)
    public_key_x = pinned_issuer_ed25519_key(
        download_pinned_issuer_jwks() if jwks_bytes is None else jwks_bytes,
        kid,
    )
    verify_ed25519_signature_with_node(public_key_x, signing_input, signature)
    return source_revision


def sidecar_from_broker_response(
    response_bytes: bytes,
    document: MarketplaceDocument,
    source_revision: str,
    *,
    now: int | None = None,
) -> bytes:
    response = json_object(response_bytes, "Cloud KMS broker response")
    exact_keys(response, {"ok", "data"}, "Cloud KMS broker response")
    if response.get("ok") is not True or not isinstance(response.get("data"), dict):
        fail("Cloud KMS broker response did not report success")
    data = response["data"]
    exact_keys(data, {"signed_document"}, "Cloud KMS broker response data")
    signed = data.get("signed_document")
    if not isinstance(signed, dict):
        fail("Cloud KMS broker response signed_document must be an object")
    exact_keys(
        signed,
        {"schema_version", "issuer_id", "issuer_url", "envelope_b64", "jws"},
        "Cloud KMS signed_document",
    )
    if signed.get("issuer_id") != OFFICIAL_MARKETPLACE_KMS_ISSUER_ID or signed.get("issuer_url") != OFFICIAL_MARKETPLACE_KMS_ISSUER_URL:
        fail("Cloud KMS broker returned an unexpected marketplace issuer")
    # Desktop intentionally reconstructs the issuer from the caller-selected
    # document purpose and rejects unknown sidecar fields.  Validate the broker
    # issuer above, then persist exactly Desktop's strict wire schema.
    sidecar = {
        "schema_version": signed.get("schema_version"),
        "envelope_b64": signed.get("envelope_b64"),
        "jws": signed.get("jws"),
    }
    result = stable_json(sidecar)
    validate_sidecar(result, document, source_revision, now=now)
    return result


def write_sidecars(sidecars: Mapping[Path, bytes]) -> None:
    """Stage every sidecar before replacing any target, avoiding partial broker output."""

    temporary_paths: list[Path] = []
    try:
        for destination, payload in sidecars.items():
            if is_link(destination):
                fail(f"KMS sidecar path must not be a symbolic link: {destination}")
            if is_link(destination.parent):
                fail(f"KMS sidecar directory must not be a symbolic link: {destination.parent}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if is_link(destination.parent) or not destination.parent.is_dir():
                fail(f"KMS sidecar directory is unavailable: {destination.parent}")
            descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
            temporary = Path(temporary_name)
            temporary_paths.append(temporary)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        for destination, temporary in zip(sidecars, temporary_paths, strict=True):
            os.replace(temporary, destination)
        temporary_paths.clear()
    finally:
        for temporary in temporary_paths:
            temporary.unlink(missing_ok=True)


def sidecar_path_for(document: MarketplaceDocument) -> Path:
    """Resolve a document's fixed output location without trusting callers."""

    return document.sidecar_path if document.sidecar_path is not None else Path(f"{document.path}.sig.jws.json")


def publish_documents(
    documents: list[MarketplaceDocument],
    source_revision: str,
    request_signed_document: Callable[[MarketplaceDocument], bytes],
    *,
    now: int | None = None,
) -> list[Path]:
    sidecars: dict[Path, bytes] = {}
    for document in documents:
        response = request_signed_document(document)
        sidecar = sidecar_from_broker_response(response, document, source_revision, now=now)
        destination = sidecar_path_for(document)
        if destination in sidecars:
            fail(f"KMS sidecar destination is duplicated: {destination}")
        sidecars[destination] = sidecar
    write_sidecars(sidecars)
    return list(sidecars)


def publish_sidecars(
    root: Path,
    source_revision: str,
    request_signed_document: Callable[[MarketplaceDocument], bytes],
    *,
    now: int | None = None,
) -> list[Path]:
    return publish_documents(marketplace_documents(root), source_revision, request_signed_document, now=now)


def validate_documents(
    documents: list[MarketplaceDocument],
    source_revision: str,
    *,
    now: int | None = None,
) -> list[Path]:
    validated: list[Path] = []
    for document in documents:
        sidecar_path = sidecar_path_for(document)
        if is_link(sidecar_path) or not sidecar_path.is_file():
            fail(f"KMS sidecar is unavailable: {sidecar_path}")
        validate_sidecar(sidecar_path.read_bytes(), document, source_revision, now=now)
        validated.append(sidecar_path)
    return validated


def validate_published_sidecars(root: Path, source_revision: str, *, now: int | None = None) -> list[Path]:
    return validate_documents(marketplace_documents(root), source_revision, now=now)


def request_json(request: Request) -> bytes:
    try:
        with build_opener(NoRedirect()).open(request, timeout=15) as response:
            if response.status != 200:
                fail(f"HTTPS signing request returned status {response.status}")
            payload = response.read(MAX_BROKER_RESPONSE_BYTES + 1)
    except HTTPError as error:
        fail(f"HTTPS signing request returned status {error.code}")
    except URLError as error:
        raise MarketplaceKmsPublisherError("HTTPS signing request failed") from error
    if len(payload) > MAX_BROKER_RESPONSE_BYTES:
        fail("HTTPS signing response exceeds the size limit")
    return payload


def github_oidc_token(environment: Mapping[str, str]) -> str:
    request_url = environment.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not request_url or not request_token:
        fail("GitHub Actions OIDC request environment is unavailable")
    parsed = urlsplit(request_url)
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or not hostname
        or not hostname.endswith(GITHUB_ACTIONS_OIDC_HOST_SUFFIX)
        or parsed.port not in {None, 443}
        or parsed.fragment
    ):
        fail("GitHub Actions OIDC request URL must use the GitHub Actions HTTPS endpoint without a fragment")
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key == "audience" for key, _ in query):
        fail("GitHub Actions OIDC request URL must not preselect an audience")
    token_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode([*query, ("audience", BROKER_AUDIENCE)]), ""))
    response = request_json(Request(token_url, headers={"Authorization": f"Bearer {request_token}", "Accept": "application/json"}))
    value = json_object(response, "GitHub Actions OIDC response")
    exact_keys(value, {"value"}, "GitHub Actions OIDC response")
    return required_string(value, "value", "GitHub Actions OIDC response")


def request_cloud_signature(document: MarketplaceDocument, oidc_token: str, source_revision: str) -> bytes:
    if not GITHUB_SHA_PATTERN.fullmatch(source_revision):
        fail("source revision must be a lowercase 40-character Git SHA")
    payload = stable_json(
        {
            "purpose": document.purpose,
            "subject": document.subject,
            "content_b64": base64.b64encode(document.path.read_bytes()).decode("ascii"),
            "source_revision": source_revision,
        }
    )
    return request_json(
        Request(
            PRODUCTION_BROKER_URL,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {oidc_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
    )


def source_revision_from_environment(environment: Mapping[str, str]) -> str:
    # A workflow that waited in the publication queue must bind sidecars to
    # the protected-main commit it checked out after acquiring that queue, not
    # to GitHub's immutable event SHA from before it waited. Keep GITHUB_SHA
    # as the compatibility fallback for callers that do not enter that queue.
    if CURRENT_SOURCE_REVISION_ENV in environment:
        revision = environment[CURRENT_SOURCE_REVISION_ENV]
        if not GITHUB_SHA_PATTERN.fullmatch(revision):
            fail(f"{CURRENT_SOURCE_REVISION_ENV} must be a lowercase 40-character Git SHA")
        return revision
    revision = environment.get("GITHUB_SHA", "")
    if not GITHUB_SHA_PATTERN.fullmatch(revision):
        fail("GITHUB_SHA must be a lowercase 40-character GitHub Actions commit SHA")
    return revision


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="marketplace root")
    parser.add_argument("--validate-only", action="store_true", help="validate existing sidecars without acquiring OIDC")
    parser.add_argument(
        "--retained-release-plugin-id",
        help="refresh or validate only one current Marketplace immutable releases.json sidecar",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    source_revision = source_revision_from_environment(os.environ)
    try:
        documents = (
            [retained_release_document(root, args.retained_release_plugin_id)]
            if args.retained_release_plugin_id is not None
            else marketplace_documents(root)
        )
        if args.validate_only:
            validated = validate_documents(documents, source_revision)
            print(f"validated {len(validated)} KMS marketplace sidecars")
            return
        token = github_oidc_token(os.environ)
        written = publish_documents(
            documents,
            source_revision,
            lambda document: request_cloud_signature(document, token, source_revision),
        )
        print(f"published {len(written)} KMS marketplace sidecars")
    except MarketplaceKmsPublisherError as error:
        raise SystemExit(f"KMS marketplace publishing failed: {error}") from error


if __name__ == "__main__":
    main()
