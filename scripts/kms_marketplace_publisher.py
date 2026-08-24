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
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE_INDEX_SUBJECT = ".agents/plugins/marketplace.json"
BROKER_AUDIENCE = "xsec-kms-document-signing-v1"
PRODUCTION_BROKER_URL = "https://api.54321000.xyz/v2/internal/signing/documents"
GITHUB_ACTIONS_OIDC_HOST_SUFFIX = ".actions.githubusercontent.com"
OFFICIAL_MARKETPLACE_KMS_ISSUER_ID = "dc24288e-f77c-4c13-81a7-f649afbe7b73"
OFFICIAL_MARKETPLACE_KMS_ISSUER_URL = f"https://kms.vercel.com/{OFFICIAL_MARKETPLACE_KMS_ISSUER_ID}"
MAX_BROKER_RESPONSE_BYTES = 64 * 1024
GITHUB_SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class MarketplaceKmsPublisherError(ValueError):
    """The broker or a generated sidecar violates the Desktop protocol."""


@dataclass(frozen=True)
class MarketplaceDocument:
    purpose: str
    subject: str
    path: Path


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
    return [documents[0], *sorted(documents[1:], key=lambda document: document.subject)]


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


def publish_sidecars(
    root: Path,
    source_revision: str,
    request_signed_document: Callable[[MarketplaceDocument], bytes],
    *,
    now: int | None = None,
) -> list[Path]:
    documents = marketplace_documents(root)
    sidecars: dict[Path, bytes] = {}
    for document in documents:
        response = request_signed_document(document)
        sidecar = sidecar_from_broker_response(response, document, source_revision, now=now)
        destination = Path(f"{document.path}.sig.jws.json")
        sidecars[destination] = sidecar
    write_sidecars(sidecars)
    return list(sidecars)


def validate_published_sidecars(root: Path, source_revision: str, *, now: int | None = None) -> list[Path]:
    validated: list[Path] = []
    for document in marketplace_documents(root):
        sidecar_path = Path(f"{document.path}.sig.jws.json")
        if is_link(sidecar_path) or not sidecar_path.is_file():
            fail(f"KMS sidecar is unavailable: {sidecar_path}")
        validate_sidecar(sidecar_path.read_bytes(), document, source_revision, now=now)
        validated.append(sidecar_path)
    return validated


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


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


def request_cloud_signature(document: MarketplaceDocument, oidc_token: str) -> bytes:
    payload = stable_json(
        {
            "purpose": document.purpose,
            "subject": document.subject,
            "content_b64": base64.b64encode(document.path.read_bytes()).decode("ascii"),
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
    revision = environment.get("GITHUB_SHA", "")
    if not GITHUB_SHA_PATTERN.fullmatch(revision):
        fail("GITHUB_SHA must be a lowercase 40-character GitHub Actions commit SHA")
    return revision


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="marketplace root")
    parser.add_argument("--validate-only", action="store_true", help="validate existing sidecars without acquiring OIDC")
    args = parser.parse_args()
    root = args.root.resolve()
    source_revision = source_revision_from_environment(os.environ)
    try:
        if args.validate_only:
            validated = validate_published_sidecars(root, source_revision)
            print(f"validated {len(validated)} KMS marketplace sidecars")
            return
        token = github_oidc_token(os.environ)
        written = publish_sidecars(root, source_revision, lambda document: request_cloud_signature(document, token))
        print(f"published {len(written)} KMS marketplace sidecars")
    except MarketplaceKmsPublisherError as error:
        raise SystemExit(f"KMS marketplace publishing failed: {error}") from error


if __name__ == "__main__":
    main()
