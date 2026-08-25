from __future__ import annotations

from contextlib import nullcontext
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_market  # noqa: E402
import validate_market  # noqa: E402
from validate_market import (  # noqa: E402
    MarketplaceValidationError,
    validate_archive,
    validate_source_manifest,
    validate_source,
)


class MarketplaceValidationTests(unittest.TestCase):
    maxDiff = None

    def build_marketplace(self, destination: Path) -> None:
        command = [
            sys.executable,
            "scripts/build_market.py",
            "--clean",
            "--output-root",
            str(destination),
        ]
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)

    def test_source_gate_accepts_disposable_unsigned_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-source-test-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output)
            validate_source(ROOT, output)

    def test_source_gate_rejects_tampered_generated_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-tampered-artifact-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output)
            artifact = next(output.glob("plugins/*/.xsec-market/artifacts/*.xsec-plugin"))
            with artifact.open("ab") as handle:
                handle.write(b"tampered")
            with self.assertRaisesRegex(MarketplaceValidationError, "SHA-256"):
                validate_source(ROOT, output)

    def test_approvals_frontend_v2_contract_survives_the_generated_archive(self) -> None:
        plugin_id = "com.xsec.workspace.approvals"
        plugin_dir = ROOT / "plugins" / plugin_id
        manifest = validate_source_manifest(plugin_id, plugin_dir)
        desktop = manifest["extensions"]["com.xsec.desktop"]
        self.assertEqual(desktop["frontendApi"]["version"], 2)
        frontend = plugin_dir / "com.xsec.desktop" / "frontend" / "index.js"
        self.assertRegex(frontend.read_text(encoding="utf-8"), r"export\s+function\s+activate\s*\(\s*host\s*\)")

        with tempfile.TemporaryDirectory(prefix="xsec-market-approvals-frontend-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output)
            artifact = next(output.glob(f"plugins/{plugin_id}/.xsec-market/artifacts/*.xsec-plugin"))
            archived_manifest = validate_archive(artifact, plugin_id, "1.1.0")
            self.assertEqual(archived_manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["version"], 2)

    def test_approvals_frontend_rejects_any_noncanonical_reviewed_structure(self) -> None:
        plugin_id = "com.xsec.workspace.approvals"
        plugin_dir = ROOT / "plugins" / plugin_id
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        entrypoint = "com.xsec.desktop/frontend/index.js"
        source = (plugin_dir / entrypoint).read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory(prefix="xsec-market-approvals-structure-") as directory:
            artifact = Path(directory) / "noncanonical.xsec-plugin"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("plugin.json", json.dumps(manifest))
                archive.writestr(entrypoint, source + "\n")
            with self.assertRaisesRegex(MarketplaceValidationError, "approved official approvals frontend structure"):
                validate_archive(artifact, plugin_id, "1.1.0")

    def test_approvals_frontend_contract_rejects_placeholder_archive(self) -> None:
        plugin_id = "com.xsec.workspace.approvals"
        plugin_dir = ROOT / "plugins" / plugin_id
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        entrypoint = "com.xsec.desktop/frontend/index.js"
        source = (plugin_dir / entrypoint).read_text(encoding="utf-8")

        for label, change_manifest, archive_source, message in (
            (
                "old-api",
                lambda value: value["extensions"]["com.xsec.desktop"]["frontendApi"].update({"version": 1}),
                source,
                "frontend API v2",
            ),
            (
                "missing-session-read-permission",
                lambda value: value["extensions"]["com.xsec.desktop"]["permissions"].pop("workspace.session.read"),
                source,
                "session read permission",
            ),
            (
                "unsupported-plugin-api-engine",
                lambda value: value["extensions"]["com.xsec.desktop"]["engines"].update({"pluginApi": "^1.0.0"}),
                source,
                "plugin API 1.1 or later",
            ),
            (
                "placeholder-module",
                lambda value: None,
                "export function renderPlaceholder() {}\n",
                "export an executable activate",
            ),
            (
                "commented-out-contract",
                lambda value: None,
                """/*
export function activate(host) {
  return host.request(\"xsec.approvals.list\", {});
  return host.request(\"xsec.approvals.statistics\", {});
}
*/
export function renderPlaceholder() {}
""",
                "export an executable activate",
            ),
            (
                "regex-literal-contract",
                lambda value: None,
                "/export function activate(host) host.request(\"xsec.approvals.list\") host.request(\"xsec.approvals.statistics\")/;\n",
                "export an executable activate",
            ),
            (
                "conditional-regex-literal-contract",
                lambda value: None,
                "if (true) /export function activate(host) host.request(\"xsec.approvals.list\") host.request(\"xsec.approvals.statistics\")/;\n",
                "export an executable activate",
            ),
            (
                "quoted-export",
                lambda value: None,
                "\"export\"\nfunction activate(host) { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "export an executable activate",
            ),
            (
                "quoted-host-receiver",
                lambda value: None,
                "export function activate(host) { \"host\".request(\"xsec.approvals.list\", {}); \"host\".request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-outside-activate",
                lambda value: None,
                "export function activate(host) { return {}; }\nfunction unused() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-unreachable-activation-helper",
                lambda value: None,
                "export function activate(host) { function neverCalled() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-unreachable-arrow-helper",
                lambda value: None,
                "export function activate(host) { const neverCalled = () => { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-unreachable-expression-arrow-helper",
                lambda value: None,
                "export function activate(host) { const neverCalled = () => Promise.all([host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})]); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-unreachable-anonymous-helper",
                lambda value: None,
                "export function activate(host) { const neverCalled = function () { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-helper-shadowed-by-member-call",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } const other = { load() {} }; other.load(); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-unreachable-object-method",
                lambda value: None,
                "export function activate(host) { const neverCalled = { load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-nested-returned-object-method",
                lambda value: None,
                "export function activate(host) { return { mount() {}, extra: { update() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } } }; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-arrow-closure-returning-lifecycle",
                lambda value: None,
                "export function activate(host) { const neverCalled = () => { return { mount() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-generator-closure-returning-lifecycle",
                lambda value: None,
                "export function activate(host) { const neverCalled = function* () { return { mount() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-lifecycle-with-shadowed-host-parameter",
                lambda value: None,
                "export function activate(host) { return { mount(host) { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; }\n",
                "host broker contract",
            ),
            (
                "rpc-after-activation-return",
                lambda value: None,
                "export function activate(host) { return {}; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-asi-return-object",
                lambda value: None,
                "export function activate(host) { return {}\nhost.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-asi-bare-return",
                lambda value: None,
                "export function activate(host) { return\nhost.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-throw",
                lambda value: None,
                "export function activate(host) { throw new Error(\"stop\"); host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-helper-called-after-activation-return",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } return {}; load(); }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-lifecycle-return",
                lambda value: None,
                "export function activate(host) { return { mount() { return; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-host-reassignment",
                lambda value: None,
                "export function activate(host) { host = { request() {} }; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-helper-after-activation-host-reassignment",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } host &&= { request() {} }; load(); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-helper-after-lifecycle-host-update",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } return { mount() { ++host; load(); } }; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-lifecycle-after-activation-host-reassignment",
                lambda value: None,
                "export function activate(host) { host ??= { request() {} }; return { mount() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } }; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-helper-with-shadowed-host-parameter",
                lambda value: None,
                "export function activate(host) { function load(host) { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } load({ request() {} }); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-activation-with-shadowed-host-local",
                lambda value: None,
                "export function activate(host) { var host = { request() {} }; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-after-destructuring-host-write",
                lambda value: None,
                "export function activate(host) { ({ host } = { host: { request() {} } }); host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-after-template-host-write",
                lambda value: None,
                "export function activate(host) { `${host = { request() {} }}`; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "unsupported executable template interpolation",
            ),
            (
                "rpc-after-escaped-host-write",
                lambda value: None,
                "export function activate(host) { h\\u006fst = { request() {} }; host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "must not contain Unicode escape sequences",
            ),
            (
                "rpc-after-hoisted-helper-host-write",
                lambda value: None,
                "export function activate(host) { poison(); host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); function poison() { host = { request() {} }; } return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-statically-false-branch",
                lambda value: None,
                "export function activate(host) { if (false) Promise.all([host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})]); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-newline-statically-false-branch",
                lambda value: None,
                "export function activate(host) { if (false)\n host.request(\"xsec.approvals.list\", {}); if (true)\n undefined;\n else\n host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-newline-continued-statically-false-branch",
                lambda value: None,
                "export function activate(host) { if (false) void\n host.request(\"xsec.approvals.list\", {}); if (false) void\n host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-statically-true-else-branch",
                lambda value: None,
                "export function activate(host) { if (true) {} else { host.request(\"xsec.approvals.list\", {}); } if (true) undefined; else host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-statically-false-loop",
                lambda value: None,
                "export function activate(host) { while (false)\n host.request(\"xsec.approvals.list\", {}); for (; false;) { host.request(\"xsec.approvals.statistics\", {}); } return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-statically-false-for-update",
                lambda value: None,
                "export function activate(host) { for (; false; host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})) {} return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-false-short-circuit",
                lambda value: None,
                "export function activate(host) { false && host.request(\"xsec.approvals.list\", {}); false && host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-false-ternary-consequent",
                lambda value: None,
                "export function activate(host) { false ? host.request(\"xsec.approvals.list\", {}) : undefined; false ? host.request(\"xsec.approvals.statistics\", {}) : undefined; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-true-short-circuit",
                lambda value: None,
                "export function activate(host) { true || host.request(\"xsec.approvals.list\", {}); true || host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-true-ternary-alternate",
                lambda value: None,
                "export function activate(host) { true ? undefined : host.request(\"xsec.approvals.list\", {}); true ? undefined : host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-after-direct-eval",
                lambda value: None,
                "export function activate(host) { eval(\"host = { request() {} }\"); host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-after-function-constructor",
                lambda value: None,
                "export function activate(host) { Function(\"return undefined\")(); host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); return {}; }\n",
                "host broker contract",
            ),
            (
                "rpc-in-shadowed-duplicate-helper",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } function load() {} load(); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-helper-shadowed-by-lexical-declaration",
                lambda value: None,
                "export function activate(host) { function list() { host.request(\"xsec.approvals.list\", {}); } function statistics() { host.request(\"xsec.approvals.statistics\", {}); } { const list = () => {}; list(); } { statistics(); let statistics = () => {}; } return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-helper-shadowed-by-var-declaration",
                lambda value: None,
                "export function activate(host) { function load() { host.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {}); } var load = () => {}; load(); return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-uncalled-helper-default-parameters",
                lambda value: None,
                "export function activate(host) { function dead(value = Promise.all([host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})])) {} return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-uncalled-arrow-default-parameters",
                lambda value: None,
                "export function activate(host) { const dead = (value = Promise.all([host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})])) => {}; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "rpc-in-uncalled-method-default-parameters",
                lambda value: None,
                "export function activate(host) { const dead = { load(value = Promise.all([host.request(\"xsec.approvals.list\", {}), host.request(\"xsec.approvals.statistics\", {})])) {} }; return {}; }\n",
                "declared approvals RPC requests",
            ),
            (
                "missing-function-body",
                lambda value: None,
                "export function activate(host)\nhost.request(\"xsec.approvals.list\", {}); host.request(\"xsec.approvals.statistics\", {});\n",
                "valid executable ESM syntax",
            ),
            (
                "wrong-method-capability",
                lambda value: value["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]["xsec.approvals.list"].update({"capability": "workspace.session.write"}),
                source,
                "session read capability",
            ),
            (
                "wrong-method-binding",
                lambda value: value["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]["xsec.approvals.statistics"].update({"binding": "workspace"}),
                source,
                "session read capability",
            ),
            (
                "unexpected-method",
                lambda value: value["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"].update({"xsec.approvals.extra": {"capability": "workspace.session.read", "binding": "session"}}),
                source,
                "approvals read RPC methods",
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory(prefix=f"xsec-market-approvals-{label}-") as directory:
                candidate = json.loads(json.dumps(manifest))
                change_manifest(candidate)
                artifact = Path(directory) / f"{label}.xsec-plugin"
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr("plugin.json", json.dumps(candidate))
                    archive.writestr(entrypoint, archive_source)
                with self.assertRaises(MarketplaceValidationError) as raised:
                    validate_archive(artifact, plugin_id, "1.1.0")
                self.assertTrue(
                    message in str(raised.exception)
                    or "approved official approvals frontend structure" in str(raised.exception),
                    str(raised.exception),
                )

    def test_unsafe_zip_member_is_rejected_before_manifest_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-zip-test-") as directory:
            artifact = Path(directory) / "unsafe.xsec-plugin"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("../plugin.json", '{"name":"com.xsec.test","version":"1.0.0"}')
            with self.assertRaisesRegex(MarketplaceValidationError, "unsafe entry path"):
                validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_case_insensitive_zip_member_collision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-case-collision-") as directory:
            artifact = Path(directory) / "collision.xsec-plugin"
            manifest = '{"name":"com.xsec.test","version":"1.0.0"}'
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("plugin.json", manifest)
                archive.writestr("Plugin.json", manifest)
            with self.assertRaisesRegex(MarketplaceValidationError, "target-filesystem collision"):
                validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_windows_normalized_zip_member_collisions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-windows-collision-") as directory:
            manifest = '{"name":"com.xsec.test","version":"1.0.0"}'
            for label, first, second in (
                ("trailing-dot", "frontend/foo./bar.js", "frontend/foo/bar.js"),
                ("unicode", "frontend/café.js", "frontend/cafe\u0301.js"),
            ):
                with self.subTest(label=label):
                    artifact = Path(directory) / f"{label}.xsec-plugin"
                    with zipfile.ZipFile(artifact, "w") as archive:
                        archive.writestr("plugin.json", manifest)
                        archive.writestr(first, "first")
                        archive.writestr(second, "second")
                    with self.assertRaisesRegex(MarketplaceValidationError, "target-filesystem collision"):
                        validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_symbolic_link_zip_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-link-test-") as directory:
            artifact = Path(directory) / "link.xsec-plugin"
            link = zipfile.ZipInfo("plugin.json")
            link.external_attr = 0o120777 << 16
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(link, "plugin.json")
            with self.assertRaisesRegex(MarketplaceValidationError, "symbolic link"):
                validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_windows_reserved_and_forbidden_zip_components_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-windows-components-") as directory:
            manifest = '{"name":"com.xsec.test","version":"1.0.0"}'
            for label, member, message in (
                ("reserved", "frontend/CON.js", "reserved device-name"),
                ("reserved-superscript-one", "frontend/COM¹.js", "reserved device-name"),
                ("reserved-superscript-two", "frontend/LPT².js", "reserved device-name"),
                ("reserved-superscript-three", "frontend/COM³.js", "reserved device-name"),
                ("forbidden", "frontend/foo?.js", "Windows-forbidden character"),
            ):
                with self.subTest(label=label):
                    artifact = Path(directory) / f"{label}.xsec-plugin"
                    with zipfile.ZipFile(artifact, "w") as archive:
                        archive.writestr("plugin.json", manifest)
                        archive.writestr(member, "entrypoint")
                    with self.assertRaisesRegex(MarketplaceValidationError, message):
                        validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_windows_normalized_file_directory_prefix_collisions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-prefix-collision-") as directory:
            manifest = '{"name":"com.xsec.test","version":"1.0.0"}'
            for label, first, second in (
                ("file-then-descendant", "frontend/Foo", "frontend/foo/bar.js"),
                ("descendant-then-file", "frontend/foo/bar.js", "frontend/Foo"),
                ("explicit-directory-then-file", "frontend/Foo/", "frontend/foo"),
            ):
                with self.subTest(label=label):
                    artifact = Path(directory) / f"{label}.xsec-plugin"
                    with zipfile.ZipFile(artifact, "w") as archive:
                        archive.writestr("plugin.json", manifest)
                        archive.writestr(first, "first")
                        archive.writestr(second, "second")
                    with self.assertRaisesRegex(MarketplaceValidationError, "file/directory target-filesystem collision|target-filesystem collision"):
                        validate_archive(artifact, "com.xsec.test", "1.0.0")

    def test_source_entrypoints_must_be_regular_files_below_the_plugin_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-source-entrypoint-") as directory:
            plugin_dir = Path(directory) / "com.xsec.test"
            entrypoint = plugin_dir / "com.xsec.desktop" / "frontend" / "index.js"
            entrypoint.parent.mkdir(parents=True)
            manifest = {
                "name": "com.xsec.test",
                "version": "1.0.0",
                "extensions": {
                    "com.xsec.desktop": {
                        "engines": {"xsec": ">=1"},
                        "entrypoints": {"frontend": "./com.xsec.desktop/frontend/index.js"},
                    },
                },
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")

            with self.subTest("missing"):
                with self.assertRaisesRegex(MarketplaceValidationError, "regular file"):
                    validate_source_manifest("com.xsec.test", plugin_dir)

            entrypoint.write_text("export {};\n", encoding="utf-8")
            validate_source_manifest("com.xsec.test", plugin_dir)

            with self.subTest("escape"):
                manifest["extensions"]["com.xsec.desktop"]["entrypoints"]["frontend"] = "../escape.js"
                (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(MarketplaceValidationError, "must not escape"):
                    validate_source_manifest("com.xsec.test", plugin_dir)

            with self.subTest("directory"):
                manifest["extensions"]["com.xsec.desktop"]["entrypoints"]["frontend"] = "./com.xsec.desktop/frontend"
                (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(MarketplaceValidationError, "regular file"):
                    validate_source_manifest("com.xsec.test", plugin_dir)

            with self.subTest("symbolic-link"):
                manifest["extensions"]["com.xsec.desktop"]["entrypoints"]["frontend"] = "./com.xsec.desktop/frontend/index.js"
                (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
                with patch.object(validate_market, "is_link", side_effect=lambda path: path == entrypoint):
                    with self.assertRaisesRegex(MarketplaceValidationError, "symbolic links"):
                        validate_source_manifest("com.xsec.test", plugin_dir)

    def test_archive_entrypoints_must_be_packed_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-archive-entrypoint-") as directory:
            manifest = json.dumps({
                "name": "com.xsec.test",
                "version": "1.0.0",
                "extensions": {
                    "com.xsec.desktop": {
                        "entrypoints": {"frontend": "./com.xsec.desktop/frontend/index.js"},
                    },
                },
            })
            for label, build, message in (
                ("missing", lambda archive: None, "does not include XSEC Desktop entrypoint"),
                ("directory", lambda archive: archive.writestr("com.xsec.desktop/frontend/index.js/", ""), "must be a regular file"),
                ("symbolic-link", self.write_symbolic_link_entrypoint, "symbolic link"),
            ):
                with self.subTest(label=label):
                    artifact = Path(directory) / f"{label}.xsec-plugin"
                    with zipfile.ZipFile(artifact, "w") as archive:
                        archive.writestr("plugin.json", manifest)
                        build(archive)
                    with self.assertRaisesRegex(MarketplaceValidationError, message):
                        validate_archive(artifact, "com.xsec.test", "1.0.0")

    @staticmethod
    def write_symbolic_link_entrypoint(archive: zipfile.ZipFile) -> None:
        entrypoint = zipfile.ZipInfo("com.xsec.desktop/frontend/index.js")
        entrypoint.external_attr = 0o120777 << 16
        archive.writestr(entrypoint, "outside.js")

    def test_builder_marks_generated_entrypoints_as_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-builder-entrypoint-") as directory:
            plugin_dir = Path(directory) / "com.xsec.test"
            entrypoint = plugin_dir / "com.xsec.desktop" / "frontend" / "index.js"
            entrypoint.parent.mkdir(parents=True)
            (plugin_dir / "plugin.json").write_text(json.dumps({
                "name": "com.xsec.test",
                "version": "1.0.0",
                "extensions": {
                    "com.xsec.desktop": {
                        "entrypoints": {"frontend": "./com.xsec.desktop/frontend/index.js"},
                    },
                },
            }), encoding="utf-8")
            entrypoint.write_text("export {};\n", encoding="utf-8")
            artifact = Path(directory) / "com.xsec.test.xsec-plugin"

            build_market.write_zip(plugin_dir, artifact)
            validate_archive(artifact, "com.xsec.test", "1.0.0")
            with zipfile.ZipFile(artifact) as archive:
                info = archive.getinfo("com.xsec.desktop/frontend/index.js")
            self.assertEqual(info.external_attr >> 16, 0o100644)

    def test_manual_publish_is_rejected_outside_main_before_signing(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("enforce-publish-ref:", workflow)
        self.assertIn('EVENT_NAME: ${{ github.event_name }}', workflow)
        self.assertIn('REF: ${{ github.ref }}', workflow)
        self.assertIn('REF_PROTECTED: ${{ github.ref_protected }}', workflow)
        self.assertIn('[ "$EVENT_NAME" = "workflow_dispatch" ] && [ "$REF" != "refs/heads/main" ]', workflow)
        self.assertIn('[ "$REF_PROTECTED" != "true" ]', workflow)
        signing_job = workflow.split("  sign-and-publish:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn("needs: enforce-publish-ref", signing_job)
        self.assertIn("needs.enforce-publish-ref.result == 'success'", signing_job)
        self.assertNotIn("needs.require_publish_token.result == 'success'", signing_job)
        self.assertIn("!startsWith(github.event.head_commit.message, 'chore: publish KMS-signed marketplace artifacts')", signing_job)
        steps = workflow.split("  sign-and-publish:\n", 1)[1].split("    steps:\n", 1)[1]
        self.assertLess(
            steps.index("Require the protected marketplace publication token before checkout or KMS"),
            steps.index("actions/checkout@v4"),
        )

    def test_disposable_build_rejects_nested_plugin_link_before_copytree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-copy-link-") as directory:
            source_root = Path(directory) / "source"
            plugin_root = source_root / "plugins"
            plugin_dir = plugin_root / "com.xsec.test"
            nested_link = plugin_dir / "linked"
            outside = source_root / "outside"
            destination = Path(directory) / "destination"
            marketplace = source_root / ".agents" / "plugins" / "marketplace.json"
            plugin_dir.mkdir(parents=True)
            outside.mkdir()
            try:
                nested_link.symlink_to(outside, target_is_directory=True)
                link_check = nullcontext()
            except OSError:
                # Some Windows developer machines cannot create symlinks. The
                # CI test uses a real link; retain a local regression check of
                # the same detection branch when this capability is absent.
                nested_link.mkdir()
                link_check = patch.object(build_market, "is_link", side_effect=lambda path: path == nested_link)
            marketplace.parent.mkdir(parents=True)
            marketplace.write_text('{"plugins": []}\n', encoding="utf-8")

            with (
                patch.object(build_market, "PLUGIN_ROOT", plugin_root),
                patch.object(build_market, "MARKETPLACE", marketplace),
                patch.object(build_market.shutil, "copytree") as copytree,
                link_check,
            ):
                with self.assertRaisesRegex(ValueError, "plugin package must not contain symbolic links"):
                    build_market.copy_source_tree(destination)
                copytree.assert_not_called()

    def test_disposable_build_rejects_linked_plugin_root_before_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-root-link-") as directory:
            source_root = Path(directory) / "source"
            plugin_root = source_root / "plugins"
            destination = Path(directory) / "destination"
            plugin_root.mkdir(parents=True)

            with (
                patch.object(build_market, "PLUGIN_ROOT", plugin_root),
                patch.object(build_market, "is_link", side_effect=lambda path: path == plugin_root),
                patch.object(Path, "iterdir") as iterdir,
                patch.object(build_market.shutil, "copytree") as copytree,
            ):
                with self.assertRaisesRegex(ValueError, "plugin root must not be a symbolic link"):
                    build_market.copy_source_tree(destination)
                iterdir.assert_not_called()
                copytree.assert_not_called()

    def test_disposable_build_rejects_linked_marketplace_before_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-index-link-") as directory:
            source_root = Path(directory) / "source"
            plugin_root = source_root / "plugins"
            marketplace = source_root / ".agents" / "plugins" / "marketplace.json"
            destination = Path(directory) / "destination"
            plugin_root.mkdir(parents=True)
            marketplace.parent.mkdir(parents=True)
            marketplace.write_text('{"plugins": []}\n', encoding="utf-8")

            for linked_path in (marketplace, marketplace.parent):
                with self.subTest(linked_path=linked_path):
                    with (
                        patch.object(build_market, "PLUGIN_ROOT", plugin_root),
                        patch.object(build_market, "MARKETPLACE", marketplace),
                        patch.object(build_market, "is_link", side_effect=lambda path: path == linked_path),
                        patch.object(build_market.shutil, "copyfile") as copyfile,
                    ):
                        with self.assertRaisesRegex(ValueError, "marketplace metadata path must not contain symbolic links"):
                            build_market.copy_source_tree(destination)
                        copyfile.assert_not_called()

    def test_build_rejects_manifest_path_components_before_writing_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-artifact-name-") as directory:
            root = Path(directory)
            source_plugin_dir = root / "source-plugin"
            source_plugin_dir.mkdir()
            output_plugin_dir = root / "output-plugin"
            base_manifest = {
                "name": "com.xsec.test",
                "version": "1.0.0",
                "extensions": {"com.xsec.desktop": {"engines": {"xsec": ">=1"}}},
            }
            for field, invalid_value in (("name", "C:\\runner"), ("version", "../outside")):
                with self.subTest(field=field, invalid_value=invalid_value):
                    manifest = dict(base_manifest)
                    manifest[field] = invalid_value
                    (source_plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
                    with patch.object(build_market, "write_zip") as write_zip:
                        with self.assertRaisesRegex(ValueError, "safe filename component"):
                            build_market.build_plugin(source_plugin_dir, output_plugin_dir)
                        write_zip.assert_not_called()

    def test_cleanup_rejects_linked_plugin_root_before_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-clean-link-") as directory:
            output_root = Path(directory) / "output"
            output_plugins = output_root / "plugins"
            output_plugins.mkdir(parents=True)

            with (
                patch.object(build_market, "is_link", side_effect=lambda path: path == output_plugins),
                patch.object(Path, "exists") as exists,
                patch.object(Path, "iterdir") as iterdir,
                patch.object(build_market.shutil, "rmtree") as rmtree,
            ):
                with self.assertRaisesRegex(ValueError, "generated plugin root must not be a symbolic link"):
                    build_market.clean_generated_output(output_root)
                exists.assert_not_called()
                iterdir.assert_not_called()
                rmtree.assert_not_called()

    def test_cleanup_rejects_linked_plugin_directory_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-clean-child-link-") as directory:
            output_root = Path(directory) / "output"
            output_plugins = output_root / "plugins"
            linked_plugin = output_plugins / "com.xsec.test"
            linked_plugin.mkdir(parents=True)

            with (
                patch.object(build_market, "is_link", side_effect=lambda path: path == linked_plugin),
                patch.object(build_market.shutil, "rmtree") as rmtree,
            ):
                with self.assertRaisesRegex(ValueError, "generated plugin directory must not be a symbolic link"):
                    build_market.clean_generated_output(output_root)
                rmtree.assert_not_called()


if __name__ == "__main__":
    unittest.main()
