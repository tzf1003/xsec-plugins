from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
import re
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
import marketplace_contract  # noqa: E402
import promote_release  # noqa: E402
import validate_market  # noqa: E402
from validate_market import (  # noqa: E402
    MarketplaceValidationError,
    validate_archive,
    validate_source_manifest,
    validate_source,
)


def snapshot_dir(root: Path, plugin_id: str) -> Path:
    """Return the retained Factory snapshot directory for one plugin."""

    return root / build_market.SNAPSHOT_ROOT_RELATIVE_PATH / plugin_id


def traffic_release_contract() -> tuple[dict[str, object], str]:
    """Load the reviewed Traffic 1.3.0 manifest and frontend fixtures."""

    fixture = ROOT / "tests" / "fixtures"
    manifest = json.loads((fixture / "traffic-1.3.0-plugin.json").read_text(encoding="utf-8"))
    source = (fixture / "traffic-1.3.0-frontend.js").read_text(encoding="utf-8")
    return manifest, source


TERMINAL_ACTIVATION_PATTERN = re.compile(
    r"(?m)^[ \t]*export\s+(?:async\s+)?function\s+activate\s*\(\s*host\s*\)\s*\{"
)
TERMINAL_ACTIVATION_PROBE = "__xsec_activation_probe__"
TERMINAL_FIXTURE_RPC_METHOD = "xsec.terminal.write"
TERMINAL_FIXTURE_RPC_PROBE = "xsec.terminal.fixture-probe"


def terminal_activation_match(source: str) -> re.Match[str]:
    """Locate the executable exported activation declaration."""

    baseline = validate_market.javascript_contract_tokens(source, "terminal fixture")
    if ("identifier", TERMINAL_ACTIVATION_PROBE) in baseline:
        raise AssertionError("terminal fixture contains the activation probe")
    for match in TERMINAL_ACTIVATION_PATTERN.finditer(source):
        probed = f"{source[:match.end()]}{TERMINAL_ACTIVATION_PROBE};{source[match.end():]}"
        tokens = validate_market.javascript_contract_tokens(probed, "terminal fixture")
        if ("identifier", TERMINAL_ACTIVATION_PROBE) in tokens:
            return match
    raise AssertionError("terminal fixture has no executable activation marker")


def terminal_rpc_match(source: str, method: str) -> re.Match[str]:
    """Locate one activation-reachable direct terminal RPC call."""

    if TERMINAL_FIXTURE_RPC_PROBE in source:
        raise AssertionError("terminal fixture contains the RPC probe")
    pattern = re.compile(rf'host\.request\(\s*"{re.escape(method)}"\s*,\s*\{{[^{{}}]*\}}\s*\)')
    for match in pattern.finditer(source):
        replacement = f'host.request("{TERMINAL_FIXTURE_RPC_PROBE}",{{}})'
        probed = replace_source_match(source, match, replacement)
        tokens = validate_market.javascript_contract_tokens(probed, "terminal fixture")
        try:
            requests = validate_market.frontend_host_requests(tokens, "terminal fixture")
            if TERMINAL_FIXTURE_RPC_PROBE in requests:
                return match
        except MarketplaceValidationError:
            continue
    raise AssertionError(f"terminal fixture has no executable {method} RPC")


def terminal_fixture_rpc_match(source: str) -> re.Match[str]:
    """Locate the declared terminal write RPC used by mutation tests."""

    return terminal_rpc_match(source, TERMINAL_FIXTURE_RPC_METHOD)


def replace_source_match(source: str, match: re.Match[str], replacement: str) -> str:
    """Replace the exact source span selected by an executable match."""

    return f"{source[:match.start()]}{replacement}{source[match.end():]}"


def mutate_terminal_activation(source: str, body: str, prefix: str = "") -> str:
    """Splice test code around the executable activation declaration."""

    match = terminal_activation_match(source)
    replacement = f"{prefix}{match.group(0)}{body}"
    return replace_source_match(source, match, replacement)


def assert_asset_settings_isolation(case: unittest.TestCase, source: str, dashboard_source: str, host_source: str) -> None:
    """Assert that asset settings failures remain isolated by surface."""

    if "type RunsLoadState" in dashboard_source:
        case.assertIn("setRunsError(", dashboard_source)
        case.assertIn("setSettingsError(", dashboard_source)
        case.assertIn("const next = await api.settings()", dashboard_source)
        case.assertIn("Promise.all([runs.loadRuns(true), setup.loadDefaults(), setup.loadSettings()])", dashboard_source)
        case.assertNotIn("setRuns([])", dashboard_source)
        case.assertIn('host.request("xsec.asset-discovery.settings.get", {})', host_source)
        return
    if "setRuns(await api.runs())" in source:
        case.assertIn("setRunsError(", source)
        case.assertIn("setSettings(await api.settings())", source)
        case.assertIn("setSettingsError(", source)
        case.assertIn("Promise.all([runs.loadRuns(),setup.loadDefaults(),setup.loadSettings()])", source)
        case.assertNotIn("setRuns([])", source)
        case.assertIn('provider==="fofa"?settings.fofaApiKeyConfigured', source)
        return
    case.assertRegex(source, r'Promise\.resolve\(\)\.then\(\(?\(\)=>host\.request\("xsec\.asset-discovery\.settings\.get",\{\}\)')
    case.assertRegex(source, r'const\s*\[\s*runsData\s*,\s*assetsData\s*,\s*settings\s*\]\s*=\s*await\s+Promise\.all')
    case.assertRegex(source, r'if\s*\(\s*"error"\s*in\s*settings\s*\)')
    case.assertRegex(source, r'renderRuns\(runsData\);renderAssets\(assetsData\);if\s*\(\s*"error"\s*in\s*settings\s*\)')
    case.assertIn('const provider=settings.value?.provider==="fofa"?"fofa":"hunter";const missing=provider==="fofa"?!settings.value?.fofaApiKeyConfigured:!settings.value?.hunterApiKeyConfigured;', source)


def frontend_section(case: unittest.TestCase, source: str, start: str, end: str) -> str:
    """Extract one named Traffic frontend section for focused assertions."""

    before, delimiter, remainder = source.partition(start)
    case.assertTrue(delimiter, f"missing frontend section: {start}")
    section, delimiter, _ = remainder.partition(end)
    case.assertTrue(delimiter, f"missing frontend section boundary: {end}")
    return section


def assert_traffic_react_loaders(case: unittest.TestCase, source: str) -> None:
    """Assert loader state and error isolation across Traffic settings sections."""

    default_filter = frontend_section(case, source, "function DefaultFilterSection({host})", "function samePassiveRule")
    rules = frontend_section(case, source, "function RulesSection({host})", "function SettingsPage")
    ca_model = frontend_section(case, source, "function useCaModel(host)", "function CaLoading")
    case.assertRegex(
        default_filter,
        r"setLoading\(!0\),setError\(void 0\),setSaved\(!1\),loadSettings\(host\)"
        r"\.then\(value=>\{active&&editRevision\.current===startedAtEdit&&"
        r"\(filterRef\.current=value,setFilter\(value\)\)\}\)"
        r"\.catch\(reason=>\{active&&setError\(`[^`]{1,}\$\{String\(reason\)\}[^`]*`\)\}\)"
        r"\.finally\(\(\)=>\{active&&setLoading\(!1\)\}\)",
    )
    case.assertIn("error?u2(Notice,{action:", default_filter)
    case.assertIn("children:error", default_filter)
    case.assertRegex(
        rules,
        r"setLoading\(!0\),setError\(void 0\),loadRules\(host\)"
        r"\.then\(value=>\{active&&setRules\(value\)\}\)"
        r"\.catch\(reason=>\{active&&setError\(`[^`]{1,}\$\{String\(reason\)\}[^`]*`\)\}\)"
        r"\.finally\(\(\)=>\{active&&setLoading\(!1\)\}\)",
    )
    case.assertIn("error?u2(Notice,{action:", rules)
    case.assertIn("children:error", rules)
    case.assertRegex(
        ca_model,
        r"setBusy\(!0\),setError\(void 0\),loadCaStatus\(host\)"
        r"\.then\(value=>\{active&&setStatus\(value\)\}\)"
        r"\.catch\(reason=>\{active&&setError\(`[^`]{1,}\$\{String\(reason\)\}[^`]*`\)\}\)"
        r"\.finally\(\(\)=>\{active&&setBusy\(!1\)\}\)",
    )


def assert_traffic_react_rules(case: unittest.TestCase, source: str) -> None:
    """Assert reviewed passive-rule mutations and their refresh ordering."""

    rules = frontend_section(case, source, "function RulesSection({host})", "function SettingsPage")
    mutations = frontend_section(case, source, "function ruleMutations", "function RulesSection({host})")
    handlers = (
        ("save:async()=>{", "},toggle:async", "await saveRule(host,submitted)"),
        ("toggle:async", "},remove:async", "await toggleRule(host,rule.rule_id,enabled)"),
        ("remove:async()=>{", "}}}", "await deleteRule(host,ruleId)"),
    )
    for start, end, mutation in handlers:
        handler_source = frontend_section(case, mutations, start, end)
        case.assertIn(mutation, handler_source)
        case.assertIn("await refreshRules(reload,setError,", handler_source)
        case.assertLess(handler_source.index(mutation), handler_source.index("await refreshRules(reload,setError,"))
        case.assertRegex(
            handler_source,
            r"catch\(reason\)\{setError\(`[^`]{1,}\$\{String\(reason\)\}[^`]*`\)\}",
        )
    case.assertIn("let reload=async()=>{setRules(await loadRules(host))}", rules)
    case.assertIn("function refreshRules(reload,setError,completed){try{await reload()}catch(reason){setError(", source)
    case.assertIn(
        "{save,toggle:toggle2,remove}=ruleMutations({host,reload,draftRef,updateDraft,deleteId,setDeleteId,setBusy,setError})",
        rules,
    )
    for callback in ("onSave:()=>void save()", "onToggle:(rule,enabled)=>void toggle2(rule,enabled)", "onClick:()=>void remove()"):
        case.assertIn(callback, rules)
    rule_actions = (
        ("async function loadRules(host)", "async function saveRule", 'host.request("xsec.traffic.passive-rules.list",{})'),
        ("async function saveRule(host,rule)", "async function toggleRule", 'host.request("xsec.traffic.passive-rules.upsert",{'),
        ("async function toggleRule", "async function deleteRule", 'host.request("xsec.traffic.passive-rules.toggle",{'),
        ("async function deleteRule", "var EVENT_COALESCE_MS", 'host.request("xsec.traffic.passive-rules.delete",{'),
    )
    for start, end, request in rule_actions:
        case.assertIn(request, frontend_section(case, source, start, end))


def assert_traffic_react_ca(case: unittest.TestCase, source: str) -> None:
    """Assert MITM CA status, import, and rotation error handling."""

    ca_model = frontend_section(case, source, "function useCaModel(host)", "function CaLoading")
    ca_ui = frontend_section(case, source, "function CaStatusDetails({host,model})", "function DefaultFilterSection")
    case.assertIn("let model=useCaModel(host)", ca_ui)
    case.assertIn("u2(CaError,{model})", ca_ui)
    case.assertIn("u2(CaStatusDetails,{host,model})", ca_ui)
    case.assertIn("model.run(()=>importCa(host),", ca_ui)
    case.assertIn("model.run(()=>rotateCa(host),", ca_ui)
    case.assertRegex(
        ca_model,
        r"run:async\(action,name\)=>\{setBusy\(!0\),setError\(void 0\);try\{setStatus\(await action\(\)\)\}"
        r"catch\(reason\)\{setError\(`[^`]{1,}\$\{String\(reason\)\}[^`]*`\)\}finally\{setBusy\(!1\)\}\}",
    )
    ca_actions = (
        ("async function loadCaStatus(host)", "async function importCa", 'host.request("xsec.traffic.ca.status",{})'),
        ("async function importCa(host)", "async function rotateCa", 'caStatus(await host.request("xsec.traffic.ca.import",{}))'),
        ("async function rotateCa(host)", "function passiveRule", 'caStatus(await host.request("xsec.traffic.ca.rotate",{}))'),
    )
    for start, end, request in ca_actions:
        case.assertIn(request, frontend_section(case, source, start, end))


def assert_traffic_react_activation(case: unittest.TestCase, source: str) -> None:
    """Assert settings rendering remains reachable from Traffic activation."""

    activation = frontend_section(case, source, "function activate(host)", "return __toCommonJS")
    plugin_app = frontend_section(case, source, "function PluginApp({host,context})", "function object2")
    settings_page = frontend_section(case, source, "function SettingsPage({host})", "function workspaceInstanceKey")
    settings_api = frontend_section(case, source, "async function loadSettings(host)", "async function saveSettings")
    settings_save = frontend_section(case, source, "async function saveSettings(host,filter)", "function caStatus")
    default_filter = frontend_section(case, source, "function DefaultFilterSection({host})", "function samePassiveRule")
    case.assertIn('host.request("xsec.traffic.settings.get",{})', settings_api)
    case.assertIn('host.request("xsec.traffic.settings.set",{filter:settingsToDomain(filter)})', settings_save)
    case.assertRegex(
        default_filter,
        r"let save=async\(\)=>\{if\(!filter\)return;let submitted=filter;setSaving\(!0\),setError\(void 0\),setSaved\(!1\);"
        r"try\{let response=await saveSettings\(host,submitted\);[^;]*\}catch\(reason\)\{setError\(`[^`]{1,}\$\{String\(reason\)\}[^`]*`\)\}"
        r"finally\{setSaving\(!1\)\}\}",
    )
    case.assertIn("onClick:()=>void save()", default_filter)
    case.assertIn("G(u2(PluginApp,{host,context:current}),root)", activation)
    case.assertIn('if(context.kind==="settings-page")return u2(SettingsPage,{host})', plugin_app)
    for section in ("DefaultFilterSection", "CaSection", "RulesSection"):
        case.assertIn(f"u2({section},{{host}})", settings_page)


def assert_traffic_react_settings_isolation(case: unittest.TestCase, source: str) -> None:
    """Assert the reviewed React settings contract preserves loaded state."""

    assert_traffic_react_loaders(case, source)
    assert_traffic_react_rules(case, source)
    assert_traffic_react_ca(case, source)
    assert_traffic_react_activation(case, source)
    for setter in ("setFilter", "setRules", "setStatus"):
        for cleared_value in ("void 0", "null", "undefined", "[]"):
            case.assertNotIn(f"{setter}({cleared_value})", source)


def assert_traffic_settings_isolation(case: unittest.TestCase, source: str) -> None:
    """Assert Traffic settings isolation for current and retained frontends."""

    if "function RulesSection({host})" in source:
        assert_traffic_react_settings_isolation(case, source)
        return
    case.assertIn('async function loadRules(){renderRules(await host.request("xsec.traffic.passive-rules.list",{}))}', source)
    case.assertIn('async function loadCa(){const view=await host.request("xsec.traffic.ca.status",{});', source)
    case.assertIn('settingsReady=true;controls.save.disabled=false;await Promise.all', source)
    case.assertIn('await Promise.all([loadCa(),loadRules()]);note("")}catch(error){note(`', source)
    case.assertIn('enabled.onchange=()=>void toggle(rule.rule_id,enabled.checked,enabled);', source)
    case.assertIn('control.checked=!enabled;note(`更新被动规则失败：', source)
    case.assertIn('CA 已导入，但刷新 CA 状态失败', source)
    case.assertIn('规则已保存，但刷新规则列表失败', source)
    case.assertIn('规则已删除，但刷新规则列表失败', source)


class MarketplaceValidationTests(unittest.TestCase):
    maxDiff = None

    def test_traffic_react_settings_contract_fixture(self) -> None:
        """Keep the reviewed React settings fixture pinned to its digest."""

        fixture = ROOT / "tests" / "fixtures" / "traffic-1.3.0-frontend.js"
        payload = fixture.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "3cea53b5bed45f4e148a47000f8a65bb53d778b768fe70f994eee6ba146c77d8",
        )
        assert_traffic_react_settings_isolation(self, payload.decode("utf-8"))

    def test_traffic_reviewed_frontend_contract_accepts_release_bundle(self) -> None:
        """Accept the complete reviewed Traffic 1.3.0 release contract."""

        manifest, source = traffic_release_contract()
        validate_market.validate_official_frontend(manifest, source, "Traffic 1.3.0")

    def test_traffic_contract_accepts_a_new_source_version(self) -> None:
        """Accept a new Traffic version once its broker surface is verified."""

        manifest, source = traffic_release_contract()
        manifest["version"] = "1.3.1"
        candidate = source.replace("traffic.frontend.activate", "traffic.frontend.1.3.1", 1)
        validate_market.validate_official_frontend(manifest, candidate, "Traffic 1.3.1")

    def test_traffic_contract_rejects_undeclared_rpc_mutation(self) -> None:
        """Reject a source change that expands the approved Traffic surface."""

        manifest, source = traffic_release_contract()
        mutated = source.replace("xsec.traffic.list", "xsec.traffic.hidden", 1)
        with self.assertRaisesRegex(MarketplaceValidationError, "declared Traffic RPC surface"):
            validate_market.validate_official_frontend(manifest, mutated, "Traffic 1.3.0")

    def test_traffic_contract_rejects_reassigned_rpc_host(self) -> None:
        """Reject a helper that replaces its broker before making an RPC."""

        manifest, source = traffic_release_contract()
        mutated = source.replace(
            "function listTraffic(host,cursor,filter){",
            "function listTraffic(host,cursor,filter){host={request(){return Promise.resolve({})}};",
            1,
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "Traffic host broker contract"):
            validate_market.validate_official_frontend(manifest, mutated, "Traffic 1.3.0")

    def test_traffic_contract_rejects_destructured_rpc_host(self) -> None:
        """Reject a helper that replaces its broker by destructuring."""

        manifest, source = traffic_release_contract()
        mutated = source.replace(
            "function listTraffic(host,cursor,filter){",
            "function listTraffic(host,cursor,filter){({host}={host:{request(){return Promise.resolve({})}}});",
            1,
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "Traffic host broker contract"):
            validate_market.validate_official_frontend(manifest, mutated, "Traffic 1.3.0")

    def test_traffic_reviewed_frontend_contract_rejects_rpc_drift(self) -> None:
        """Reject capability or binding drift in the reviewed Traffic RPCs."""

        manifest, source = traffic_release_contract()
        methods = manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]
        methods["xsec.traffic.reference.add"]["binding"] = "plugin"
        with self.assertRaisesRegex(MarketplaceValidationError, "reviewed Traffic RPC contract"):
            validate_market.validate_official_frontend(manifest, source, "Traffic 1.3.0")

    def test_composer_capability_requires_plugin_api_1_4_for_any_method_name(self) -> None:
        """Require Plugin API 1.4 for every Composer-capable method name."""

        manifest, source = traffic_release_contract()
        manifest["extensions"]["com.xsec.desktop"]["engines"]["pluginApi"] = "^1.3.0"
        with self.assertRaisesRegex(MarketplaceValidationError, "plugin API 1.4"):
            validate_market.validate_official_frontend(manifest, source, "Traffic 1.3.0")

    def test_browser_surface_methods_require_plugin_api_1_4(self) -> None:
        """Require Plugin API 1.4 for Browser Surface control methods."""

        plugin_id = "com.xsec.workspace.browser"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        methods = manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]
        methods["xsec.browser.surface.open"] = {
            "capability": "browser.control",
            "binding": "session",
        }
        manifest["extensions"]["com.xsec.desktop"]["engines"]["pluginApi"] = "^1.3.0"
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        with self.assertRaisesRegex(MarketplaceValidationError, "browser surface methods"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def build_marketplace(self, destination: Path) -> None:
        """Build a disposable marketplace tree for source-gate assertions."""

        command = [
            sys.executable,
            "scripts/build_market.py",
            "--clean",
            "--source-only",
            "--output-root",
            str(destination),
        ]
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)

    def test_source_gate_accepts_disposable_unsigned_output(self) -> None:
        """Accept a disposable unsigned marketplace produced from current sources."""

        with tempfile.TemporaryDirectory(prefix="xsec-market-source-test-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output)
            validate_source(ROOT, output, allow_pending_native_sources=True)

    def test_source_gate_preserves_active_discovery_and_default_set_in_disposable_output(self) -> None:
        """The temporary output retains active entries and their default policy."""

        expected_defaults = set(validate_market.active_default_official_plugin_ids(ROOT))
        expected_entries = {
            plugin_id
            for plugin_id, _ in marketplace_contract.active_official_plugin_policies(ROOT)
        }
        with tempfile.TemporaryDirectory(prefix="xsec-market-active-default-set-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output)
            entries = validate_market.marketplace_entries(output, expected_default_ids=expected_defaults)
            self.assertEqual(
                {plugin_id for plugin_id, _, _ in entries},
                expected_entries,
            )
            self.assertEqual(
                {
                    plugin_id
                    for plugin_id, _, entry in entries
                    if entry.get("policy") == marketplace_contract.DEFAULT_INSTALLATION_POLICY
                },
                expected_defaults,
            )

    def test_official_plugin_settings_pages_and_plugin_bound_rpcs_are_declared(self) -> None:
        """The six reviewed settings surfaces remain field-renderable packages."""

        contracts = validate_market.OFFICIAL_PLUGIN_SETTINGS_CONTRACT
        self.assertEqual(set(contracts), {
            "com.xsec.asset-discovery",
            "com.xsec.project-workspace",
            "com.xsec.system-terminal",
            "com.xsec.workspace.approvals",
            "com.xsec.workspace.browser",
            "com.xsec.workspace.traffic",
        })
        for plugin_id, contract in contracts.items():
            with self.subTest(plugin_id=plugin_id):
                plugin_dir = snapshot_dir(ROOT, plugin_id)
                manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
                source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
                validate_market.validate_official_settings_contract(manifest, plugin_id)
                self.assertIn("host.context?.kind", source)
                self.assertIn("settings-page", source)
                self.assertIn(
                    f"onSettingsPage:{contract['page']}",
                    manifest["extensions"]["com.xsec.desktop"]["activationEvents"],
                )
                for method, (capability, binding) in contract["methods"].items():
                    self.assertIn(method, source)
                    descriptor = manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"][method]
                    self.assertEqual(descriptor, {"capability": capability, "binding": binding})

    def test_official_plugin_settings_rejects_session_bound_read(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        manifest = json.loads((snapshot_dir(ROOT, plugin_id) / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]["xsec.terminal.settings.get"]["binding"] = "session"
        with self.assertRaisesRegex(MarketplaceValidationError, "canonical plugin settings permission"):
            validate_market.validate_official_settings_contract(manifest, plugin_id)

    def test_official_plugin_settings_rejects_missing_settings_activation(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        manifest = json.loads((snapshot_dir(ROOT, plugin_id) / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["activationEvents"] = ["onWorkspaceTool:system-terminal"]
        with self.assertRaisesRegex(MarketplaceValidationError, "activate for its canonical plugin settings page"):
            validate_market.validate_official_settings_contract(manifest, plugin_id)

    def test_terminal_settings_contract_is_limited_to_persistent_profile_data(self) -> None:
        self.assertEqual(
            validate_market.OFFICIAL_PLUGIN_SETTINGS_CONTRACT["com.xsec.system-terminal"]["methods"],
            {
                "xsec.terminal.settings.get": ("pluginData.read", "plugin"),
                "xsec.terminal.settings.set": ("pluginData.write", "plugin"),
            },
        )

    def test_terminal_settings_navigation_is_validated_when_declared(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        manifest = json.loads((snapshot_dir(ROOT, plugin_id) / "plugin.json").read_text(encoding="utf-8"))
        methods = manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]
        methods["xsec.plugin.settings.open"] = {"capability": "terminal.shell", "binding": "session"}
        with self.assertRaisesRegex(MarketplaceValidationError, "canonical plugin settings permission"):
            validate_market.validate_official_settings_contract(manifest, plugin_id)

    def test_terminal_settings_navigation_rejects_null_descriptor(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        manifest = json.loads((snapshot_dir(ROOT, plugin_id) / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]["xsec.plugin.settings.open"] = None
        with self.assertRaisesRegex(MarketplaceValidationError, "canonical plugin settings permission"):
            validate_market.validate_official_settings_contract(manifest, plugin_id)

    def test_official_frontend_rejects_undeclared_host_request(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"].pop("xsec.plugin.settings.open", None)
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        source = mutate_terminal_activation(source, 'host.request("xsec.plugin.settings.open",{});')
        with self.assertRaisesRegex(MarketplaceValidationError, "calls undeclared host RPC methods"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_terminal_fixture_matches_preserve_executable_offsets(self) -> None:
        activation_decoy = 'const activation="export function activate(host){";'
        rpc_decoy = 'const rpc=\'host.request("xsec.terminal.write",{})\';'
        source = (
            f"{activation_decoy}{rpc_decoy}\n"
            'export function activate(host){host.request("xsec.terminal.write",{})}'
        )
        activation = terminal_activation_match(source)
        rpc = terminal_fixture_rpc_match(source)
        prefix_length = len(f"{activation_decoy}{rpc_decoy}\n")
        activation_offset = source.index("export function activate(host){", prefix_length)
        rpc_offset = source.index('host.request("xsec.terminal.write",{})', activation_offset)
        self.assertEqual(activation.start(), activation_offset)
        self.assertEqual(rpc.start(), rpc_offset)
        self.assertIn(rpc_decoy, replace_source_match(source, rpc, "undefined"))

    def test_official_frontend_rejects_undeclared_template_literal_host_request(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"].pop("xsec.plugin.settings.open", None)
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        source = mutate_terminal_activation(source, 'host.request(`xsec.plugin.settings.open`,{});')
        with self.assertRaisesRegex(MarketplaceValidationError, "calls undeclared host RPC methods"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_official_frontend_rejects_undeclared_constant_host_request(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"].pop("xsec.plugin.settings.open", None)
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        source = mutate_terminal_activation(
            source,
            'const SETTINGS_OPEN="xsec.plugin.settings.open";host.request(SETTINGS_OPEN,{});',
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "calls undeclared host RPC methods"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_official_frontend_ignores_host_request_examples_outside_code(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        examples = (
            '// host.request("xsec.example.comment", {});',
            'const example = \'host.request("xsec.example.string", {})\';',
        )
        for example in examples:
            with self.subTest(example=example):
                validate_market.validate_official_frontend(manifest, f"{source}\n{example}\n", plugin_id)

    def test_javascript_contract_tokens_distinguish_division_from_regex_literals(self) -> None:
        source = (
            'const ratio=value/"path/segment".length;'
            'const scaled=1/"path/segment".length;'
            'value++/"path/segment".length;'
            'const matcher=/host\\.request\\("xsec\\.example"/;'
            'return /host\\.request\\("xsec\\.example"/;'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        regexes = [value for kind, value in tokens if kind == "regex"]
        strings = [value for kind, value in tokens if kind == "string"]

        self.assertEqual(len(regexes), 2)
        self.assertEqual(strings, ["path/segment", "path/segment", "path/segment"])

    def test_javascript_contract_tokens_parse_only_executable_template_expressions(self) -> None:
        source = (
            '`host.request("xsec.example.text", {})`;'
            '`${host.request("xsec.example.executable", {})}`;'
            '`${value /* denominator */ / "path/segment"}`;'
            '`${/}/.test(value) ? `nested:${value}` : "plain"}`/"path/segment";'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        requested = validate_market.frontend_host_requests(tokens, "frontend")
        regexes = [value for kind, value in tokens if kind == "regex"]
        strings = [value for kind, value in tokens if kind == "string"]

        self.assertEqual(requested, {"xsec.example.executable"})
        self.assertIn("/}/", regexes)
        self.assertEqual(strings.count("path/segment"), 2)

    def test_official_frontend_rejects_unresolved_host_request_argument(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        source = mutate_terminal_activation(source, "host.request(dynamicMethod,{});")
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_official_frontend_rejects_partially_dynamic_rpc_map(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        dispatch = (
            'const rpcMap={safe:["xsec.terminal.read"],unsafe:[dynamicMethod]};'
            "const [method]=rpcMap[key];host.request(method,{});"
        )
        source = mutate_terminal_activation(source, dispatch)
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_official_frontend_rejects_partially_dynamic_rpc_constant(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        binding = (
            'const METHOD="xsec.terminal.settings.get"+host.context.suffix;'
            "host.request(METHOD,{});"
        )
        source = mutate_terminal_activation(source, binding)
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_official_frontend_rejects_optional_and_bracket_host_request(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        calls = (
            "host?.request(dynamicMethod,{});",
            'host["request"](dynamicMethod,{});',
        )
        for call in calls:
            with self.subTest(call=call):
                mutated = mutate_terminal_activation(source, call)
                with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
                    validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_javascript_contract_tokens_do_not_treat_member_catch_as_control_header(self) -> None:
        source = 'promise.catch(error=>error)/host.request("xsec.example")/1;'
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        self.assertNotIn(("regex", '/host.request("xsec.example")/'), tokens)

    def test_javascript_contract_tokens_preserve_asi_for_break_and_continue(self) -> None:
        source = 'while(true){break\n/host.request("xsec.example")/.test("")} '
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        self.assertIn(("regex", '/host.request("xsec.example")/'), tokens)

    def test_official_frontend_rejects_parenthesized_and_continued_rpc_arguments(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        for call in (
            '(host).request(dynamicMethod,{});',
            'host.request("xsec.terminal.settings.get"+host.context.suffix,{});',
        ):
            with self.subTest(call=call):
                mutated = mutate_terminal_activation(source, call)
                with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
                    validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_excludes_unreachable_function_rpc_evidence(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        method = rpc_match.group(0)
        source = replace_source_match(source, rpc_match, "undefined")
        source += f'\nfunction example(host){{{method}}}\n'
        with self.assertRaisesRegex(MarketplaceValidationError, "does not reference declared RPC methods"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_frontend_binding_counts_include_catch_and_method_parameters(self) -> None:
        source = 'const METHOD="xsec.good";class C{send(METHOD){host.request(METHOD,{})}}try{}catch(METHOD){host.request(METHOD,{})}'
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
            validate_market.frontend_host_requests(tokens, "frontend")

    def test_javascript_contract_tokens_treat_slash_after_control_header_as_regex(self) -> None:
        source = (
            'if(true)/host.request("xsec.plugin.settings.open")/.test("");'
            'foo()/host.request("xsec.example")/.test("");'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        regexes = [value for kind, value in tokens if kind == "regex"]
        requested = validate_market.frontend_host_requests(tokens, "frontend")

        self.assertEqual(regexes, ['/host.request("xsec.plugin.settings.open")/'])
        self.assertEqual(requested, {"xsec.example"})

    def test_official_frontend_rejects_regex_text_as_declared_host_request(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        replacement = 'Promise.resolve((()=>{if(true)/host.request("xsec.terminal.write")/.test("")})())'
        source = replace_source_match(source, rpc_match, replacement)
        with self.assertRaisesRegex(MarketplaceValidationError, "does not reference declared RPC methods"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_javascript_contract_tokens_scan_division_heavy_templates(self) -> None:
        divisions = 800
        source = "`${" + "1" + "/2" * divisions + "}`"
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        slashes = [value for kind, value in tokens if kind == "punctuation" and value == "/"]

        self.assertEqual(len(slashes), divisions)

    def test_official_frontend_rejects_undeclared_request_after_template_interpolation(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"].pop("xsec.plugin.settings.open", None)
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        payload = '`${typeof of}`/host.request("xsec.plugin.settings.open",{})/1'
        source = mutate_terminal_activation(source, f"{payload};")
        tokens = validate_market.javascript_contract_tokens(payload, "frontend")
        regexes = [value for kind, value in tokens if kind == "regex"]
        self.assertEqual(regexes, [])
        self.assertEqual(
            validate_market.frontend_host_requests(tokens, "frontend"),
            {"xsec.plugin.settings.open"},
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "calls undeclared host RPC methods"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_javascript_contract_tokens_treat_slash_after_statement_block_as_regex(self) -> None:
        source = (
            'if(true){}/host.request("xsec.plugin.settings.open")/.test("");'
            '({a:1})/host.request("xsec.example",{})/1;'
            'const o={a:1}/host.request("xsec.example",{})/1;'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        regexes = [value for kind, value in tokens if kind == "regex"]
        requested = validate_market.frontend_host_requests(tokens, "frontend")

        self.assertEqual(regexes, ['/host.request("xsec.plugin.settings.open")/'])
        self.assertEqual(requested, {"xsec.example"})

    def test_official_frontend_rejects_block_regex_as_declared_host_request(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        replacement = (
            'Promise.resolve((()=>'
            '{if(true){}/host.request("xsec.terminal.write")/.test("")})())'
        )
        source = replace_source_match(source, rpc_match, replacement)
        with self.assertRaisesRegex(MarketplaceValidationError, "does not reference declared RPC methods"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_official_frontend_rejects_shadowed_rpc_constant(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        shadow = (
            'const METHOD="xsec.plugin.settings.open";'
            "function send(METHOD){host.request(METHOD,{})}"
        )
        source = mutate_terminal_activation(source, shadow)
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_javascript_contract_tokens_treat_of_as_regex_prefix_only_in_keyword_position(self) -> None:
        source = (
            '({}).of/host.request("xsec.plugin.settings.open",{})/1;'
            'typeof of/host.request("xsec.plugin.settings.open",{})/1;'
            'const of=1;of/host.request("xsec.plugin.settings.open",{})/1;'
            'for(const x of /host.request("xsec.example")/){}'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        regexes = [value for kind, value in tokens if kind == "regex"]
        requested = validate_market.frontend_host_requests(tokens, "frontend")

        self.assertEqual(regexes, ['/host.request("xsec.example")/'])
        self.assertEqual(requested, {"xsec.plugin.settings.open"})

    def test_official_frontend_rejects_undeclared_request_after_identifier_name(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"].pop("xsec.plugin.settings.open", None)
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        payloads = (
            '({}).of/host.request("xsec.plugin.settings.open",{})/1',
            'typeof of/host.request("xsec.plugin.settings.open",{})/1',
            'const of=1;of/host.request("xsec.plugin.settings.open",{})/1',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                mutated = mutate_terminal_activation(source, f"{payload};")
                with self.assertRaisesRegex(MarketplaceValidationError, "calls undeclared host RPC methods"):
                    validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_rejects_undeclared_request_after_catch_method(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"].pop("xsec.plugin.settings.open", None)
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        payload = 'Promise.resolve(1).catch(()=>1)/host.request("xsec.plugin.settings.open",{})/1'
        source = mutate_terminal_activation(source, f"{payload};")
        tokens = validate_market.javascript_contract_tokens(payload, "frontend")
        self.assertEqual([value for kind, value in tokens if kind == "regex"], [])
        with self.assertRaisesRegex(MarketplaceValidationError, "calls undeclared host RPC methods"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_official_frontend_rejects_continued_literal_rpc_argument(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        call = (
            'host.request("xsec.terminal.settings.get"'
            '.replace("terminal.settings.get","plugin.settings.open"),{})'
        )
        mutated = mutate_terminal_activation(source, f"{call};")
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_rejects_comma_host_receiver(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        mutated = mutate_terminal_activation(
            source,
            "(0,host).request(host.context.dynamicMethod,{});",
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_rejects_constructor_and_object_method_shadowed_rpc_constant(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        shadows = (
            'const METHOD="xsec.plugin.settings.open";class C{constructor(METHOD){host.request(METHOD,{})}}',
            'const METHOD="xsec.plugin.settings.open";const o={send(METHOD){host.request(METHOD,{})}};',
        )
        for shadow in shadows:
            with self.subTest(shadow=shadow):
                mutated = mutate_terminal_activation(source, shadow)
                with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
                    validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_javascript_contract_tokens_preserve_asi_for_labeled_break(self) -> None:
        source = 'done:for(;;){break done\n/host.request("xsec.plugin.settings.open")/.test("")}'
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        regexes = [value for kind, value in tokens if kind == "regex"]
        with self.assertRaisesRegex(MarketplaceValidationError, "does not call the declared host RPC surface"):
            validate_market.frontend_host_requests(tokens, "frontend")
        self.assertEqual(regexes, ['/host.request("xsec.plugin.settings.open")/'])

    def test_official_frontend_rejects_labeled_break_asi_regex_as_declared_host_request(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        replacement = (
            "Promise.resolve((()=>{done:for(;;){break done\n"
            '/host.request("xsec.terminal.write")/.test("")}})())'
        )
        source = replace_source_match(source, rpc_match, replacement)
        with self.assertRaisesRegex(MarketplaceValidationError, "does not reference declared RPC methods"):
            validate_market.validate_official_frontend(manifest, source, plugin_id)

    def test_javascript_contract_tokens_preserve_asi_for_debugger(self) -> None:
        source = 'debugger\n/host.request("xsec.example")/.test("")'
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        self.assertIn(("regex", '/host.request("xsec.example")/'), tokens)

    def test_frontend_static_rpc_maps_require_complete_elements_and_initializers(self) -> None:
        cases = (
            'const RPC={safe:["xsec.good"]};const [METHOD]=RPC[key]||[dynamic];host.request(METHOD,{})',
            'const RPC={safe:["xsec.good"+dynamic]};const [METHOD]=RPC.safe;host.request(METHOD,{})',
        )
        for source in cases:
            with self.subTest(source=source):
                tokens = validate_market.javascript_contract_tokens(source, "frontend")
                with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
                    validate_market.frontend_host_requests(tokens, "frontend")

    def test_official_frontend_rejects_host_alias_and_unscoped_rpc_constant(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved receiver"):
            mutated = mutate_terminal_activation(source, "const broker=host;broker.request(dynamicMethod,{});")
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
            mutated = mutate_terminal_activation(
                source,
                'function unrelated(){const METHOD="xsec.terminal.settings.get"};host.request(METHOD,{});',
            )
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_excludes_uncalled_nested_rpc_and_requires_actual_requests(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        call = rpc_match.group(0)
        mutated = replace_source_match(source, rpc_match, "undefined")
        mutated = mutate_terminal_activation(
            mutated,
            f'function decoy(){{{call}}};openSettings.onclick=()=>"xsec.plugin.settings.open";',
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "does not reference declared RPC methods"):
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_frontend_activation_reachability_accepts_multiline_signature(self) -> None:
        tokens = validate_market.javascript_contract_tokens(
            'export function activate(\n host\n){host.request("xsec.example",{})}',
            "frontend",
        )
        self.assertEqual(validate_market.frontend_reachable_token_indices(tokens) is not None, True)

    def test_frontend_request_identifier_must_be_the_complete_argument(self) -> None:
        source = (
            'const METHOD="xsec.good";'
            'host.request(METHOD.replace("good","bad"),{})'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
            validate_market.frontend_host_requests(tokens, "frontend")

    def test_frontend_rejects_unsupported_request_invocation_forms(self) -> None:
        cases = (
            'host.request.call(host,"xsec.bad",{})',
            '(host.request)("xsec.bad",{})',
            'const h=host;h["request"]("xsec.bad",{})',
        )
        for source in cases:
            with self.subTest(source=source):
                tokens = validate_market.javascript_contract_tokens(source, "frontend")
                with self.assertRaisesRegex(MarketplaceValidationError, "unresolved receiver"):
                    validate_market.frontend_host_requests(tokens, "frontend")

    def test_frontend_rejects_request_in_unsupported_helper_shapes(self) -> None:
        source = (
            'const helper=()=>host.request("xsec.bad",{});'
            'const object={send(){host.request("xsec.bad",{})}};'
            'export function activate(host){host.request("xsec.good",{});helper();object.send()}'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        with self.assertRaisesRegex(MarketplaceValidationError, "activation-reachable"):
            validate_market.frontend_host_requests(tokens, "frontend")

    def test_frontend_rejects_noncanonical_parenthesized_and_alias_receivers(self) -> None:
        cases = (
            '(true?fake:host).request("xsec.bad",{})',
            'const broker=host;broker?.request("xsec.bad",{})',
            'const broker=host;broker["request"]("xsec.bad",{})',
        )
        for source in cases:
            with self.subTest(source=source):
                tokens = validate_market.javascript_contract_tokens(source, "frontend")
                with self.assertRaisesRegex(MarketplaceValidationError, "unresolved receiver"):
                    validate_market.frontend_host_requests(tokens, "frontend")

    def test_frontend_callback_reachability_rejects_property_key_decoy(self) -> None:
        source = (
            'export function activate(host){'
            'function decoy(){host.request("xsec.bad",{})}'
            'const value={decoy:1};host.request("xsec.good",{});return value}'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        with self.assertRaisesRegex(MarketplaceValidationError, "activation-reachable"):
            validate_market.frontend_host_requests(tokens, "frontend")

    def test_frontend_reachability_follows_optional_named_helper_call(self) -> None:
        source = (
            'export function activate(host){'
            'function load(){host.request("xsec.good",{})}load?.()}'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        self.assertEqual(validate_market.frontend_host_requests(tokens, "frontend"), {"xsec.good"})

    def test_official_frontend_rejects_continued_identifier_rpc_argument(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        calls = (
            'const METHOD="xsec.terminal.settings.get";host.request(METHOD.replace("get","set"),{})',
            'const METHOD="xsec.terminal.settings.get";host.request(METHOD+host.context.suffix,{})',
        )
        for call in calls:
            with self.subTest(call=call):
                mutated = mutate_terminal_activation(source, f"{call};")
                with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
                    validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_rejects_untracked_helper_host_request(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        helpers = (
            'const helper=(host)=>{host.request("xsec.evil.open",{})};',
            'const helper=function(host){host.request("xsec.evil.open",{})};',
            'const api={send(host){host.request("xsec.evil.open",{})}};',
            'class H{send(host){host.request("xsec.evil.open",{})}}',
        )
        calls = ("helper(host);", "helper(host);", "api.send(host);", "new H().send(host);")
        for helper, call in zip(helpers, calls, strict=True):
            with self.subTest(helper=helper):
                mutated = mutate_terminal_activation(source, call, prefix=helper)
                with self.assertRaisesRegex(MarketplaceValidationError, "activation-reachable|unresolved receiver"):
                    validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_javascript_contract_tokens_treat_interpolation_object_slash_as_division(self) -> None:
        source = '`${{}/host.request("xsec.plugin.settings.open",{})/1}`'
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        self.assertEqual([value for kind, value in tokens if kind == "regex"], [])
        self.assertEqual(
            validate_market.frontend_host_requests(tokens, "frontend"),
            {"xsec.plugin.settings.open"},
        )

    def test_official_frontend_rejects_undeclared_request_inside_interpolation_object(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"].pop("xsec.plugin.settings.open", None)
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        payload = '`${{}/host.request("xsec.plugin.settings.open",{})/1}`'
        mutated = replace_source_match(source, rpc_match, "undefined")
        mutated = mutate_terminal_activation(mutated, f"{payload};")
        with self.assertRaisesRegex(MarketplaceValidationError, "calls undeclared host RPC methods"):
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_rejects_ternary_parenthesized_host_receiver(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        mutated = replace_source_match(source, rpc_match, "undefined")
        mutated = mutate_terminal_activation(
            mutated,
            '(true?fake:host).request("xsec.plugin.settings.open",{});',
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved receiver"):
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_rejects_alias_optional_and_bracket_request(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        calls = (
            'const broker=host;broker["request"](dynamicMethod,{})',
            "const broker=host;broker?.request(dynamicMethod,{})",
        )
        for call in calls:
            with self.subTest(call=call):
                mutated = mutate_terminal_activation(source, f"{call};")
                with self.assertRaisesRegex(MarketplaceValidationError, "unresolved receiver"):
                    validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_excludes_object_property_key_as_callback(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        call = rpc_match.group(0)
        mutated = replace_source_match(source, rpc_match, "undefined")
        mutated = mutate_terminal_activation(
            mutated,
            f"function decoy(){{{call}}};const value={{decoy:1}};",
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "does not reference declared RPC methods"):
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_rejects_later_const_binding_for_request_argument(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        mutated = mutate_terminal_activation(
            source,
            'host.request(METHOD,{});const METHOD="xsec.plugin.settings.open";',
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_rejects_rpc_map_union_from_unrelated_property(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        body = (
            'const RPC={safe:["xsec.terminal.settings.get"],'
            'write:["xsec.terminal.write"]};const [METHOD]=RPC.safe;host.request(METHOD,{});'
        )
        mutated = replace_source_match(source, rpc_match, "undefined")
        mutated = mutate_terminal_activation(mutated, body)
        with self.assertRaisesRegex(MarketplaceValidationError, "does not reference declared RPC methods"):
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_official_frontend_excludes_short_circuit_and_unselected_ternary_requests(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        payloads = (
            'false&&host.request("xsec.plugin.settings.open",{})',
            'true?0:host.request("xsec.plugin.settings.open",{})',
            'false?host.request("xsec.plugin.settings.open",{}):0',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                mutated = replace_source_match(source, rpc_match, "undefined")
                mutated = mutate_terminal_activation(mutated, f"{payload};")
                with self.assertRaisesRegex(MarketplaceValidationError, "does not reference declared RPC methods"):
                    validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_javascript_contract_tokens_treat_interpolation_function_slash_as_division(self) -> None:
        cases = (
            '`${function(){}/host.request("xsec.plugin.settings.open",{})/1}`',
            '`${class X{}/host.request("xsec.plugin.settings.open",{})/1}`',
        )
        for source in cases:
            with self.subTest(source=source):
                tokens = validate_market.javascript_contract_tokens(source, "frontend")
                self.assertEqual([value for kind, value in tokens if kind == "regex"], [])
                self.assertEqual(
                    validate_market.frontend_host_requests(tokens, "frontend"),
                    {"xsec.plugin.settings.open"},
                )

    def test_official_frontend_rejects_undeclared_request_after_interpolation_function(self) -> None:
        plugin_id = "com.xsec.system-terminal"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"].pop("xsec.plugin.settings.open", None)
        source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
        rpc_match = terminal_fixture_rpc_match(source)
        payload = '`${function(){}/host.request("xsec.plugin.settings.open",{})/1}`'
        mutated = replace_source_match(source, rpc_match, "undefined")
        mutated = mutate_terminal_activation(mutated, f"{payload};")
        with self.assertRaisesRegex(MarketplaceValidationError, "calls undeclared host RPC methods"):
            validate_market.validate_official_frontend(manifest, mutated, plugin_id)

    def test_frontend_rpc_binding_requires_source_order_and_block_scope(self) -> None:
        cases = (
            'host.request(METHOD,{});const METHOD="xsec.good";',
            'if(true){const METHOD="xsec.good"}host.request(METHOD,{})',
        )
        for source in cases:
            with self.subTest(source=source):
                tokens = validate_market.javascript_contract_tokens(source, "frontend")
                with self.assertRaisesRegex(MarketplaceValidationError, "unresolved host RPC request argument"):
                    validate_market.frontend_host_requests(tokens, "frontend")

    def test_frontend_rpc_map_preserves_property_level_values(self) -> None:
        source = (
            'const RPC={chosen:["xsec.good"],decoy:["xsec.bad"]};'
            'const [METHOD]=RPC.chosen;host.request(METHOD,{})'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        self.assertEqual(validate_market.frontend_host_requests(tokens, "frontend"), {"xsec.good"})

    def test_frontend_rpc_map_unions_genuinely_dynamic_property_values(self) -> None:
        source = (
            'const RPC={chosen:["xsec.good"],other:["xsec.other"]};'
            'const [METHOD]=RPC[key];host.request(METHOD,{})'
        )
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        self.assertEqual(
            validate_market.frontend_host_requests(tokens, "frontend"),
            {"xsec.good", "xsec.other"},
        )

    def test_frontend_excludes_requests_in_literal_dead_expressions(self) -> None:
        cases = (
            'export function activate(host){false&&host.request("xsec.bad",{})}',
            'export function activate(host){true?undefined:host.request("xsec.bad",{})}',
        )
        for source in cases:
            with self.subTest(source=source):
                tokens = validate_market.javascript_contract_tokens(source, "frontend")
                with self.assertRaisesRegex(MarketplaceValidationError, "activation-reachable"):
                    validate_market.frontend_host_requests(tokens, "frontend")

    def test_template_expression_braces_do_not_hide_request_division(self) -> None:
        cases = (
            '`${{}/host.request("xsec.bad")/1}`',
            '`${function(){}/host.request("xsec.bad")/1}`',
            '`${class X{}/host.request("xsec.bad")/1}`',
        )
        for source in cases:
            with self.subTest(source=source):
                tokens = validate_market.javascript_contract_tokens(source, "frontend")
                self.assertNotIn("regex", {kind for kind, _ in tokens})
                self.assertEqual(validate_market.frontend_host_requests(tokens, "frontend"), {"xsec.bad"})

    def test_javascript_contract_tokens_scan_division_heavy_source(self) -> None:
        divisions = 2000
        source = "x=1" + "/2" * divisions + ";"
        tokens = validate_market.javascript_contract_tokens(source, "frontend")
        slashes = [value for kind, value in tokens if kind == "punctuation" and value == "/"]
        self.assertEqual(len(slashes), divisions)

    def test_terminal_profile_controls_are_limited_to_the_settings_page_branch(self) -> None:
        source = (
            snapshot_dir(ROOT, "com.xsec.system-terminal") / "com.xsec.desktop" / "frontend" / "index.js"
        ).read_text(encoding="utf-8")
        settings_source, main_source = source.split("export function activate(host)", 1)

        # Profile selection is a persistent default, so it may only appear in
        # the isolated settings-page renderer. The terminal surface must never
        # reintroduce the old selector/restart/clear toolbar.
        self.assertIn("function terminalSettings(host)", settings_source)
        self.assertRegex(settings_source, r'profile\s*=\s*e\("select"\)')
        self.assertIn("xsec.terminal.settings.set", settings_source)
        self.assertRegex(settings_source, r"(?:settingsReady|state\.ready)\s*=\s*false")
        self.assertRegex(settings_source, r"(?:controls|state\.controls)\.save\.disabled\s*=\s*true")
        self.assertRegex(settings_source, r"(?:settingsReady|state\.ready)\s*=\s*true")
        self.assertRegex(settings_source, r"if\s*\(\s*!(?:settingsReady|state\.ready)\s*\)")
        self.assertRegex(main_source, r'host\.context\?\.kind\s*===\s*"settings-page"')
        for forbidden in (
            'e("select")',
            '"重新启动"',
            '"清屏"',
            "xsec.terminal.profiles",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, main_source)

    def test_settings_read_failures_do_not_discard_workspace_data_or_clear_the_notice(self) -> None:
        """Auxiliary plugin settings reads must not hide the useful failure state."""

        asset_source = (
            snapshot_dir(ROOT, "com.xsec.asset-discovery") / "com.xsec.desktop" / "frontend" / "index.js"
        ).read_text(encoding="utf-8")
        asset_dashboard_source = (
            snapshot_dir(ROOT, "com.xsec.asset-discovery") / "frontend-src" / "dashboard-state.ts"
        ).read_text(encoding="utf-8")
        asset_host_source = (snapshot_dir(ROOT, "com.xsec.asset-discovery") / "frontend-src" / "host.ts").read_text(encoding="utf-8")
        # Both supported renderers keep workspace data and settings errors in
        # separate state so an auxiliary settings failure remains visible.
        assert_asset_settings_isolation(self, asset_source, asset_dashboard_source, asset_host_source)
        # Credentials stay out of the generic plugin KV store and use the
        # dedicated write and clear actions with password fields.
        self.assertIn('xsec.asset-discovery.credentials.set', asset_source)
        self.assertIn('xsec.asset-discovery.credentials.clear', asset_source)
        if 'type:"password"' in asset_source:
            self.assertIn("await api.saveCredential", asset_source)
            self.assertIn("await api.clearCredential", asset_source)
        else:
            self.assertIn('type="password"', asset_source)
            self.assertIn("await load(true);note(", asset_source)
        asset_manifest = json.loads(
            (snapshot_dir(ROOT, "com.xsec.asset-discovery") / "plugin.json").read_text(encoding="utf-8")
        )
        asset_methods = asset_manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]
        self.assertEqual(asset_methods["xsec.asset-discovery.credentials.set"]["binding"], "plugin")
        self.assertEqual(asset_methods["xsec.asset-discovery.credentials.clear"]["binding"], "plugin")
        self.assertEqual(
            validate_market.OFFICIAL_PLUGIN_SETTINGS_CONTRACT["com.xsec.asset-discovery"]["methods"],
            {
                "xsec.asset-discovery.settings.get": ("pluginData.read", "plugin"),
                "xsec.asset-discovery.settings.set": ("pluginData.write", "plugin"),
                "xsec.asset-discovery.credentials.set": ("pluginData.write", "plugin"),
                "xsec.asset-discovery.credentials.clear": ("pluginData.write", "plugin"),
                "xsec.plugin.settings.open": ("pluginData.read", "plugin"),
            },
        )

        approval_source = (
            snapshot_dir(ROOT, "com.xsec.workspace.approvals") / "com.xsec.desktop" / "frontend" / "index.js"
        ).read_text(encoding="utf-8")
        self.assertIn("let settingsReady = false;", approval_source)
        self.assertIn("settingsReady = false;", approval_source)
        self.assertIn("if (!settingsReady)", approval_source)
        self.assertIn('saveButton.disabled = true;', approval_source)

        traffic_source = (
            snapshot_dir(ROOT, "com.xsec.workspace.traffic") / "com.xsec.desktop" / "frontend" / "index.js"
        ).read_text(encoding="utf-8")
        assert_traffic_settings_isolation(self, traffic_source)

        for plugin_id in validate_market.OFFICIAL_PLUGIN_SETTINGS_CONTRACT:
            if plugin_id in {"com.xsec.system-terminal", "com.xsec.workspace.traffic"}:
                continue
            frontend = snapshot_dir(ROOT, plugin_id) / "com.xsec.desktop" / "frontend" / "index.js"
            settings_source = frontend.read_text(encoding="utf-8")
            self.assertRegex(settings_source, r"settingsReady\s*=\s*false", plugin_id)
            self.assertRegex(settings_source, r"if\s*\(!(?:this\.)?settingsReady\)", plugin_id)
            self.assertRegex(settings_source, r"\bretry(?:Button)?\.onclick", plugin_id)
            self.assertRegex(settings_source, r"\.disabled\s*=\s*true", plugin_id)

    def test_v1_migration_initially_points_beta_and_stable_to_the_same_release(self) -> None:
        artifacts = [{"os": "any", "arch": "any", "url": "artifacts/test.xsec-plugin", "sha256": "a" * 64}]
        legacy = {
            "schemaVersion": 1,
            "pluginId": "com.example.test",
            "releases": [{"version": "1.0.0", "channel": "stable", "engines": {"xsec": ">=1", "pluginApi": "^1"}, "artifacts": artifacts}],
        }

        migrated = build_market.migrate_v1_release_document(legacy, "com.example.test")

        self.assertEqual(migrated["schemaVersion"], 2)
        self.assertEqual(migrated["channels"]["beta"], migrated["channels"]["stable"])
        self.assertEqual(migrated["channels"]["stable"]["releaseId"], migrated["releases"][0]["releaseId"])

    def test_release_id_canonicalization_is_cross_client_deterministic(self) -> None:
        artifacts = [
            {"os": "windows", "arch": "x86_64", "url": "windows.xsec-plugin", "sha256": "a" * 64},
            {"os": "linux", "arch": "aarch64", "url": "linux.xsec-plugin", "sha256": "b" * 64},
            {"os": "darwin", "arch": "x86_64", "url": "darwin.xsec-plugin", "sha256": "c" * 64},
        ]
        self.assertEqual(
            build_market.release_id("1.2.3", {"xsec": ">=0.1.0", "pluginApi": "^1.2.0"}, artifacts),
            "sha256-ec6330f7e2dd37747576d26c5597dcc25cd68797d19f113ff357805b2e1ceb54",
        )
        self.assertEqual(
            build_market.release_id("1.2.3", {"pluginApi": "^1.2.0", "xsec": ">=0.1.0"}, list(reversed(artifacts))),
            "sha256-ec6330f7e2dd37747576d26c5597dcc25cd68797d19f113ff357805b2e1ceb54",
        )

    def test_release_engine_and_beta_only_pointer_contract_is_strict(self) -> None:
        with self.assertRaisesRegex(ValueError, "only xsec and pluginApi"):
            build_market.require_release_engines(
                {"xsec": ">=0.1.0", "pluginApi": "^1.2.0", "feature": "preview"},
                "test release",
            )
        with tempfile.TemporaryDirectory(prefix="xsec-market-stable-pointer-") as directory:
            release_path = Path(directory) / "releases.json"
            release_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 2,
                        "pluginId": "com.example.test",
                        "releases": [],
                        "channels": {"beta": {"releaseId": None}, "stable": {"releaseId": None}},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "use null"):
                build_market.load_release_document(release_path, "com.example.test")

    def test_beta_build_requires_a_version_bump_for_new_immutable_content(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-v2-build-") as directory:
            root = Path(directory)
            plugin_dir = root / "source"
            output_dir = root / "output"
            entrypoint = plugin_dir / "frontend" / "index.js"
            entrypoint.parent.mkdir(parents=True)
            manifest = {
                "name": "com.example.test",
                "version": "1.0.0",
                "extensions": {"com.xsec.desktop": {"engines": {"xsec": ">=1", "pluginApi": "^1"}, "entrypoints": {"frontend": "./frontend/index.js"}}},
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            entrypoint.write_text("export const value = 1;\n", encoding="utf-8")

            build_market.build_plugin(plugin_dir, output_dir)
            first = build_market.load_release_document(output_dir / ".xsec-market" / "releases.json", "com.example.test")
            first_id = first["channels"]["beta"]["releaseId"]
            self.assertIsNone(first["channels"]["stable"])
            validated_first, validated_records = validate_market.validate_release_index("com.example.test", output_dir)
            self.assertEqual(validated_first, first)
            self.assertIn(first_id, validated_records)

            # A cloud release must use a new SemVer. Desktop can hot-reload a
            # same-version local dev revision, but the installer and rollback
            # records use a version path and cannot safely represent two
            # Marketplace artifacts at one version.
            entrypoint.write_text("export const value = 2;\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bump plugin.json"):
                build_market.build_plugin(plugin_dir, output_dir)
            manifest["version"] = "1.0.1"
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            build_market.build_plugin(plugin_dir, output_dir)
            second = build_market.load_release_document(output_dir / ".xsec-market" / "releases.json", "com.example.test")
            second_id = second["channels"]["beta"]["releaseId"]
            self.assertNotEqual(first_id, second_id)
            self.assertIsNone(second["channels"]["stable"])
            self.assertEqual(len(second["releases"]), 2)
            artifacts = sorted((output_dir / ".xsec-market" / "artifacts").glob("*.xsec-plugin"))
            self.assertEqual(len(artifacts), 2)
            self.assertEqual(len({artifact.name for artifact in artifacts}), 2)

    def test_release_index_keeps_historical_archive_checks_without_requiring_the_current_frontend_contract(self) -> None:
        """A new frontend policy cannot invalidate an immutable rollback archive."""

        with tempfile.TemporaryDirectory(prefix="xsec-market-historical-archive-") as directory:
            plugin_id = "com.xsec.asset-discovery"
            plugin_dir = Path(directory) / plugin_id
            entrypoint = plugin_dir / "frontend" / "index.js"
            entrypoint.parent.mkdir(parents=True)
            manifest = {
                "name": plugin_id,
                "version": "1.0.0",
                "extensions": {
                    "com.xsec.desktop": {
                        "engines": {"xsec": ">=1", "pluginApi": "^1.0.0"},
                        "entrypoints": {"frontend": "./frontend/index.js"},
                    }
                },
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            entrypoint.write_text("export function activate(){ return {}; }\n", encoding="utf-8")
            build_market.build_plugin(plugin_dir, plugin_dir)
            release_path = plugin_dir / ".xsec-market" / "releases.json"
            release = build_market.load_release_document(release_path, plugin_id)
            beta_id = release["channels"]["beta"]["releaseId"]
            beta_release = next(item for item in release["releases"] if item["releaseId"] == beta_id)
            artifact = release_path.parent / beta_release["artifacts"][0]["url"]

            with self.assertRaisesRegex(MarketplaceValidationError, "plugin API 1.2"):
                validate_archive(artifact, plugin_id, manifest["version"])
            _, records = validate_market.validate_release_index(plugin_id, plugin_dir)
            self.assertIn(beta_id, records)

    def test_stable_promotion_reuses_an_existing_release_and_changes_no_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-stable-promotion-") as directory:
            root = Path(directory)
            plugin_dir = snapshot_dir(root, "com.example.test")
            entrypoint = plugin_dir / "frontend" / "index.js"
            entrypoint.parent.mkdir(parents=True)
            manifest = {
                "name": "com.example.test",
                "version": "1.0.0",
                "extensions": {"com.xsec.desktop": {"engines": {"xsec": ">=1", "pluginApi": "^1"}, "entrypoints": {"frontend": "./frontend/index.js"}}},
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            entrypoint.write_text("export const value = 1;\n", encoding="utf-8")
            build_market.build_plugin(plugin_dir, plugin_dir)
            entrypoint.write_text("export const value = 2;\n", encoding="utf-8")
            manifest["version"] = "1.0.1"
            (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
            build_market.build_plugin(plugin_dir, plugin_dir)
            release_path = plugin_dir / ".xsec-market" / "releases.json"
            before = build_market.load_release_document(release_path, "com.example.test")
            beta_id = before["channels"]["beta"]["releaseId"]
            stable_id = before["channels"]["stable"]
            artifact_bytes = {path.name: path.read_bytes() for path in (plugin_dir / ".xsec-market" / "artifacts").glob("*.xsec-plugin")}

            self.assertTrue(promote_release.promote_stable(root, "com.example.test", str(beta_id)))
            after = build_market.load_release_document(release_path, "com.example.test")
            self.assertEqual(after["channels"]["stable"]["releaseId"], beta_id)
            self.assertNotEqual(stable_id, beta_id)
            self.assertEqual(artifact_bytes, {path.name: path.read_bytes() for path in (plugin_dir / ".xsec-market" / "artifacts").glob("*.xsec-plugin")})
            self.assertFalse(promote_release.promote_stable(root, "com.example.test", str(beta_id)))

    def test_stable_promotion_workflow_detects_snapshot_metadata_changes(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "promote-stable.yml").read_text(encoding="utf-8")

        self.assertIn("git diff --quiet -- .xsec-factory/snapshots", workflow)

    def test_stable_promotion_rejects_an_unknown_release_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-stable-promotion-invalid-") as directory:
            root = Path(directory)
            plugin_dir = snapshot_dir(root, "com.example.test") / ".xsec-market"
            plugin_dir.mkdir(parents=True)
            release = {
                "schemaVersion": 2,
                "pluginId": "com.example.test",
                "releases": [],
                "channels": {"beta": {"releaseId": None}, "stable": None},
            }
            (plugin_dir / "releases.json").write_text(json.dumps(release), encoding="utf-8")
            with self.assertRaisesRegex(promote_release.PromotionError, "target is not an existing immutable release"):
                promote_release.promote_stable(root, "com.example.test", "sha256-" + "a" * 64)

    def test_source_gate_rejects_tampered_generated_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-tampered-artifact-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output)
            artifact = next(output.glob(".xsec-factory/snapshots/*/.xsec-market/artifacts/*.xsec-plugin"))
            with artifact.open("ab") as handle:
                handle.write(b"tampered")
            with self.assertRaisesRegex(MarketplaceValidationError, "SHA-256"):
                validate_source(ROOT, output, allow_pending_native_sources=True)

    def test_approvals_frontend_v2_contract_survives_the_generated_archive(self) -> None:
        plugin_id = "com.xsec.workspace.approvals"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = validate_source_manifest(plugin_id, plugin_dir)
        desktop = manifest["extensions"]["com.xsec.desktop"]
        self.assertEqual(desktop["frontendApi"]["version"], 2)
        frontend = plugin_dir / "com.xsec.desktop" / "frontend" / "index.js"
        self.assertRegex(frontend.read_text(encoding="utf-8"), r"export\s+function\s+activate\s*\(\s*host\s*\)")

        with tempfile.TemporaryDirectory(prefix="xsec-market-approvals-frontend-") as directory:
            output = Path(directory) / "marketplace"
            self.build_marketplace(output)
            release_path = snapshot_dir(output, plugin_id) / ".xsec-market" / "releases.json"
            release = build_market.load_release_document(release_path, plugin_id)
            beta_id = release["channels"]["beta"]["releaseId"]
            beta_release = next(item for item in release["releases"] if item["releaseId"] == beta_id)
            artifact = release_path.parent / beta_release["artifacts"][0]["url"]
            archived_manifest = validate_archive(artifact, plugin_id, manifest["version"])
            self.assertEqual(archived_manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["version"], 2)

    def test_every_official_frontend_is_executable_and_placeholder_free(self) -> None:
        """Validate lifecycle shape and API floors across official frontends."""

        placeholder = "XSEC official plugin is active in Desktop."
        for plugin_dir in sorted((ROOT / build_market.SNAPSHOT_ROOT_RELATIVE_PATH).iterdir()):
            if not plugin_dir.is_dir():
                continue
            plugin_id = plugin_dir.name
            manifest = validate_source_manifest(plugin_id, plugin_dir)
            desktop = manifest["extensions"]["com.xsec.desktop"]
            methods = desktop["frontendApi"]["methods"]
            expected_plugin_api = (
                "^1.4.0"
                if validate_market.frontend_methods_with_capability(methods, "workspace.composer.write")
                or validate_market.frontend_methods_require_browser_surface_api(methods)
                else "^1.3.0"
                if "xsec.workspace.tool.open" in methods
                else "^1.2.0"
            )
            self.assertEqual(desktop["engines"]["pluginApi"], expected_plugin_api, plugin_id)
            self.assertEqual(desktop["frontendApi"]["version"], 2, plugin_id)
            self.assertTrue(desktop["frontendApi"]["methods"], plugin_id)
            source = (plugin_dir / "com.xsec.desktop" / "frontend" / "index.js").read_text(encoding="utf-8")
            self.assertNotIn(placeholder, source, plugin_id)
            self.assertIn("export function activate(host)", source, plugin_id)

    def test_generic_official_frontend_gate_rejects_success_screen_stub(self) -> None:
        """Reject an inert success screen in place of an official frontend."""

        plugin_id = "com.xsec.workspace.files"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        stub = "export function activate(host){document.body.textContent='XSEC official plugin is active in Desktop.';return{mount(){},update(){},dispose(){}}}"
        with self.assertRaisesRegex(MarketplaceValidationError, "placeholder/fallback marker"):
            validate_market.validate_official_frontend(manifest, stub, "files stub")

    def test_approvals_frontend_rejects_any_noncanonical_reviewed_structure(self) -> None:
        plugin_id = "com.xsec.workspace.approvals"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
        manifest = json.loads((plugin_dir / "plugin.json").read_text(encoding="utf-8"))
        entrypoint = "com.xsec.desktop/frontend/index.js"
        source = (plugin_dir / entrypoint).read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory(prefix="xsec-market-approvals-structure-") as directory:
            artifact = Path(directory) / "noncanonical.xsec-plugin"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("plugin.json", json.dumps(manifest))
                archive.writestr(entrypoint, source + "\n")
            with self.assertRaisesRegex(MarketplaceValidationError, "approved official approvals frontend structure"):
                validate_archive(artifact, plugin_id, manifest["version"])

    def test_approvals_frontend_contract_rejects_placeholder_archive(self) -> None:
        plugin_id = "com.xsec.workspace.approvals"
        plugin_dir = snapshot_dir(ROOT, plugin_id)
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
                "plugin API 1.2",
            ),
            (
                "missing-approvals-workspace-tool",
                lambda value: value["extensions"]["com.xsec.desktop"]["contributes"]["workspaceTools"].pop("approvals"),
                source,
                "canonical approvals workspace-tool contribution",
            ),
            (
                "renamed-approvals-workspace-tool",
                lambda value: value["extensions"]["com.xsec.desktop"]["contributes"]["workspaceTools"].update({"approval-log": value["extensions"]["com.xsec.desktop"]["contributes"]["workspaceTools"].pop("approvals")}),
                source,
                "canonical approvals workspace-tool contribution",
            ),
            (
                "missing-approvals-workspace-tool-activation",
                lambda value: value["extensions"]["com.xsec.desktop"].update({"activationEvents": []}),
                source,
                "workspace-tool activation event",
            ),
            (
                "renamed-approvals-workspace-tool-activation",
                lambda value: value["extensions"]["com.xsec.desktop"].update({"activationEvents": ["onWorkspaceTool:approval-log"]}),
                source,
                "workspace-tool activation event",
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
                "host broker contract",
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
                    validate_archive(artifact, plugin_id, manifest["version"])
                self.assertTrue(
                    message in str(raised.exception)
                    or "approved official approvals frontend structure" in str(raised.exception),
                    str(raised.exception),
                )

    def test_dot_prefixed_mcp_json_member_does_not_raise_keyerror(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-dot-mcp-") as directory:
            artifact = Path(directory) / "dot-mcp.xsec-plugin"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("plugin.json", '{"name":"com.xsec.test","version":"1.0.0"}')
                archive.writestr("./mcp.json", json.dumps({"mcpServers": {}}))
            try:
                validate_archive(artifact, "com.xsec.test", "1.0.0")
            except MarketplaceValidationError:
                pass

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
                        "engines": {"xsec": ">=1", "pluginApi": "^1"},
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

    def test_builder_normalizes_utf8_text_line_endings_without_changing_binary_members(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-line-endings-") as directory:
            root = Path(directory)
            windows_plugin = root / "windows" / "com.xsec.test"
            unix_plugin = root / "unix" / "com.xsec.test"
            for plugin_dir, line_ending in ((windows_plugin, "\r\n"), (unix_plugin, "\n")):
                entrypoint = plugin_dir / "com.xsec.desktop" / "frontend" / "index.js"
                entrypoint.parent.mkdir(parents=True)
                (plugin_dir / "plugin.json").write_bytes(
                    (json.dumps({"name": "com.xsec.test", "version": "1.0.0"}) + line_ending).encode("utf-8")
                )
                entrypoint.write_bytes(f"export const platform = 'test';{line_ending}".encode("utf-8"))
                (plugin_dir / "asset.pdf").write_bytes(b"%PDF-1.7\r\nstream\r\n%%EOF\r\n")

            windows_artifact = root / "windows.xsec-plugin"
            unix_artifact = root / "unix.xsec-plugin"
            build_market.write_zip(windows_plugin, windows_artifact)
            build_market.write_zip(unix_plugin, unix_artifact)

            self.assertEqual(windows_artifact.read_bytes(), unix_artifact.read_bytes())
            with zipfile.ZipFile(windows_artifact) as archive:
                self.assertEqual(archive.read("com.xsec.desktop/frontend/index.js"), b"export const platform = 'test';\n")
                self.assertEqual(archive.read("asset.pdf"), b"%PDF-1.7\r\nstream\r\n%%EOF\r\n")

    def test_manual_publish_is_rejected_outside_main_before_signing(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("enforce-publish-ref:", workflow)
        self.assertIn('EVENT_NAME: ${{ github.event_name }}', workflow)
        self.assertIn('REF: ${{ github.ref }}', workflow)
        self.assertIn('REF_PROTECTED: ${{ github.ref_protected }}', workflow)
        self.assertIn("workflow_dispatch)", workflow)
        self.assertIn('[ "$REF" = "refs/heads/main" ] || {', workflow)
        self.assertIn("Manual marketplace publishing is permitted only from refs/heads/main.", workflow)
        self.assertIn('[ "$REF_PROTECTED" != "true" ]', workflow)
        classify_job = workflow.split("  classify-generated-main-change:\n", 1)[1].split("  sign-and-publish:\n", 1)[0]
        # GitHub skips a job whose dependency was skipped, regardless of the
        # downstream condition.  A protected-main manual dispatch must give
        # the classifier a successful, explicit non-generated result so the
        # external Beta/Stable request can reach the signing gate.  Pushes
        # remain the only event that classifies a main merge range.
        self.assertIn("github.event_name == 'workflow_dispatch' || github.event_name == 'push'", classify_job)
        self.assertIn("if: ${{ github.event_name == 'push' }}", classify_job)
        self.assertIn('EVENT_NAME: ${{ github.event_name }}', classify_job)
        self.assertIn('[ "$EVENT_NAME" = "workflow_dispatch" ]', classify_job)
        self.assertIn('echo "generated=false" >> "$GITHUB_OUTPUT"', classify_job)
        self.assertLess(
            classify_job.index('[ "$EVENT_NAME" = "workflow_dispatch" ]'),
            classify_job.index('[[ "$BEFORE" =~ ^[a-f0-9]{40}$'),
        )
        signing_job = workflow.split("  sign-and-publish:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn(
            "needs: [enforce-publish-ref, classify-generated-main-change, build-native-sidecars]",
            signing_job,
        )
        self.assertIn("always()", signing_job)
        self.assertIn("needs.enforce-publish-ref.result == 'success'", signing_job)
        self.assertIn("github.event_name == 'workflow_dispatch' || github.event_name == 'push'", signing_job)
        self.assertIn("needs.build-native-sidecars.result == 'success'", signing_job)
        self.assertNotIn("needs.require_publish_token.result == 'success'", signing_job)
        self.assertIn("needs.classify-generated-main-change.outputs.generated != 'true'", signing_job)
        self.assertNotIn("github.event.head_commit.message", signing_job)
        steps = workflow.split("  sign-and-publish:\n", 1)[1].split("    steps:\n", 1)[1]
        self.assertLess(
            steps.index("Require the protected marketplace publication token before checkout or KMS"),
            steps.index("actions/checkout@v4"),
        )
        sidecar_job = workflow.split("  build-native-sidecars:\n", 1)[1].split("  sign-and-publish:\n", 1)[0]
        self.assertIn("XSEC_DESKTOP_SIDECAR_SOURCE_APP_ID", sidecar_job)
        self.assertIn("repository: tzf1003/xSecDesktop", sidecar_job)
        self.assertIn("ref: ${{ inputs.native_sidecars_source_sha }}", sidecar_job)
        self.assertIn("repos/tzf1003/xSecDesktop/commits/main", sidecar_job)
        self.assertIn("--package xsec-attack-path-mcp", sidecar_job)
        self.assertIn("--package xsec-asset-discovery-mcp", sidecar_job)
        self.assertIn("xsec-native-sidecars-${{ matrix.rust_target }}", sidecar_job)
        self.assertIn("com.xsec.asset-discovery@$target=$asset_discovery_binary", steps)
        self.assertIn("--native-sidecar-source-revision", steps)

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
                with self.assertRaisesRegex(ValueError, "plugin source tree must not contain symbolic links"):
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
                "extensions": {"com.xsec.desktop": {"engines": {"xsec": ">=1", "pluginApi": "^1"}}},
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
            output_plugins = output_root / build_market.SNAPSHOT_ROOT_RELATIVE_PATH
            output_plugins.mkdir(parents=True)

            with (
                patch.object(build_market, "is_link", side_effect=lambda path: path == output_plugins),
                patch.object(Path, "exists") as exists,
                patch.object(Path, "iterdir") as iterdir,
            ):
                with self.assertRaisesRegex(ValueError, "generated plugin root must not be a symbolic link"):
                    build_market.clean_generated_output(output_root)
                exists.assert_not_called()
                iterdir.assert_not_called()

    def test_cleanup_rejects_linked_plugin_directory_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-market-clean-child-link-") as directory:
            output_root = Path(directory) / "output"
            output_plugins = output_root / build_market.SNAPSHOT_ROOT_RELATIVE_PATH
            linked_plugin = output_plugins / "com.xsec.test"
            linked_plugin.mkdir(parents=True)

            with (
                patch.object(build_market, "is_link", side_effect=lambda path: path == linked_plugin),
            ):
                with self.assertRaisesRegex(ValueError, "generated plugin directory must not be a symbolic link"):
                    build_market.clean_generated_output(output_root)


if __name__ == "__main__":
    unittest.main()
