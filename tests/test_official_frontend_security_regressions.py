from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_market  # noqa: E402
import validate_market  # noqa: E402
from validate_market import MarketplaceValidationError  # noqa: E402


PLUGIN_ID = "com.xsec.system-terminal"
PLUGIN_DIR = ROOT / build_market.SNAPSHOT_ROOT_RELATIVE_PATH / PLUGIN_ID
ACTIVATION_MARKER = "export function activate(host){"
SETTINGS_OPEN_CALL = 'host.request("xsec.plugin.settings.open",{})'


def terminal_contract() -> tuple[dict[str, object], str]:
    manifest = json.loads((PLUGIN_DIR / "plugin.json").read_text(encoding="utf-8"))
    source = (PLUGIN_DIR / "com.xsec.desktop" / "frontend" / "index.js").read_text(
        encoding="utf-8"
    )
    return manifest, source


def inject_activation(source: str, payload: str) -> str:
    if ACTIVATION_MARKER not in source:
        raise AssertionError("terminal fixture has no activation marker")
    return source.replace(ACTIVATION_MARKER, f"{ACTIVATION_MARKER}{payload}", 1)


class OfficialFrontendSecurityRegressionTests(unittest.TestCase):
    def test_javascript_line_terminator_consumes_crlf_once(self) -> None:
        self.assertEqual(validate_market.javascript_line_terminator("x\r\ny", 0), (1, 2))

    def test_unicode_line_separators_end_single_line_comments(self) -> None:
        manifest, source = terminal_contract()
        methods = manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]
        methods.pop("xsec.plugin.settings.open")
        source = source.replace(SETTINGS_OPEN_CALL, "undefined", 1)
        for separator in ("\u2028", "\u2029"):
            with self.subTest(separator=ord(separator)):
                payload = f'// comment{separator}{SETTINGS_OPEN_CALL};'
                with self.assertRaisesRegex(MarketplaceValidationError, "undeclared host RPC"):
                    validate_market.validate_official_frontend(
                        manifest, inject_activation(source, payload), PLUGIN_ID
                    )

    def test_escaped_request_spellings_cannot_hide_broker_calls(self) -> None:
        manifest, source = terminal_contract()
        cases = (
            (r"host.requ\u0065st(dynamicMethod,{});", "Unicode escape"),
            (r'host["requ\u0065st"](dynamicMethod,{});', "unresolved host RPC"),
            (r"host[`requ\u0065st`](dynamicMethod,{});", "unresolved host RPC"),
        )
        for payload, error in cases:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(MarketplaceValidationError, error):
                    validate_market.validate_official_frontend(
                        manifest, inject_activation(source, payload), PLUGIN_ID
                    )

    def test_uncalled_activation_closures_do_not_prove_required_rpcs(self) -> None:
        manifest, source = terminal_contract()
        source = source.replace(SETTINGS_OPEN_CALL, "undefined", 1)
        request = f"{SETTINGS_OPEN_CALL};"
        decoys = (
            f"const decoy=()=>{{{request}}};",
            f"const onDecoy=()=>{{{request}}};",
            f"const decoy=()=>{{{request}}};const holder={{decoy(){{}}}};holder.decoy();",
            f"const holder={{}};holder.decoy=()=>{{{request}}};",
            f"const decoy=()=>{{{request}}};{{const decoy=()=>{{}};decoy();}}",
            f"const holder={{onLoad:()=>{{{request}}}}};",
            f"const decoy={{load(){{{request}}}}};",
            f"class Decoy{{load(){{{request}}}}}",
        )
        for decoy in decoys:
            with self.subTest(decoy=decoy):
                with self.assertRaisesRegex(
                    MarketplaceValidationError, "activation-reachable|does not reference"
                ):
                    validate_market.validate_official_frontend(
                        manifest, inject_activation(source, decoy), PLUGIN_ID
                    )

    def test_activation_host_reassignment_invalidates_broker_proof(self) -> None:
        manifest, source = terminal_contract()
        payload = "host={request(){return Promise.resolve({})}};"
        with self.assertRaisesRegex(MarketplaceValidationError, "host broker contract"):
            validate_market.validate_official_frontend(
                manifest, inject_activation(source, payload), PLUGIN_ID
            )

    def test_comment_text_cannot_supply_activation_or_lifecycle_contracts(self) -> None:
        manifest, _ = terminal_contract()
        methods = manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]
        descriptor = next(iter(methods.values()))
        manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"] = {
            "xsec.test.get": descriptor
        }
        source = (
            "// export function activate(host) mount() update() dispose()\n"
            'function unused(){host.request("xsec.test.get",{})}\n'
            f'const padding="{"a" * 1100}";\n'
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "executable activate"):
            validate_market.validate_official_frontend(manifest, source, PLUGIN_ID)

    def test_dynamic_javascript_evaluators_are_rejected(self) -> None:
        manifest, source = terminal_contract()
        payloads = (
            'eval(\'host.request("xsec.hidden",{})\');',
            'Function("host",\'host.request("xsec.hidden",{})\')(host);',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(MarketplaceValidationError, "dynamic JavaScript evaluator"):
                    validate_market.validate_official_frontend(
                        manifest, inject_activation(source, payload), PLUGIN_ID
                    )

    def test_dynamic_host_member_cannot_hide_request(self) -> None:
        manifest, source = terminal_contract()
        payload = (
            'const member=["re","quest"].join("");'
            'host[member](["xsec","hidden"].join("."),{});'
        )
        with self.assertRaisesRegex(MarketplaceValidationError, "dynamic broker member"):
            validate_market.validate_official_frontend(
                manifest, inject_activation(source, payload), PLUGIN_ID
            )

    def test_host_request_destructuring_cannot_hide_alias_calls(self) -> None:
        manifest, source = terminal_contract()
        payloads = (
            "const {request}=host;"
            'request.call(host,["xsec","hidden"].join("."),{});',
            'const {[ ["re","quest"].join("") ]:request}=host;'
            'request.call(host,["xsec","hidden"].join("."),{});',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(MarketplaceValidationError, "destructure request"):
                    validate_market.validate_official_frontend(
                        manifest, inject_activation(source, payload), PLUGIN_ID
                    )

    def test_shadowed_controller_helper_cannot_supply_lifecycle_contract(self) -> None:
        manifest, source = terminal_contract()
        helper = "function reviewed(){return{mount(){},update(){},dispose(){}}}"
        activation = (
            "export function activate(host){"
            "const reviewed=()=>({});return reviewed(host)}"
        )
        prefix, _ = source.split(ACTIVATION_MARKER, 1)
        mutated = f"{prefix}{helper}{activation}"
        with self.assertRaisesRegex(MarketplaceValidationError, "executable mount/update/dispose"):
            validate_market.validate_official_frontend(manifest, mutated, PLUGIN_ID)

    def test_reviewed_event_callbacks_and_lifecycle_remain_valid(self) -> None:
        manifest, source = terminal_contract()
        validate_market.validate_official_frontend(manifest, source, PLUGIN_ID)


if __name__ == "__main__":
    unittest.main()
