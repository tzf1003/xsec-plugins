from __future__ import annotations

import json
import re
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
ACTIVATION_PATTERN = re.compile(
    r"(?m)^[ \t]*export\s+(?:async\s+)?function\s+activate\s*\(\s*host\s*\)\s*\{"
)
ACTIVATION_PROBE = "__xsec_activation_probe__"
FIXTURE_RPC_METHOD = "xsec.terminal.write"
FIXTURE_RPC_CALL = f'host.request("{FIXTURE_RPC_METHOD}",{{}})'
FIXTURE_RPC_PATTERN = re.compile(
    rf'host\.request\(\s*"{re.escape(FIXTURE_RPC_METHOD)}"\s*,\s*\{{[^{{}}]*\}}\s*\)'
)


def terminal_contract() -> tuple[dict[str, object], str]:
    """Load the published system-terminal manifest and frontend fixture."""

    manifest = json.loads((PLUGIN_DIR / "plugin.json").read_text(encoding="utf-8"))
    source = (PLUGIN_DIR / "com.xsec.desktop" / "frontend" / "index.js").read_text(
        encoding="utf-8"
    )
    return manifest, source


def activation_match(source: str) -> re.Match[str]:
    """Locate the executable exported activation declaration in source."""

    baseline = validate_market.javascript_contract_tokens(source, "terminal fixture")
    if ("identifier", ACTIVATION_PROBE) in baseline:
        raise AssertionError("terminal fixture contains the activation probe")
    for match in ACTIVATION_PATTERN.finditer(source):
        probed = f"{source[:match.end()]}{ACTIVATION_PROBE};{source[match.end():]}"
        tokens = validate_market.javascript_contract_tokens(probed, "terminal fixture")
        if ("identifier", ACTIVATION_PROBE) in tokens:
            return match
    raise AssertionError("terminal fixture has no executable activation marker")


def inject_activation(source: str, payload: str) -> str:
    """Insert a security-regression payload into executable activation."""

    match = activation_match(source)
    return f"{source[:match.end()]}{payload}{source[match.end():]}"


def without_fixture_rpc(source: str) -> str:
    """Remove the declared terminal RPC used as a security-test fixture."""

    rewritten, count = FIXTURE_RPC_PATTERN.subn("undefined", source)
    if count == 0:
        raise AssertionError("terminal fixture has no declared RPC call")
    return rewritten


class OfficialFrontendSecurityRegressionTests(unittest.TestCase):
    def test_activation_injection_accepts_reviewed_formatting(self) -> None:
        """Allow reviewed spacing around a synchronous activation declaration."""

        source = (
            "// export function activate(host){\n"
            "export function activate(host) { return terminalSurface(host); }\n"
        )
        self.assertIn(
            "activate(host) {const injected=true; return",
            inject_activation(source, "const injected=true;"),
        )

    def test_activation_injection_accepts_async_formatting(self) -> None:
        """Allow the optional async keyword in an activation declaration."""

        source = "export async function activate ( host ) { return terminalSurface(host); }\n"
        self.assertIn(
            "activate ( host ) {const injected=true; return",
            inject_activation(source, "const injected=true;"),
        )

    def test_activation_injection_ignores_non_executable_text(self) -> None:
        """Skip activation-like text in comments and template literals."""

        source = (
            "/*\nexport function activate(host) { return commented; }\n*/\n"
            "const example = `\nexport async function activate(host) { return templated; }\n`;\n"
            "export function activate(host) { return terminalSurface(host); }\n"
        )
        injected = inject_activation(source, "const injected=true;")
        self.assertEqual(injected.count("const injected=true;"), 1)
        self.assertIn(
            "return templated; }\n`;\nexport function activate(host) {const injected=true; return",
            injected,
        )

    def test_javascript_line_terminator_consumes_crlf_once(self) -> None:
        self.assertEqual(validate_market.javascript_line_terminator("x\r\ny", 0), (1, 2))

    def test_unicode_line_separators_end_single_line_comments(self) -> None:
        """Treat both Unicode line separators as JavaScript comment endings."""

        manifest, source = terminal_contract()
        methods = manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]
        methods.pop(FIXTURE_RPC_METHOD)
        source = without_fixture_rpc(source)
        for separator in ("\u2028", "\u2029"):
            with self.subTest(separator=ord(separator)):
                payload = f"// comment{separator}{FIXTURE_RPC_CALL};"
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
        """Require the fixture RPC to remain reachable from activation."""

        manifest, source = terminal_contract()
        source = without_fixture_rpc(source)
        request = f"{FIXTURE_RPC_CALL};"
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
        """Reject lifecycle evidence supplied by a shadowed controller helper."""

        manifest, source = terminal_contract()
        helper = "function reviewed(){return{mount(){},update(){},dispose(){}}}"
        activation = (
            "export function activate(host){"
            "const reviewed=()=>({});return reviewed(host)}"
        )
        prefix = source[:activation_match(source).start()]
        mutated = f"{prefix}{helper}{activation}"
        with self.assertRaisesRegex(MarketplaceValidationError, "executable mount/update/dispose"):
            validate_market.validate_official_frontend(manifest, mutated, PLUGIN_ID)

    def test_reviewed_event_callbacks_and_lifecycle_remain_valid(self) -> None:
        manifest, source = terminal_contract()
        validate_market.validate_official_frontend(manifest, source, PLUGIN_ID)


if __name__ == "__main__":
    unittest.main()
