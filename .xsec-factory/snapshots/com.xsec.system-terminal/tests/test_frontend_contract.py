from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT
FRONTEND = PLUGIN_ROOT / "com.xsec.desktop" / "frontend" / "index.js"


class FrontendContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = FRONTEND.read_text(encoding="utf-8")

    def test_terminal_surface_contains_only_terminal_content_and_errors(self) -> None:
        surface = self.source.split("function terminalSurface(host)", 1)[1]
        self.assertIn('screen.setAttribute("aria-label", "系统终端")', self.source)
        self.assertIn("启动终端失败：", self.source)
        for text in ("打开插件设置", "重试启动终端", "重新打开终端", "点击终端区域后直接键入命令"):
            self.assertNotIn(text, surface)

    def test_settings_follow_host_theme_and_limit_windows_profiles(self) -> None:
        """Keep themed Windows profiles and the Unix login-shell label aligned."""

        self.assertIn("host.onTheme?.(apply)", self.source)
        self.assertIn(':root[data-theme="light"]', self.source)
        self.assertIn('view?.platform === "windows"', self.source)
        self.assertIn('new Set(["cmd", "windows-powershell", "powershell-7"])', self.source)
        self.assertIn("effective.label || effective.id", self.source)
        self.assertIn("新建终端使用当前帐户的登录 Shell。", self.source)

    def test_terminal_open_delegates_the_saved_profile_to_the_host(self) -> None:
        opened = self.source.split("async function openTerminal", 1)[1]
        opened = opened.split("function scheduleWrite", 1)[0]
        self.assertIn('host.request("xsec.terminal.open", terminalSize(state))', opened)
        self.assertNotIn('host.request("xsec.terminal.settings.get"', opened)
        self.assertNotIn("profileId", opened)
        self.assertNotIn("navigator.userAgent", opened)
        opened = self.source.split("state.terminalId = handle.terminal_id", 1)[1]
        opened = opened.split("function scheduleWrite", 1)[0]
        self.assertIn("resizeTerminal(host, state)", opened)

    def test_terminal_size_uses_the_visible_content_box(self) -> None:
        size = self.source.split("function terminalSize", 1)[1]
        size = size.split("async function openTerminal", 1)[0]
        self.assertIn("getComputedStyle(screen)", size)
        for edge in ("paddingLeft", "paddingRight", "paddingTop", "paddingBottom"):
            self.assertIn(edge, size)

    def test_settings_read_failure_offers_an_explicit_retry(self) -> None:
        settings = self.source.split("async function loadSettings", 1)[1]
        settings = settings.split("function terminalSettings", 1)[0]
        self.assertIn('retry = e("button", "", "重试读取设置")', settings)
        self.assertIn('state.controls.retry.hidden = false', settings)
        self.assertIn('system-terminal.settings.retry', settings)
        self.assertIn('void loadSettings(host, state)', settings)
        self.assertIn('actions.append(save); retryActions.append(retry)', settings)
        self.assertIn('form, systemDefault, retryActions, notice', settings)
        failure = settings.split("catch (error)", 1)[1]
        self.assertNotIn("renderSettingsView", failure)
        self.assertNotIn("state.ready = true", failure)

    def test_polling_stops_on_read_failure_and_throttles_idle_reads(self) -> None:
        poll = self.source.split("async function poll", 1)[1]
        poll = poll.split("function terminalSize", 1)[0]
        self.assertIn("IDLE_POLL_INTERVAL_MS = 500", self.source)
        self.assertIn("await failTerminal(host, state, `读取终端失败\uFF1A", poll)
        self.assertNotIn("schedulePoll(host, state", poll.split("catch (error)", 1)[1].split("finally", 1)[0])

    def test_terminal_failure_closes_once_and_scrollback_is_bounded(self) -> None:
        failure = self.source.split("async function failTerminal", 1)[1].split("function appendScreen", 1)[0]
        self.assertLess(failure.index('state.terminalId = ""'), failure.index('host.request("xsec.terminal.close"'))
        self.assertLess(failure.index('host.request("xsec.terminal.close"'), failure.index("report(state"))
        self.assertEqual(failure.count('host.request("xsec.terminal.close"'), 1)
        self.assertIn('state.reading = false; state.writing = false; state.inputBuffer = ""', failure)
        self.assertIn("catch (error) { closeError = error; }", failure)
        self.assertIn("generation !== state.generation", failure)
        self.assertNotIn("throw closeError", failure)
        append = self.source.split("function appendScreen", 1)[1].split("function isCurrentTerminal", 1)[0]
        self.assertIn("MAX_SCROLLBACK_CHARACTERS = 200_000", self.source)
        self.assertIn("text.appendData(clean(value))", append)
        self.assertIn("text.deleteData(0, overflow)", append)
        self.assertNotIn("textContent +=", self.source)

    def test_superseded_resize_failures_do_not_stop_the_terminal(self) -> None:
        resize = self.source.split("function resizeTerminal", 1)[1]
        resize = resize.split("function buildTerminal", 1)[0]
        self.assertIn("const resizeGeneration = ++state.resizeGeneration", resize)
        self.assertIn("resizeGeneration === state.resizeGeneration", resize)
        self.assertIn("resizeGeneration: 0", self.source)

    def test_remount_owns_theme_and_async_terminal_results(self) -> None:
        self.assertGreaterEqual(self.source.count("state.theme = followHostTheme(host)"), 2)
        self.assertIn("generation !== state.generation", self.source)
        self.assertIn("isCurrentTerminal(state, generation, terminalId)", self.source)
        self.assertIn('state.terminalId = ""', self.source)
        dispose = self.source.split("async function disposeTerminal", 1)[1]
        dispose = dispose.split("function terminalSurface", 1)[0]
        self.assertLess(dispose.index("cancelAnimationFrame(state.inputFrame)"), dispose.index("state.inputFrame = 0"))

    def test_manifest_versions_and_frontend_methods_match(self) -> None:
        manifest = json.loads((PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8"))
        codex = json.loads((PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], codex["version"])
        methods = manifest["extensions"]["com.xsec.desktop"]["frontendApi"]["methods"]
        requested = set(re.findall(r'host\.request\("([^"]+)"', self.source))
        self.assertEqual(requested, set(methods))

    def test_activation_returns_explicit_lifecycle_helpers(self) -> None:
        activation = self.source.split("export function activate(host)", 1)[1]
        self.assertIn('return terminalSettings(host)', activation)
        self.assertIn('return terminalSurface(host)', activation)

    def test_source_respects_workspace_complexity_limits(self) -> None:
        lines = self.source.splitlines()
        self.assertLessEqual(len(lines), 300)
        starts = [index for index, line in enumerate(lines) if re.match(r"^(?:async )?function ", line)]
        ends = starts[1:] + [len(lines)]
        for start, end in zip(starts, ends, strict=True):
            self.assertLessEqual(end - start, 50, lines[start])


if __name__ == "__main__":
    unittest.main()
