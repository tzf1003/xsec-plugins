import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_market  # noqa: E402
import materialize_first_party_source as materializer  # noqa: E402


PLUGIN_ID = "com.xsec.workspace.sub-agent"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout.decode("utf-8").strip()


class FirstPartySourceMaterializerTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        verifier = patch.object(materializer, "verify_historical_sidecar_signature", return_value="a" * 40)
        verifier.start()
        self.addCleanup(verifier.stop)
        # Materialization queries the real fixed public Factory origin before
        # reading artifacts. Unit fixtures use isolated repositories, so make
        # that read-only remote result equal their actual local HEAD while
        # retaining a dedicated stale-remote regression below.
        self.remote_main = patch.object(
            materializer,
            "trusted_factory_remote_main",
            side_effect=lambda root: git(root, "rev-parse", "HEAD"),
        )
        self.remote_main.start()
        self.addCleanup(self.remote_main.stop)

    def manifest(self, version: str) -> dict[str, object]:
        return {
            "name": PLUGIN_ID,
            "version": version,
            "extensions": {
                "com.xsec.desktop": {
                    "engines": {"xsec": ">=1", "pluginApi": "^1"},
                    "entrypoints": {"frontend": "frontend.js"},
                }
            },
        }

    def archive(self, path: Path, version: str, *, traversal: bool = False) -> dict[str, object]:
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("plugin.json", json.dumps(self.manifest(version), separators=(",", ":")))
            archive.writestr(
                ".codex-plugin/plugin.json",
                json.dumps({"name": PLUGIN_ID, "version": version}, separators=(",", ":")),
            )
            archive.writestr("frontend.js", f"export function activate() {{ return '{version}'; }}\n")
            if traversal:
                archive.writestr("../escape.txt", "not allowed")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        artifact = {"os": "any", "arch": "any", "url": f"artifacts/{path.name}", "sha256": digest}
        return {
            "releaseId": build_market.release_id(version, {"xsec": ">=1", "pluginApi": "^1"}, [artifact]),
            "version": version,
            "engines": {"xsec": ">=1", "pluginApi": "^1"},
            "artifacts": [artifact],
        }

    def make_factory(self, root: Path, *, traversal: bool = False) -> tuple[dict[str, object], dict[str, object]]:
        plugin = root / "plugins" / PLUGIN_ID
        artifacts = plugin / ".xsec-market" / "artifacts"
        stable = self.archive(artifacts / "stable.xsec-plugin", "1.0.0")
        beta = self.archive(artifacts / "beta.xsec-plugin", "1.1.0", traversal=traversal)
        write_json(
            plugin / ".xsec-market" / "releases.json",
            {
                "schemaVersion": 2,
                "pluginId": PLUGIN_ID,
                "releases": [stable, beta],
                "channels": {
                    "beta": {"releaseId": beta["releaseId"]},
                    "stable": {"releaseId": stable["releaseId"]},
                },
            },
        )
        (plugin / ".xsec-market" / "releases.json.sig.jws.json").write_text("test-sidecar", encoding="utf-8")
        write_json(plugin / "plugin.json", self.manifest("1.1.0"))
        write_json(plugin / ".codex-plugin" / "plugin.json", {"name": PLUGIN_ID, "version": "1.1.0"})
        (plugin / "frontend.js").write_text("export function activate() {}\n", encoding="utf-8")
        # The history intentionally includes the Factory-only files that the
        # materializer must permanently remove before creating source branches.
        (plugin / ".xsec-market" / "old.sig.jws.json").write_text("signature", encoding="utf-8")
        (plugin / "legacy.xsec-plugin").write_text("artifact", encoding="utf-8")
        write_json(
            root / ".agents" / "plugins" / "marketplace.json",
            {
                "name": "xsec-official",
                "interface": {"displayName": "Test"},
                "plugins": [
                    {
                        "name": PLUGIN_ID,
                        "source": {"source": "local", "path": f"./plugins/{PLUGIN_ID}"},
                        "policy": {"installation": "INSTALLED_BY_DEFAULT", "authentication": "ON_INSTALL"},
                        "category": "Security",
                    }
                ],
            },
        )
        git(root, "init", "--quiet", "--initial-branch=main")
        git(root, "config", "user.name", "Factory Test")
        git(root, "config", "user.email", "factory-test@example.invalid")
        git(root, "remote", "add", "origin", materializer.TRUSTED_FACTORY_ORIGIN)
        git(root, "add", "--all")
        git(root, "commit", "--quiet", "-m", "feat: retain plugin source history")
        git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
        return stable, beta

    def test_materializes_exact_stable_and_beta_source_branches_with_filtered_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            output = Path(directory) / "source-repository"

            result = materializer.materialize_repository(factory, PLUGIN_ID, output)

            stable_manifest = json.loads(git(output, "show", f"main:plugins/{PLUGIN_ID}/plugin.json"))
            beta_manifest = json.loads(git(output, "show", f"beta:plugins/{PLUGIN_ID}/plugin.json"))
            self.assertEqual(stable_manifest["version"], "1.0.0")
            self.assertEqual(beta_manifest["version"], "1.1.0")
            self.assertEqual(git(output, "show", "main:README.md").splitlines()[0], f"# {PLUGIN_ID}")
            self.assertIn("plugins/com.xsec.workspace.sub-agent/plugin.json", git(output, "ls-tree", "-r", "--name-only", "beta"))
            history = git(output, "log", "--format=%s", "--all")
            self.assertIn("feat: retain plugin source history", history)
            source_paths = git(output, "rev-list", "--objects", "--all")
            self.assertNotIn(".xsec-market", source_paths)
            self.assertNotIn(".xsec-plugin", source_paths)
            self.assertNotIn(".sig.jws.json", source_paths)
            self.assertEqual(set(result), {"sourceCommits", "pendingAdoptionRegistry"})
            self.assertEqual(result["pendingAdoptionRegistry"]["status"], "pending-adoption")
            self.assertEqual(result["pendingAdoptionRegistry"]["source"]["repository"], "tzf1003/xsec-plugin-sub-agent")
            self.assertRegex(result["sourceCommits"]["stable"], r"^[a-f0-9]{40}$")

    def test_materialization_ignores_global_git_templates_and_seals_candidate_hooks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-template-") as directory:
            root = Path(directory)
            factory = root / "factory"
            factory.mkdir()
            self.make_factory(factory)
            template = root / "attacker-template"
            hook = template / "hooks" / "post-checkout"
            hook.parent.mkdir(parents=True)
            hook.write_text("#!/bin/sh\nprintf injected > template-hook-ran.txt\n", encoding="utf-8")
            hook.chmod(0o755)
            global_config = root / "attacker.gitconfig"
            global_config.write_text(f"[init]\n\ttemplateDir = {template.as_posix()}\n", encoding="utf-8")
            output = root / "source-repository"

            with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(global_config)}):
                materializer.materialize_repository(factory, PLUGIN_ID, output)

            self.assertEqual(git(output, "config", "--local", "--get", "core.hooksPath"), os.devnull)
            self.assertFalse((output / "template-hook-ran.txt").exists())
            self.assertNotIn("template-hook-ran.txt", git(output, "ls-tree", "-r", "--name-only", "main"))

    def test_exact_tree_guard_rejects_a_mutated_materialized_branch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-tree-guard-") as directory:
            root = Path(directory)
            factory = root / "factory"
            factory.mkdir()
            stable, _ = self.make_factory(factory)
            output = root / "source-repository"
            materializer.materialize_repository(factory, PLUGIN_ID, output)
            _, stable_artifact = materializer.selected_release_artifact(factory, PLUGIN_ID, "stable")
            git(output, "config", "user.name", "Tree Guard")
            git(output, "config", "user.email", "tree-guard@example.invalid")
            git(output, "checkout", "--quiet", "main")
            (output / "plugins" / PLUGIN_ID / "frontend.js").write_text("tampered\n", encoding="utf-8")
            git(output, "add", "--all")
            git(output, "commit", "--quiet", "-m", "tamper")

            with self.assertRaisesRegex(materializer.MaterializationError, "does not exactly match"):
                materializer.assert_materialized_branch_tree(output, "main", PLUGIN_ID, stable_artifact, stable)

    def test_cli_dry_run_prints_only_commits_and_pending_registry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-cli-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            output = StringIO()
            errors = StringIO()
            with patch.object(sys, "argv", [str(SCRIPTS / "materialize_first_party_source.py"), "--root", str(factory), "--plugin-id", PLUGIN_ID]), redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(materializer.main(), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(set(result), {"sourceCommits", "pendingAdoptionRegistry"})
            self.assertEqual(result["pendingAdoptionRegistry"]["status"], "pending-adoption")
            self.assertEqual(errors.getvalue(), "")

    def test_rejects_unsafe_artifact_member_before_extracting_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-traversal-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory, traversal=True)
            output = Path(directory) / "source-repository"

            with self.assertRaisesRegex(materializer.MaterializationError, "not safely extractable"):
                materializer.materialize_repository(factory, PLUGIN_ID, output)
            self.assertFalse((Path(directory) / "escape.txt").exists())
            self.assertFalse(output.exists())

    def test_push_target_is_closed_to_the_exact_first_party_mapping(self) -> None:
        expected = "https://github.com/tzf1003/xsec-plugin-sub-agent.git"
        self.assertEqual(len(materializer.FIRST_PARTY_APPROVED_SOURCES), 11)
        self.assertEqual(materializer.require_exact_target(PLUGIN_ID, expected), expected)
        with self.assertRaisesRegex(materializer.MaterializationError, "exact approved public GitHub repository"):
            materializer.require_exact_target(PLUGIN_ID, "https://github.com/tzf1003/xsec-plugin-approvals.git")
        script = (SCRIPTS / "materialize_first_party_source.py").read_text(encoding="utf-8")
        self.assertIn('"--atomic"', script)
        self.assertIn('"--credential-helper"', script)

    def test_push_credential_helper_is_optional_bounded_and_dispatch_only(self) -> None:
        self.assertIn("manager", materializer.PUSH_CREDENTIAL_HELPERS)
        self.assertNotIn("!arbitrary-command", materializer.PUSH_CREDENTIAL_HELPERS)
        with self.assertRaisesRegex(materializer.MaterializationError, "approved platform-provided helper"):
            materializer.sealed_transport_arguments(protocols=("https",), credential_helper="!arbitrary-command")
        with patch.object(
            sys,
            "argv",
            [str(SCRIPTS / "materialize_first_party_source.py"), "--plugin-id", PLUGIN_ID, "--credential-helper", "manager"],
        ):
            with redirect_stderr(StringIO()):
                self.assertEqual(materializer.main(), 2)

    def test_remote_factory_lookup_uses_an_isolated_sealed_transport(self) -> None:
        self.remote_main.stop()
        factory = Path(tempfile.gettempdir()) / "factory-with-local-url-rewrite"
        completed = subprocess.CompletedProcess(
            ["git"],
            0,
            stdout=(b"a" * 40) + b"\trefs/heads/main\n",
            stderr=b"",
        )
        with patch.dict(os.environ, {"GIT_DIR": "attacker-worktree", "GIT_SSH_COMMAND": "attacker-ssh"}):
            with patch.object(materializer, "run_git", return_value=completed) as invoke:
                self.assertEqual(materializer.trusted_factory_remote_main(factory), "a" * 40)
        arguments = invoke.call_args.args[0]
        kwargs = invoke.call_args.kwargs
        self.assertIn("ls-remote", arguments)
        self.assertIn(materializer.TRUSTED_FACTORY_ORIGIN, arguments)
        self.assertNotEqual(kwargs["cwd"], factory)
        self.assertEqual(kwargs["environment"]["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(kwargs["environment"]["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(kwargs["environment"]["GIT_ALLOW_PROTOCOL"], "https")
        self.assertEqual(kwargs["environment"]["GIT_CEILING_DIRECTORIES"], str(kwargs["cwd"].resolve()))
        self.assertNotIn("GIT_DIR", kwargs["environment"])
        self.assertNotIn("GIT_SSH_COMMAND", kwargs["environment"])

    def test_push_rejects_local_url_rewrite_before_remote_preflight(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-url-rewrite-") as directory:
            repository = Path(directory) / "candidate"
            git(Path(directory), "init", "--quiet", "--initial-branch=main", str(repository))
            git(repository, "config", "url.https://attacker.invalid/.insteadOf", "https://github.com/")
            with patch.object(materializer, "run_git") as invoke:
                with self.assertRaisesRegex(materializer.MaterializationError, "URL rewrite"):
                    materializer.push_candidate(
                        repository,
                        PLUGIN_ID,
                        "https://github.com/tzf1003/xsec-plugin-sub-agent.git",
                        "manager",
                    )
            invoke.assert_not_called()

    def test_push_rejects_local_http_proxy_ca_and_resolution_overrides_before_remote_preflight(self) -> None:
        overrides = {
            "http.proxy": "http://attacker.invalid:8080",
            "http.https://github.com.proxy": "http://attacker.invalid:8080",
            "http.sslCAInfo": "C:/attacker-ca.pem",
            "http.sslCAPath": "C:/attacker-ca-directory",
            "http.curloptResolve": "github.com:443:127.0.0.1",
        }
        for key, value in overrides.items():
            with self.subTest(key=key), tempfile.TemporaryDirectory(prefix="xsec-materializer-http-override-") as directory:
                repository = Path(directory) / "candidate"
                git(Path(directory), "init", "--quiet", "--initial-branch=main", str(repository))
                git(repository, "config", key, value)
                with patch.object(materializer, "run_git") as invoke:
                    with self.assertRaisesRegex(materializer.MaterializationError, "HTTP transport override"):
                        materializer.push_candidate(
                            repository,
                            PLUGIN_ID,
                            "https://github.com/tzf1003/xsec-plugin-sub-agent.git",
                            "manager",
                        )
                invoke.assert_not_called()

    def test_push_rejects_a_local_include_before_remote_preflight(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-include-") as directory:
            repository = Path(directory) / "candidate"
            git(Path(directory), "init", "--quiet", "--initial-branch=main", str(repository))
            git(repository, "config", "include.path", "C:/attacker.gitconfig")
            with patch.object(materializer, "run_git") as invoke:
                with self.assertRaisesRegex(materializer.MaterializationError, "Git include configuration"):
                    materializer.push_candidate(
                        repository,
                        PLUGIN_ID,
                        "https://github.com/tzf1003/xsec-plugin-sub-agent.git",
                        "manager",
                    )
            invoke.assert_not_called()

    def test_push_rejects_worktree_scoped_configuration_before_remote_preflight(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-worktree-config-") as directory:
            repository = Path(directory) / "candidate"
            git(Path(directory), "init", "--quiet", "--initial-branch=main", str(repository))
            git(repository, "config", "extensions.worktreeConfig", "true")
            # The extension causes an ordinary later push to read
            # ``.git/config.worktree``.  The materializer rejects the opt-in
            # before that extra candidate-controlled file can be consulted.
            (repository / ".git" / "config.worktree").write_text(
                "[http]\n\tproxy = http://attacker.invalid:8080\n",
                encoding="utf-8",
            )
            with patch.object(materializer, "run_git") as invoke:
                with self.assertRaisesRegex(materializer.MaterializationError, "worktree-specific configuration"):
                    materializer.push_candidate(
                        repository,
                        PLUGIN_ID,
                        "https://github.com/tzf1003/xsec-plugin-sub-agent.git",
                        "manager",
                    )
            invoke.assert_not_called()

    def test_push_rejects_a_local_fsmonitor_before_remote_preflight(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-fsmonitor-") as directory:
            repository = Path(directory) / "candidate"
            git(Path(directory), "init", "--quiet", "--initial-branch=main", str(repository))
            git(repository, "config", "core.fsmonitor", "C:/attacker-fsmonitor.exe")
            with patch.object(materializer, "run_git") as invoke:
                with self.assertRaisesRegex(materializer.MaterializationError, "fsmonitor configuration"):
                    materializer.push_candidate(
                        repository,
                        PLUGIN_ID,
                        "https://github.com/tzf1003/xsec-plugin-sub-agent.git",
                        "manager",
                    )
            invoke.assert_not_called()

    def test_manager_helper_uses_an_absolute_binary_from_the_trusted_git_install(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-credential-manager-") as directory:
            install = Path(directory) / "git-install"
            exec_path = install / "mingw64" / "libexec" / "git-core"
            manager = install / "mingw64" / "bin" / "git-credential-manager.exe"
            exec_path.mkdir(parents=True)
            manager.parent.mkdir(parents=True)
            manager.write_bytes(b"platform helper")
            # Keep the production boundary strict: non-Windows hosts must
            # require a runnable helper even when this fixture models the
            # Windows Git-for-Windows layout.
            if os.name != "nt":
                manager.chmod(manager.stat().st_mode | 0o111)
            completed = subprocess.CompletedProcess(
                ["git", "--exec-path"],
                0,
                stdout=(str(exec_path) + "\n").encode("utf-8"),
                stderr=b"",
            )
            with patch.dict(os.environ, {"PATH": "C:/attacker-bin"}):
                with patch.object(materializer, "run_git", return_value=completed) as invoke:
                    arguments = materializer.sealed_transport_arguments(protocols=("https",), credential_helper="manager")
            helper_values = [value for option, value in zip(arguments, arguments[1:]) if option == "-c" and value.startswith("credential.helper=!")]
            self.assertEqual(helper_values, [f"credential.helper=!{materializer.shlex.quote(manager.resolve().as_posix())}"])
            self.assertNotIn("credential.helper=manager", arguments)
            self.assertEqual(invoke.call_args.args[0], ["--exec-path"])
            environment = invoke.call_args.kwargs["environment"]
            self.assertNotIn("GIT_EXEC_PATH", environment)

    def test_candidate_git_checks_disable_fsmonitor(self) -> None:
        arguments = materializer.candidate_git_arguments(["status", "--porcelain"])
        self.assertIn("core.fsmonitor=false", arguments)

    def test_push_revalidates_transport_configuration_after_status_and_before_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-revalidate-") as directory:
            repository = Path(directory) / "candidate"
            git(Path(directory), "init", "--quiet", "--initial-branch=main", str(repository))
            events: list[str] = []

            def fake_candidate_stdout(arguments: list[str], **kwargs: object) -> str:
                if arguments[:2] == ["status", "--porcelain"]:
                    events.append("status")
                return ""

            def fake_transport_assertion(candidate: Path) -> None:
                self.assertEqual(candidate, repository)
                events.append("assert-transport")

            def fake_git(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                if "push" in arguments:
                    events.append("push")
                return subprocess.CompletedProcess(["git", *arguments], 0, stdout=b"", stderr=b"")

            with patch.object(materializer, "assert_no_local_url_rewrites", side_effect=fake_transport_assertion):
                with patch.object(materializer, "git_stdout", return_value=os.devnull):
                    with patch.object(materializer, "candidate_git_stdout", side_effect=fake_candidate_stdout):
                        with patch.object(materializer, "resolve_approved_credential_helper", return_value="!/trusted/manager"):
                            with patch.object(materializer, "run_git", side_effect=fake_git):
                                materializer.push_candidate(
                                    repository,
                                    PLUGIN_ID,
                                    "https://github.com/tzf1003/xsec-plugin-sub-agent.git",
                                    "manager",
                                )
            self.assertEqual(events, ["assert-transport", "status", "assert-transport", "assert-transport", "push"])

    def test_push_rejects_a_candidate_without_the_materializer_hook_seal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-missing-hook-seal-") as directory:
            repository = Path(directory) / "candidate"
            git(Path(directory), "init", "--quiet", "--initial-branch=main", str(repository))
            with self.assertRaisesRegex(materializer.MaterializationError, "disabled local Git hook path"):
                materializer.push_candidate(
                    repository,
                    PLUGIN_ID,
                    "https://github.com/tzf1003/xsec-plugin-sub-agent.git",
                )

    def test_push_preflight_and_write_seal_global_url_rewrite_configuration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-sealed-push-") as directory:
            repository = Path(directory) / "candidate"
            git(Path(directory), "init", "--quiet", "--initial-branch=main", str(repository))
            git(repository, "config", "core.hooksPath", os.devnull)
            calls: list[tuple[list[str], dict[str, object]]] = []

            def fake_git(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                calls.append((arguments, kwargs))
                stdout = f"{os.devnull}\n".encode("utf-8") if arguments[-1:] == ["core.hooksPath"] else b""
                return subprocess.CompletedProcess(["git", *arguments], 0, stdout=stdout, stderr=b"")

            with patch.dict(
                os.environ,
                {
                    "GIT_CONFIG": "injected",
                    "HTTPS_PROXY": "https://attacker.invalid",
                    "GIT_TRACE_CURL": "1",
                    "GIT_TRACE_REDACT": "0",
                    "GIT_EXEC_PATH": "C:/attacker-git-exec-path",
                    "GIT_SSL_CAINFO": "C:/attacker-ca.pem",
                    "GIT_SSL_CAPATH": "C:/attacker-ca-directory",
                },
            ):
                with patch.object(materializer, "resolve_approved_credential_helper", return_value="!/trusted/git-credential-manager"):
                    with patch.object(materializer, "run_git", side_effect=fake_git):
                        materializer.push_candidate(
                            repository,
                            PLUGIN_ID,
                            "https://github.com/tzf1003/xsec-plugin-sub-agent.git",
                            "manager",
                        )
            remote_calls = [(arguments, kwargs) for arguments, kwargs in calls if "ls-remote" in arguments or "push" in arguments]
            self.assertEqual(len(remote_calls), 2)
            preflight_arguments, preflight_kwargs = remote_calls[0]
            push_arguments, push_kwargs = remote_calls[1]
            self.assertIn("ls-remote", preflight_arguments)
            self.assertNotEqual(preflight_kwargs["cwd"], repository)
            self.assertIn("push", push_arguments)
            self.assertEqual(push_kwargs["cwd"], repository)
            self.assertIn("credential.helper=", preflight_arguments)
            self.assertLess(push_arguments.index("credential.helper="), push_arguments.index("credential.helper=!/trusted/git-credential-manager"))
            for _, kwargs in calls:
                environment = kwargs["environment"]
                assert isinstance(environment, dict)
                self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
                self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
                self.assertNotIn("GIT_CONFIG", environment)
                self.assertNotIn("HTTPS_PROXY", environment)
                self.assertNotIn("GIT_TRACE_CURL", environment)
                self.assertNotIn("GIT_TRACE_REDACT", environment)
                self.assertNotIn("GIT_EXEC_PATH", environment)
                self.assertNotIn("GIT_SSL_CAINFO", environment)
                self.assertNotIn("GIT_SSL_CAPATH", environment)

    def test_ssh_target_uses_a_safe_openssh_command_without_user_host_rewrites(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-sealed-ssh-") as directory:
            repository = Path(directory) / "candidate"
            git(Path(directory), "init", "--quiet", "--initial-branch=main", str(repository))
            git(repository, "config", "core.hooksPath", os.devnull)
            calls: list[tuple[list[str], dict[str, object]]] = []

            def fake_git(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                calls.append((arguments, kwargs))
                stdout = f"{os.devnull}\n".encode("utf-8") if arguments[-1:] == ["core.hooksPath"] else b""
                return subprocess.CompletedProcess(["git", *arguments], 0, stdout=stdout, stderr=b"")

            with patch.dict(os.environ, {"GIT_SSH_COMMAND": "ssh -F attacker-config"}):
                with patch.object(materializer, "run_git", side_effect=fake_git):
                    materializer.push_candidate(
                        repository,
                        PLUGIN_ID,
                        "git@github.com:tzf1003/xsec-plugin-sub-agent.git",
                    )
            remote_calls = [(arguments, kwargs) for arguments, kwargs in calls if "ls-remote" in arguments or "push" in arguments]
            self.assertEqual(len(remote_calls), 2)
            for _, kwargs in remote_calls:
                environment = kwargs["environment"]
                assert isinstance(environment, dict)
                command = environment["GIT_SSH_COMMAND"]
                self.assertNotIn("attacker-config", command)
                self.assertIn(f"-F {os.devnull}", command)
                self.assertIn("Hostname=github.com", command)
                self.assertIn("ProxyCommand=none", command)
                self.assertIn("ProxyJump=none", command)
                self.assertIn("StrictHostKeyChecking=yes", command)
                self.assertEqual(environment["GIT_SSH_VARIANT"], "ssh")

    def test_rejects_an_artifact_that_no_longer_matches_the_retained_sha256(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-digest-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            _, beta = self.make_factory(factory)
            artifact = factory / "plugins" / PLUGIN_ID / ".xsec-market" / beta["artifacts"][0]["url"]
            artifact.write_bytes(artifact.read_bytes() + b"changed")

            with self.assertRaisesRegex(materializer.MaterializationError, "SHA-256 does not match"):
                materializer.selected_release_artifact(factory, PLUGIN_ID, "beta")

    def test_filter_index_removes_factory_only_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-index-") as directory:
            root = Path(directory)
            plugin = root / "plugins" / PLUGIN_ID
            (plugin / ".xsec-market").mkdir(parents=True)
            (plugin / ".xsec-market" / "release.sig.jws.json").write_text("signature", encoding="utf-8")
            (plugin / "old.xsec-plugin").write_text("artifact", encoding="utf-8")
            (plugin / "frontend.js").write_text("source", encoding="utf-8")
            git(root, "init", "--quiet", "--initial-branch=main")
            git(root, "config", "user.name", "Factory Test")
            git(root, "config", "user.email", "factory-test@example.invalid")
            git(root, "add", "--all")
            git(root, "commit", "--quiet", "-m", "test")
            previous = Path.cwd()
            os.chdir(root)
            try:
                materializer.filter_index_paths(PLUGIN_ID)
            finally:
                os.chdir(previous)
            self.assertEqual(git(root, "ls-files"), f"plugins/{PLUGIN_ID}/frontend.js")

    def test_rejects_dirty_or_non_main_factory_input_before_reading_release_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-trusted-main-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            (factory / "untrusted.txt").write_text("dirty", encoding="utf-8")
            with self.assertRaisesRegex(materializer.MaterializationError, "clean trusted Factory main"):
                materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")
            (factory / "untrusted.txt").unlink()
            git(factory, "checkout", "--quiet", "-b", "untrusted")
            (factory / "untrusted.txt").write_text("different commit", encoding="utf-8")
            git(factory, "add", "untrusted.txt")
            git(factory, "commit", "--quiet", "-m", "untrusted local main lookalike")
            with self.assertRaisesRegex(materializer.MaterializationError, "trusted Factory.*main commit"):
                materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")

    def test_rejects_a_clean_clone_with_an_untrusted_factory_origin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-untrusted-origin-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            git(factory, "remote", "set-url", "origin", "https://github.com/attacker/xsec-plugins.git")
            with self.assertRaisesRegex(materializer.MaterializationError, "canonical trusted xsec-plugins"):
                materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")

    def test_rejects_a_clean_factory_checkout_when_cached_origin_main_is_stale(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-stale-remote-main-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            with patch.object(materializer, "trusted_factory_remote_main", return_value="b" * 40):
                with self.assertRaisesRegex(materializer.MaterializationError, "current trusted Factory remote main"):
                    materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")
            script = (SCRIPTS / "materialize_first_party_source.py").read_text(encoding="utf-8")
            self.assertIn('"ls-remote"', script)
            self.assertIn("TRUSTED_FACTORY_ORIGIN", script)

    def test_rejects_factory_replacement_refs_and_shallow_history_before_export(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-replace-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            head = git(factory, "rev-parse", "HEAD")
            git(factory, "update-ref", f"refs/replace/{head}", head)
            with self.assertRaisesRegex(materializer.MaterializationError, "replacement refs"):
                materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")

        with tempfile.TemporaryDirectory(prefix="xsec-materializer-shallow-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            head = git(factory, "rev-parse", "HEAD")
            (factory / ".git" / "shallow").write_text(head + "\n", encoding="utf-8")
            with self.assertRaisesRegex(materializer.MaterializationError, "non-shallow"):
                materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")
            script = (SCRIPTS / "materialize_first_party_source.py").read_text(encoding="utf-8")
            self.assertIn("GIT_NO_REPLACE_OBJECTS", script)
            self.assertIn('"--no-replace-objects"', script)

    def test_rejects_a_retained_release_index_without_a_valid_kms_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-unverified-release-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            with patch.object(
                materializer,
                "verify_historical_sidecar_signature",
                side_effect=materializer.MarketplaceKmsPublisherError("signature mismatch"),
            ):
                with self.assertRaisesRegex(materializer.MaterializationError, "retained release KMS sidecar is invalid"):
                    materializer.materialize_repository(factory, PLUGIN_ID, Path(directory) / "source-repository")

    def test_retained_signature_uses_the_trusted_git_blob_not_windows_eol_checkout_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-eol-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            self.make_factory(factory)
            relative = f"plugins/{PLUGIN_ID}/.xsec-market/releases.json"
            blob = subprocess.run(
                ["git", "cat-file", "blob", f"HEAD:{relative}"],
                cwd=str(factory),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout
            release_path = factory / relative
            release_path.write_bytes(blob.replace(b"\n", b"\r\n"))
            self.assertNotEqual(release_path.read_bytes(), blob)
            verified_documents: list[bytes] = []
            materializer.verify_historical_sidecar_signature.side_effect = (
                lambda _sidecar, document: verified_documents.append(document.path.read_bytes()) or "a" * 40
            )

            materializer.verify_retained_release_signature(factory, PLUGIN_ID)

            self.assertEqual(verified_documents, [blob])

    def test_release_selection_consumes_the_authenticated_blob_after_worktree_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-materializer-authenticated-release-") as directory:
            factory = Path(directory) / "factory"
            factory.mkdir()
            stable, beta = self.make_factory(factory)
            authenticated = materializer.verify_retained_release_signature(factory, PLUGIN_ID)
            release_path = factory / "plugins" / PLUGIN_ID / ".xsec-market" / "releases.json"
            mutated = json.loads(release_path.read_text(encoding="utf-8"))
            mutated["channels"]["stable"]["releaseId"] = beta["releaseId"]
            write_json(release_path, mutated)

            record, _ = materializer.selected_release_artifact(
                factory,
                PLUGIN_ID,
                "stable",
                release_document=authenticated,
            )

            self.assertEqual(record["releaseId"], stable["releaseId"])


if __name__ == "__main__":
    unittest.main()
