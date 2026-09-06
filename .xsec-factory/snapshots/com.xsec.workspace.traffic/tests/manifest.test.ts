import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { test } from "node:test";

const manifestPath = "plugin.json";
const frontendPath = "com.xsec.desktop/frontend/index.js";
const packagePath = "package.json";
const catalogManifestPath = ".codex-plugin/plugin.json";
const sourcePreflightPath = ".github/workflows/ci.yml";

/** Verify the Traffic manifest's capability and RPC declarations. */
async function verifyManifestCapabilities(): Promise<void> {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const extension = manifest.extensions["com.xsec.desktop"];
  assert.equal(manifest.version, "2.1.1");
  assert.equal(extension.schemaVersion, 2);
  const sourcePackage = JSON.parse(await readFile(packagePath, "utf8"));
  const catalogManifest = JSON.parse(await readFile(catalogManifestPath, "utf8"));
  assert.equal(sourcePackage.version, manifest.version);
  assert.equal(catalogManifest.name, manifest.name);
  assert.equal(catalogManifest.version, manifest.version);
  assert.equal(extension.engines.pluginApi, "^1.5.0");
  assert.match(await readFile(sourcePreflightPath, "utf8"), /engines\.pluginApi !== "\^1\.5\.0"/u);
  assert.deepEqual(Object.keys(extension.permissions).sort(), ["pluginData.read", "pluginData.write", "workspace.composer.write", "workspace.session.read", "workspace.session.write", "workspace.tool.open"]);
  assert.deepEqual(extension.frontendApi.methods["xsec.traffic.replay"], { capability: "workspace.session.write", binding: "session" });
  assert.deepEqual(extension.frontendApi.methods["xsec.traffic.payload.open"], { capability: "workspace.session.read", binding: "session" });
  assert.deepEqual(extension.frontendApi.methods["xsec.traffic.reference.add"], { capability: "workspace.composer.write", binding: "session" });
  assert.deepEqual(extension.frontendApi.methods["xsec.workspace.tool.open"], { capability: "workspace.tool.open", binding: "context" });
  assert.equal(extension.contributes.agentTools, undefined);
}

/** Verify every restored Traffic surface remains contributed and activated. */
async function verifyManifestContributions(): Promise<void> {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const extension = manifest.extensions["com.xsec.desktop"];
  assert.deepEqual(extension.activationEvents.sort(), [
    "onSettingsPage:traffic",
    "onWorkspaceTool:request-detail",
    "onWorkspaceTool:traffic",
    "onWorkspaceTool:traffic-replay",
  ]);
  assert.deepEqual(Object.keys(extension.contributes.workspaceTools).sort(), [
    "request-detail", "traffic", "traffic-replay",
  ]);
  assert.equal(extension.contributes.workspaceTools.traffic.scope, "session");
  assert.equal(extension.contributes.workspaceTools.traffic.launchable, true);
  assert.equal(extension.contributes.workspaceTools["traffic-replay"].scope, "entity");
  assert.equal(extension.contributes.workspaceTools["traffic-replay"].launchable, false);
  assert.equal(extension.contributes.workspaceTools["request-detail"].scope, "entity");
  assert.deepEqual(Object.keys(extension.contributes.settingsPages), ["traffic"]);
}

test("manifest grants only the capabilities required by the restored workbench", verifyManifestCapabilities);
test("manifest activates every restored surface through plugin contributions", verifyManifestContributions);

/** Verify the generated frontend module and its delegated lifecycle contract. */
async function verifyGeneratedFrontend(): Promise<void> {
  const source = await readFile(frontendPath, "utf8");
  assert.match(source, /export\s+function\s+activate\s*\(\s*host\s*\)/u);
  for (const annotation of [
    "@param {object} host",
    "@param {Element} root",
    "@param {object} context",
    "@returns {object}",
    "@returns {void}",
  ]) {
    assert.match(source, new RegExp(annotation.replace(/[{}]/gu, "\\$&"), "u"));
  }
  for (const method of ["mount", "update", "dispose"]) {
    assert.match(source, new RegExp(`${method}\\([^)]*\\)\\{return controller\\.${method}\\(`, "u"));
  }
  assert.equal(/\bfetch\s*\(/u.test(source), false);
  assert.equal(/https?:\/\/(?!www\.w3\.org)/u.test(source), false);
  for (const event of [
    "traffic.frontend.activate",
    "traffic.frontend.mount",
    "traffic.frontend.dispose",
    "traffic.replay",
    "traffic.payload.open",
    "traffic.settings.ca.rotate",
  ]) assert.equal(source.includes(event), true, `missing development log event: ${event}`);
  assert.equal(source.includes(".started"), true);
  assert.equal(source.includes(".completed"), true);
  assert.equal(source.includes(".failed"), true);
  for (const message of [
    "读取默认筛选失败",
    "读取 MITM CA 状态失败",
    "读取被动规则失败",
  ]) assert.equal(source.includes(message), true, `missing UTF-8 error boundary: ${message}`);
  const module = await import(`${pathToFileURL(frontendPath).href}?test=${Date.now()}`);
  assert.deepEqual(Object.keys(module), ["activate"]);
  assert.equal(typeof module.activate, "function");
  const controller = module.activate({
    apiVersion: 2,
    context: { kind: "settings-page", settings: { id: "traffic", page: "traffic" } },
  });
  assert.equal(typeof controller.mount, "function");
  assert.equal(typeof controller.update, "function");
  assert.equal(typeof controller.dispose, "function");
}

test("generated frontend is a loadable self-contained ESM controller", verifyGeneratedFrontend);
