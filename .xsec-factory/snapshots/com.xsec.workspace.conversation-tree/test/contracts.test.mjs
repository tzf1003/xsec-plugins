import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const pluginRoot = new URL("../", import.meta.url);
const manifest = JSON.parse(await readFile(new URL("plugin.json", pluginRoot), "utf8"));
const codexManifest = JSON.parse(await readFile(new URL(".codex-plugin/plugin.json", pluginRoot), "utf8"));

test("dual manifests identify the same 1.3.4 release", () => {
  assert.equal(manifest.name, codexManifest.name);
  assert.equal(manifest.version, codexManifest.version);
  assert.equal(manifest.version, "1.3.4");
});

test("manifest commits a v2 single-esm frontend with exact tree methods", () => {
  const desktop = manifest.extensions["com.xsec.desktop"];
  assert.equal(desktop.frontendApi.version, 2);
  assert.equal(desktop.frontendApi.module, "single-esm");
  assert.deepEqual(Object.keys(desktop.frontendApi.methods).sort(), [
    "xsec.conversation-tree.navigate",
    "xsec.conversation-tree.read",
  ]);
  assert.equal(desktop.entrypoints.frontend, "./com.xsec.desktop/frontend/index.js");
});

test("committed frontend exports an explicit lifecycle contract", async () => {
  const source = await readFile(new URL("com.xsec.desktop/frontend/index.js", pluginRoot), "utf8");
  assert.doesNotMatch(source, /\bfrom\s+["']/);
  assert.match(source, /export\s+function\s+activate\s*\(\s*host\s*\)/);
  assert.match(source, /return\s*\{\s*mount\s*\([^)]*\)\s*\{/);
  assert.match(source, /update\s*\([^)]*\)\s*\{/);
  assert.match(source, /dispose\s*\(\s*\)\s*\{/);

  const frontend = await import(new URL("com.xsec.desktop/frontend/index.js", pluginRoot));
  assert.equal(typeof frontend.activate, "function");
});

test("theme updates remain optional at the host boundary", async () => {
  const controller = await readFile(new URL("../src/controller.js", import.meta.url), "utf8");
  const frontend = await readFile(new URL("com.xsec.desktop/frontend/index.js", pluginRoot), "utf8");

  assert.match(controller, /this\.host\.onTheme\?\.\(/);
  assert.match(frontend, /this\.host\.onTheme\?\.\(/);
});
