import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pythonCommand = process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
const snapshotPath = (pluginId) => join(root, ".xsec-factory", "snapshots", pluginId);

async function loadFrontend(pluginId) {
  const path = join(snapshotPath(pluginId), "com.xsec.desktop", "frontend", "index.js");
  const source = await readFile(path, "utf8");
  const module = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
  return { module, source };
}

async function manifest(pluginId) {
  return JSON.parse(await readFile(join(snapshotPath(pluginId), "plugin.json"), "utf8"));
}

test("attack-path frontend exposes the reviewed attack-path and subagent contract", async () => {
  const { module, source } = await loadFrontend("com.xsec.attack-path");
  const attackPath = await manifest("com.xsec.attack-path");
  const methods = attackPath.extensions["com.xsec.desktop"].frontendApi.methods;
  assert.equal(typeof module.activate, "function");
  assert.match(source, /function layoutTreeNodes\(/);
  assert.match(source, /function graphModel\(/);
  assert.match(source, /xsec\.attack-path\.tree\.list/);
  assert.match(source, /xsec\.attack-path\.subagents\.list/);
  assert.match(source, /xsec\.workspace\.tool\.open/);
  assert.match(source, /(?:SUBAGENT_PLUGIN_ID\s*=\s*|pluginId:\s*)"com\.xsec\.workspace\.sub-agent"/);
  assert.match(source, /(?:SUBAGENT_DETAIL_TOOL_ID\s*=\s*|toolId:\s*)"subagent-detail"/);
  if (methods["xsec.attack-path.operations.list"]) {
    assert.ok(methods["xsec.attack-path.operations.resume"]);
    assert.match(source, /xsec\.attack-path\.operations\.list/);
    assert.match(source, /xsec\.attack-path\.operations\.resume/);
  }
  assert.doesNotMatch(source, /compatibility bridge|兼容渲染器/);
});

test("subagent frontend owns observer ordering and duration formatting", async () => {
  const { module, source } = await loadFrontend("com.xsec.workspace.sub-agent");
  const sorted = module.sortObservers([
    { id: "done", status: "done", updated_at: 3 },
    { id: "running", status: "running", updated_at: 1 },
    { id: "failed", status: "failed", updated_at: 2 },
  ]);

  assert.deepEqual(sorted.map((row) => row.id), ["running", "failed", "done"]);
  assert.equal(module.formatDuration(1_000, 1_125), "2 分 5 秒");
  assert.equal(module.isTerminalStatus("dispatched"), false);
  assert.equal(module.isTerminalStatus("done"), true);
  assert.match(source, /xsec\.subagents\.get/);
  assert.doesNotMatch(source, /compatibility bridge|兼容渲染器/);
});

test("retained manifests express the attack-path to subagent plugin relationship", async () => {
  const attackPath = await manifest("com.xsec.attack-path");
  const subagent = await manifest("com.xsec.workspace.sub-agent");
  const attackExtension = attackPath.extensions["com.xsec.desktop"];
  const subagentExtension = subagent.extensions["com.xsec.desktop"];

  assert.equal(attackExtension.dependencies.required["com.xsec.workspace.sub-agent"], "^1.2.3");
  assert.equal(attackExtension.engines.pluginApi, "^1.3.0");
  assert.equal(subagentExtension.engines.pluginApi, "^1.3.0");
  assert.ok(attackExtension.permissions["workspace.tool.open"]);
  assert.equal(attackExtension.frontendApi.methods["xsec.workspace.tool.open"].capability, "workspace.tool.open");
  assert.equal(attackExtension.frontendApi.methods["xsec.workspace.tool.open"].binding, "context");
  assert.ok(subagentExtension.permissions["workspace.tool.open"]);
  assert.equal(subagentExtension.frontendApi.methods["xsec.workspace.tool.open"].capability, "workspace.tool.open");
  assert.equal(subagentExtension.contributes.workspaceTools["sub-agent"].launchable, false);
  assert.equal(subagentExtension.contributes.workspaceTools["subagent-detail"].launchable, false);
});

test("marketplace bootstrap preserves every package-owned frontend", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "xsec-plugin-bootstrap-"));
  try {
    const marketplaceRoot = join(temporaryRoot, "marketplace");
    const desktopRoot = join(temporaryRoot, "desktop-plugins");
    await mkdir(join(marketplaceRoot, "scripts"), { recursive: true });
    await mkdir(join(marketplaceRoot, ".xsec-factory"), { recursive: true });
    await cp(join(root, "scripts", "bootstrap_plugins.py"), join(marketplaceRoot, "scripts", "bootstrap_plugins.py"));
    await cp(join(root, "scripts", "build_market.py"), join(marketplaceRoot, "scripts", "build_market.py"));
    await cp(join(root, "scripts", "native_sidecars.py"), join(marketplaceRoot, "scripts", "native_sidecars.py"));
    await cp(join(root, "scripts", "marketplace_contract.py"), join(marketplaceRoot, "scripts", "marketplace_contract.py"));
    await cp(join(root, ".xsec-factory", "official-registry.json"), join(marketplaceRoot, ".xsec-factory", "official-registry.json"));
    const marketplace = JSON.parse(await readFile(join(root, ".agents", "plugins", "marketplace.json"), "utf8"));
    for (const entry of marketplace.plugins) {
      const pluginId = entry.name;
      await mkdir(join(desktopRoot, pluginId), { recursive: true });
      await cp(join(snapshotPath(pluginId), "plugin.json"), join(desktopRoot, pluginId, "plugin.json"));
    }
    const sentinels = new Map([
      ["com.xsec.attack-path", "// attack-path package frontend sentinel\n"],
      ["com.xsec.workspace.sub-agent", "// sub-agent package frontend sentinel\n"],
    ]);
    const packageFrontends = new Map(marketplace.plugins.map(({ name }) => [name, `// ${name} package frontend sentinel\n`]));
    for (const [pluginId, sentinel] of sentinels) packageFrontends.set(pluginId, sentinel);
    for (const [pluginId, sentinel] of packageFrontends) {
      const frontend = join(marketplaceRoot, ".xsec-factory", "snapshots", pluginId, "com.xsec.desktop", "frontend", "index.js");
      await mkdir(dirname(frontend), { recursive: true });
      await writeFile(frontend, sentinel, "utf8");
    }

    const result = spawnSync(pythonCommand, [join(marketplaceRoot, "scripts", "bootstrap_plugins.py"), desktopRoot], {
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    for (const [pluginId, sentinel] of sentinels) {
      assert.equal(
          await readFile(join(marketplaceRoot, ".xsec-factory", "snapshots", pluginId, "com.xsec.desktop", "frontend", "index.js"), "utf8"),
          sentinel,
      );
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});
