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

const treeNode = (id, parentId, extra = {}) => ({
  id,
  parent_id: parentId,
  title: id,
  kind: "task",
  status: "pending",
  subagent_id: null,
  ...extra,
});

test("attack-path frontend owns the disconnected-tree layout", async () => {
  const { module, source } = await loadFrontend("com.xsec.attack-path");
  const layout = module.layoutTreeNodes([
    treeNode("root-a", null),
    treeNode("child-a", "root-a"),
    treeNode("root-b", null),
    treeNode("child-b", "root-b"),
    treeNode("orphan", "missing"),
  ], "root-a");

  assert.equal(layout.positions.size, 5);
  assert.ok(layout.positions.get("root-a").x < layout.positions.get("root-b").x);
  assert.notDeepEqual(layout.positions.get("orphan"), layout.positions.get("root-b"));
  assert.match(source, /xsec\.attack-path\.tree\.list/);
  assert.doesNotMatch(source, /compatibility bridge|兼容渲染器/);
});

test("attack-path graph connects a node to its subagent plugin entity", async () => {
  const { module, source } = await loadFrontend("com.xsec.attack-path");
  const nodes = [
    treeNode("root", null),
    treeNode("node-1", "root", { subagent_id: "subagent-1" }),
  ];
  const model = module.graphModel(nodes, [{ id: "subagent-1", node_id: "node-1", status: "running" }]);

  assert.equal(model.subagentsByNode.get("node-1").id, "subagent-1");
  assert.equal(model.counts.task, 1);
  assert.match(source, /pluginId:\s*"com\.xsec\.workspace\.sub-agent"/);
  assert.match(source, /toolId:\s*"subagent-detail"/);
});

test("attack-path graph prefers a node's explicit subagent over retry fallbacks", async () => {
  const { module } = await loadFrontend("com.xsec.attack-path");
  const node = treeNode("node-1", "root", { subagent_id: "attempt-2" });
  const model = module.graphModel([treeNode("root", null), node], [
    { id: "attempt-1", node_id: "node-1", status: "failed" },
    { id: "attempt-2", node_id: "node-1", status: "running" },
  ]);

  assert.equal(model.subagentsByNode.get("node-1").id, "attempt-2");
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

test("manifests express the attack-path to subagent plugin relationship", async () => {
  const attackPath = await manifest("com.xsec.attack-path");
  const subagent = await manifest("com.xsec.workspace.sub-agent");
  const attackExtension = attackPath.extensions["com.xsec.desktop"];
  const subagentExtension = subagent.extensions["com.xsec.desktop"];

  assert.equal(attackExtension.dependencies.required["com.xsec.workspace.sub-agent"], "^2.0.0");
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
