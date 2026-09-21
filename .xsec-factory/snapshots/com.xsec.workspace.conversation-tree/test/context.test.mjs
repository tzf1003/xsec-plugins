import assert from "node:assert/strict";
import test from "node:test";
import { inspectorContextResult, navigationBlock, parseContext, parseMountContext, supportsTreeSnapshot } from "../src/context.js";
import { context, message, tree } from "./fixtures.mjs";

const projection = tree([
  message("root", { active: true }),
  message("leaf", { parentId: "root", active: true }),
], { activeLeafId: "leaf" });

test("cached context is the authoritative tree and hash source", () => {
  const parsed = parseContext(context(projection));
  assert.equal(parsed.tree.activeLeafId, "leaf");
  assert.equal(parsed.treeHash, "hash-1");
  assert.equal(navigationBlock(parsed, parsed.tree, parsed.treeHash), null);
});

test("navigation fails closed without the authoritative hash", () => {
  const parsed = parseContext(context(projection));
  assert.match(navigationBlock(parsed, parsed.tree, null), /权威树摘要/);
});

test("busy, unsynchronized and hidden sessions block navigation", () => {
  const busy = parseContext(context(projection, { status: "running" }));
  assert.match(navigationBlock(busy, busy.tree, busy.treeHash), /运行中/);
  const pending = parseContext(context(projection, { consistency: "verification_pending" }));
  assert.match(navigationBlock(pending, pending.tree, pending.treeHash), /尚未同步/);
  const missingConsistency = context(projection);
  delete missingConsistency.workspace.session.consistency;
  const unknown = parseContext(missingConsistency);
  assert.match(navigationBlock(unknown, unknown.tree, unknown.treeHash), /尚未同步/);
  const hidden = parseContext(context(projection, { visible: false }));
  assert.match(navigationBlock(hidden, hidden.tree, hidden.treeHash), /不可见/);
  const interaction = parseContext(context(projection, { pendingInteractions: { approval: {} } }));
  assert.match(navigationBlock(interaction, interaction.tree, interaction.treeHash), /待处理交互/);
});

test("navigation capability must be the explicit boolean true", () => {
  const malformed = context(projection);
  malformed.workspace.session.tree_capability.navigate = "false";
  const parsed = parseContext(malformed);
  assert.match(navigationBlock(parsed, parsed.tree, parsed.treeHash), /不支持分支切换/);
});

test("malformed pending-interaction containers block navigation", () => {
  for (const pending of [false, 0, []]) {
    const malformed = context(projection);
    malformed.workspace.session.pending_interactions = pending;
    const parsed = parseContext(malformed);
    assert.match(navigationBlock(parsed, parsed.tree, parsed.treeHash), /状态无效/);
  }
});

test("visibility and truncation flags must be booleans when present", () => {
  assert.throws(() => parseContext({ ...context(projection), visible: "false" }), /invalid_visible/);
  assert.throws(() => parseContext({ ...context(projection), truncated: "true" }), /invalid_truncated/);
  const mounted = parseMountContext({ ...context(projection), visible: "false" });
  assert.equal(mounted.visible, false);
  assert.match(mounted.error, /invalid_visible/);
});

test("snapshot capability explicitly blocks tree reads", () => {
  assert.equal(supportsTreeSnapshot(parseContext(context(projection, { snapshot: false }))), false);
});

test("truncated context remains explicit and contains no navigation hash", () => {
  const parsed = parseContext({ truncated: true, reason: "host context exceeds sandbox message limit", workspace: {} });
  assert.equal(parsed.truncated, true);
  assert.equal(parsed.tree, null);
  assert.equal(parsed.treeHash, null);
});

test("truncated context blocks navigation even when authority fields survived", () => {
  const retained = { ...context(projection), truncated: true };
  const parsed = parseContext(retained);
  assert.equal(parsed.treeHash, "hash-1");
  assert.match(navigationBlock(parsed, parsed.tree, parsed.treeHash), /上下文已截断/);
});

test("malformed mount context becomes an explicit disabled state", () => {
  const parsed = parseMountContext({ workspace: [] });
  assert.equal(parsed.visible, false);
  assert.match(parsed.error, /读取宿主上下文失败/);
});

test("malformed inspector metadata stays inside the inspector error boundary", () => {
  const selected = message("root");
  const session = {
    messages: [{ entry_id: "root", content: { parts: [{ kind: "reference", reference: { kind: "unknown" } }] } }],
  };
  const result = inspectorContextResult(session, [selected]);
  assert.equal(result.status, "error");
  assert.match(result.message, /unknown_reference/);
});
